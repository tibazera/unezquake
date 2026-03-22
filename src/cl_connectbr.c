/*
Copyright (C) 2024 unezQuake team

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

cl_connectbr.c - Smart route selection for connectbr/connectnext commands

Tests top 5 proxy routes measuring ping, jitter and packet loss,
presents ranking to user, and allows cycling through routes with
the 'connectnext' command.
*/

#include "quakedef.h"
#include "EX_browser.h"
#include "cl_connectbr.h"

#define CONNECTBR_MAX_ROUTES     5
#define CONNECTBR_TEST_PACKETS   20
#define CONNECTBR_TIMEOUT_MS     600
#define CONNECTBR_PACKET_DELAY   15   // ms between packets (~67pps like QW)

// Quality score weights (must sum to 1.0)
#define WEIGHT_PING     0.5f
#define WEIGHT_JITTER   0.3f
#define WEIGHT_LOSS     0.2f

typedef struct route_candidate_s {
	char    proxylist[512];  // value for cl_proxyaddr (empty = direct)
	char    label[128];      // human-readable name
	float   ping_ms;
	float   jitter_ms;
	float   loss_pct;
	float   score;           // lower = better
	qbool   valid;
} route_candidate_t;

// Persistent state for connectnext
static route_candidate_t br_routes[CONNECTBR_MAX_ROUTES];
static int               br_route_count   = 0;
static int               br_current_route = 0;
static netadr_t          br_target_addr;
static qbool             br_active        = false;

// ─────────────────────────────────────────────
// Measure quality of a single route to dest
// ─────────────────────────────────────────────
static qbool CL_BR_MeasureRoute(const netadr_t *dest,
                                 float *out_ping,
                                 float *out_jitter,
                                 float *out_loss)
{
	socket_t sock;
	struct sockaddr_storage to_addr;
	struct timeval tv;
	fd_set fd;
	int i, ret;
	double send_times[CONNECTBR_TEST_PACKETS];
	double recv_times[CONNECTBR_TEST_PACKETS];
	qbool  received[CONNECTBR_TEST_PACKETS];
	int    recv_count = 0;
	double ping_sum = 0, ping_sq_sum = 0;
	char   packet[] = "\xff\xff\xff\xffk\n"; // A2A_PING

	memset(received,   0, sizeof(received));
	memset(send_times, 0, sizeof(send_times));
	memset(recv_times, 0, sizeof(recv_times));

	sock = UDP_OpenSocket(PORT_ANY);
	if (sock == INVALID_SOCKET) {
		*out_ping = *out_jitter = 9999;
		*out_loss = 100;
		return false;
	}

	NetadrToSockadr(dest, &to_addr);

	// Send packets with spacing similar to QW game traffic
	for (i = 0; i < CONNECTBR_TEST_PACKETS; i++) {
		send_times[i] = Sys_DoubleTime();
		sendto(sock, packet, strlen(packet), 0,
		       (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
		Sys_MSleep(CONNECTBR_PACKET_DELAY);
	}

	// Collect A2A_ACK replies until deadline
	{
		double deadline = Sys_DoubleTime() + (CONNECTBR_TIMEOUT_MS / 1000.0);

		while (Sys_DoubleTime() < deadline) {
			char buf[32];
			struct sockaddr_storage from_addr;
			socklen_t from_len = sizeof(from_addr);
			double now;

			FD_ZERO(&fd);
			FD_SET(sock, &fd);
			tv.tv_sec  = 0;
			tv.tv_usec = 20 * 1000; // 20ms poll
			ret = select(sock + 1, &fd, NULL, NULL, &tv);
			if (ret <= 0) continue;

			ret = recvfrom(sock, buf, sizeof(buf), 0,
			               (struct sockaddr *)&from_addr, &from_len);
			if (ret <= 0)    continue;
			if (buf[0] != 'l') continue; // not A2A_ACK

			now = Sys_DoubleTime();
			for (i = 0; i < CONNECTBR_TEST_PACKETS; i++) {
				if (!received[i]) {
					received[i]   = true;
					recv_times[i] = now;
					recv_count++;
					break;
				}
			}
		}
	}

	closesocket(sock);

	if (recv_count == 0) {
		*out_ping = *out_jitter = 9999;
		*out_loss = 100;
		return false;
	}

	// Average ping
	for (i = 0; i < CONNECTBR_TEST_PACKETS; i++) {
		if (received[i]) {
			double rtt = (recv_times[i] - send_times[i]) * 1000.0;
			ping_sum    += rtt;
			ping_sq_sum += rtt * rtt;
		}
	}

	*out_ping = (float)(ping_sum / recv_count);
	*out_loss = (float)((CONNECTBR_TEST_PACKETS - recv_count) * 100)
	            / CONNECTBR_TEST_PACKETS;

	// Jitter = standard deviation
	if (recv_count > 1) {
		double mean     = ping_sum / recv_count;
		double variance = (ping_sq_sum / recv_count) - (mean * mean);
		*out_jitter = (float)sqrt(variance > 0 ? variance : 0);
	} else {
		*out_jitter = 0;
	}

	return true;
}

// ─────────────────────────────────────────────
// Score a route (lower = better)
// ─────────────────────────────────────────────
static float CL_BR_Score(float ping, float jitter, float loss)
{
	float norm_ping   = ping   / 300.0f;
	float norm_jitter = jitter / 100.0f;
	float norm_loss   = loss   / 100.0f;

	return (WEIGHT_PING   * norm_ping)   +
	       (WEIGHT_JITTER * norm_jitter) +
	       (WEIGHT_LOSS   * norm_loss);
}

// ─────────────────────────────────────────────
// Build candidate list from ping tree
// ─────────────────────────────────────────────
static int CL_BR_BuildCandidates(const netadr_t *addr,
                                  route_candidate_t *candidates)
{
	extern cvar_t cl_proxyaddr;
	int   count   = 0;
	int   pathlen = SB_PingTree_GetPathLen(addr);
	char  saved_proxy[512];

	memset(candidates, 0, sizeof(route_candidate_t) * CONNECTBR_MAX_ROUTES);
	strlcpy(saved_proxy, cl_proxyaddr.string, sizeof(saved_proxy));

	// Route 0: best route from ping tree (may use proxies)
	if (pathlen > 0) {
		SB_PingTree_ConnectBestPath(addr);
		strlcpy(candidates[count].proxylist,
		        cl_proxyaddr.string,
		        sizeof(candidates[count].proxylist));
		snprintf(candidates[count].label, sizeof(candidates[count].label),
		         "best proxy route (%d hop%s)", pathlen, pathlen > 1 ? "s" : "");
		count++;

		// Restore proxy so we don't accidentally connect yet
		Cvar_Set(&cl_proxyaddr, saved_proxy);
	}

	// Last route: always offer direct connection
	candidates[count].proxylist[0] = '\0';
	strlcpy(candidates[count].label, "direct connection",
	        sizeof(candidates[count].label));
	count++;

	return count;
}

// ─────────────────────────────────────────────
// Apply route N and connect
// ─────────────────────────────────────────────
static void CL_BR_ApplyRoute(int idx)
{
	extern cvar_t cl_proxyaddr;
	route_candidate_t *r = &br_routes[idx];

	Cvar_Set(&cl_proxyaddr, r->proxylist);

	Com_Printf("\n&cf80connectbr:&r Connecting via route #%d — %s\n",
	           idx + 1, r->label);
	Com_Printf("  ping:&cf80%.0fms&r  jitter:&cf80%.0fms&r  loss:&cf80%.0f%%&r\n",
	           r->ping_ms, r->jitter_ms, r->loss_pct);

	if (idx + 1 < br_route_count) {
		Com_Printf("  Type &cf80connectnext&r to try route #%d (%s)\n",
		           idx + 2, br_routes[idx + 1].label);
	} else {
		Com_Printf("  This was the last available route.\n");
	}

	Cbuf_AddText(va("connect %s\n", NET_AdrToString(br_target_addr)));
}

// ─────────────────────────────────────────────
// PUBLIC: connectbr <address>
// ─────────────────────────────────────────────
void CL_Connect_BestRoute_f(void)
{
	route_candidate_t candidates[CONNECTBR_MAX_ROUTES];
	int candidate_count, i;

	if (Cmd_Argc() != 2) {
		Com_Printf("Usage: connectbr <address>\n");
		Com_Printf("Tests up to %d routes (ping + jitter + packet loss) and\n",
		           CONNECTBR_MAX_ROUTES);
		Com_Printf("connects via the best one. Use 'connectnext' to try the next.\n");
		Com_Printf("Requires server browser refreshed with sb_findroutes 1.\n");
		return;
	}

	if (!NET_StringToAdr(Cmd_Argv(1), &br_target_addr)) {
		Com_Printf("connectbr: invalid address\n");
		return;
	}
	if (br_target_addr.port == 0)
		br_target_addr.port = htons(27500);

	if (SB_PingTree_IsBuilding()) {
		Com_Printf("connectbr: ping tree is still being built, please wait...\n");
		return;
	}

	if (!SB_PingTree_Built()) {
		Com_Printf("connectbr: no route data — enable 'sb_findroutes 1',\n");
		Com_Printf("  refresh the server browser, then try again.\n");
		Com_Printf("  Falling back to direct connection...\n");
		Cbuf_AddText(va("connect %s\n", Cmd_Argv(1)));
		return;
	}

	candidate_count = CL_BR_BuildCandidates(&br_target_addr, candidates);
	if (candidate_count == 0) {
		Com_Printf("connectbr: no routes found, connecting directly...\n");
		Cbuf_AddText(va("connect %s\n", Cmd_Argv(1)));
		return;
	}

	Com_Printf("\n&cf80connectbr:&r Testing %d route(s) to %s...\n\n",
	           candidate_count, Cmd_Argv(1));

	br_route_count   = 0;
	br_current_route = 0;
	br_active        = false;

	for (i = 0; i < candidate_count && br_route_count < CONNECTBR_MAX_ROUTES; i++) {
		float ping, jitter, loss;
		qbool ok;

		Com_Printf("  [%d/%d] %s... ", i + 1, candidate_count, candidates[i].label);

		ok = CL_BR_MeasureRoute(&br_target_addr, &ping, &jitter, &loss);

		if (!ok) {
			Com_Printf("&cf00unreachable&r\n");
			continue;
		}

		br_routes[br_route_count]            = candidates[i];
		br_routes[br_route_count].ping_ms    = ping;
		br_routes[br_route_count].jitter_ms  = jitter;
		br_routes[br_route_count].loss_pct   = loss;
		br_routes[br_route_count].score      = CL_BR_Score(ping, jitter, loss);
		br_routes[br_route_count].valid      = true;

		Com_Printf("ping=&cf80%.0fms&r  jitter=&cf80%.0fms&r  loss=&cf80%.0f%%&r\n",
		           ping, jitter, loss);
		br_route_count++;
	}

	if (br_route_count == 0) {
		Com_Printf("\nconnectbr: all routes failed.\n");
		return;
	}

	// Sort by score (bubble sort, small N)
	{
		int a, b;
		for (a = 0; a < br_route_count - 1; a++) {
			for (b = a + 1; b < br_route_count; b++) {
				if (br_routes[b].score < br_routes[a].score) {
					route_candidate_t tmp = br_routes[a];
					br_routes[a] = br_routes[b];
					br_routes[b] = tmp;
				}
			}
		}
	}

	// Show ranking
	Com_Printf("\n&cf80--- Route ranking ---&r\n");
	for (i = 0; i < br_route_count; i++) {
		Com_Printf("  #%d %s\n"
		           "     ping=%.0fms  jitter=%.0fms  loss=%.0f%%\n",
		           i + 1, br_routes[i].label,
		           br_routes[i].ping_ms,
		           br_routes[i].jitter_ms,
		           br_routes[i].loss_pct);
	}

	br_current_route = 0;
	br_active        = true;
	CL_BR_ApplyRoute(0);
}

// ─────────────────────────────────────────────
// PUBLIC: connectnext
// ─────────────────────────────────────────────
void CL_Connect_Next_f(void)
{
	if (!br_active || br_route_count == 0) {
		Com_Printf("connectnext: no active connectbr session.\n");
		Com_Printf("  Use 'connectbr <address>' first.\n");
		return;
	}

	br_current_route++;

	if (br_current_route >= br_route_count) {
		Com_Printf("connectnext: no more routes (tried all %d).\n", br_route_count);
		br_active = false;
		return;
	}

	Host_EndGame();
	CL_BR_ApplyRoute(br_current_route);
}
