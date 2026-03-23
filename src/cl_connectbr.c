/*
Copyright (C) 2024 unezQuake team

cl_connectbr.c - Smart route selection for connectbr/connectnext commands

Uses the ping tree (already built by sb_findroutes) to enumerate
multiple proxy routes, measures each hop's quality (ping+jitter+loss)
and picks the best combined path.
*/

#include "quakedef.h"
#include "EX_browser.h"
#include "cl_connectbr.h"

#define CONNECTBR_MAX_ROUTES     6    // +1 slot for direct connection
#define CONNECTBR_TEST_PACKETS   20
#define CONNECTBR_TIMEOUT_MS     600
#define CONNECTBR_PACKET_DELAY   15   // ms between packets

// Quality score weights (must sum to 1.0)
#define WEIGHT_PING     0.5f
#define WEIGHT_JITTER   0.3f
#define WEIGHT_LOSS     0.2f

// Ping colour thresholds for console output
#define PING_GREEN      70    // <= green  (good)
#define PING_ORANGE     130   // <= orange (acceptable)
                              // >  red    (bad)

// Ping normalisation references.
// Direct:    <50ms great, 80ms ok   → reference 80ms
// Via proxy: <100ms great, 130ms ok → reference 160ms
#define PING_REF_DIRECT_MS    80.0f
#define PING_REF_PROXY_MS    160.0f

typedef struct route_candidate_s {
	char    proxylist[512];  // value for cl_proxyaddr (empty = direct)
	char    label[128];      // human-readable name
	float   ping_ms;         // total estimated ping for this route
	float   jitter_ms;       // measured jitter to first hop
	float   loss_pct;        // measured packet loss to first hop
	float   score;           // lower = better
	float   proxy_ping_ms;   // raw measured ping to first hop (display only)
	qbool   via_proxy;
	qbool   valid;
} route_candidate_t;

// Persistent state for connectnext
static route_candidate_t br_routes[CONNECTBR_MAX_ROUTES];
static int               br_route_count   = 0;
static int               br_current_route = 0;
static netadr_t          br_target_addr;
static qbool             br_active        = false;

// ─────────────────────────────────────────────
// Colour-coded ping string for console output.
// green <= 70ms, orange <= 130ms, red > 130ms
// ─────────────────────────────────────────────
static const char *CL_BR_PingColor(float ms)
{
	if (ms <= PING_GREEN)  return "&c0f0";   // green
	if (ms <= PING_ORANGE) return "&cfa0";   // orange
	return "&cf00";                           // red
}

// ─────────────────────────────────────────────
// Look up the server browser ping for a given address.
// Returns -1 if not found.
//
// Reusing browser ping avoids the A2A_PING distortion: game servers
// may handle A2A_PING in a low-priority path, returning RTTs 5-10x
// higher than the real in-game ping.
// ─────────────────────────────────────────────
static int CL_BR_GetBrowserPing(const netadr_t *dest)
{
	int i, best = -1;
	SB_ServerList_Lock();
	for (i = 0; i < serversn; i++) {
		if (NET_CompareAdr(servers[i]->address, *dest) && servers[i]->ping >= 0) {
			best = servers[i]->ping;
			break;
		}
	}
	SB_ServerList_Unlock();
	return best;
}

// ─────────────────────────────────────────────
// Measure RTT to a proxy hop using A2A_PING.
// Do NOT use for direct game server connections — use
// CL_BR_GetBrowserPing() instead to avoid protocol distortion.
// ─────────────────────────────────────────────
static qbool CL_BR_MeasureHop(const netadr_t *dest,
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

	for (i = 0; i < CONNECTBR_TEST_PACKETS; i++) {
		send_times[i] = Sys_DoubleTime();
		sendto(sock, packet, strlen(packet), 0,
		       (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
		Sys_MSleep(CONNECTBR_PACKET_DELAY);
	}

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
			tv.tv_usec = 20 * 1000;
			ret = select(sock + 1, &fd, NULL, NULL, &tv);
			if (ret <= 0) continue;

			ret = recvfrom(sock, buf, sizeof(buf), 0,
			               (struct sockaddr *)&from_addr, &from_len);
			if (ret <= 0)      continue;
			if (buf[0] != 'l') continue; // A2A_ACK

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
// Score a route (lower = better).
// Ping normalised per route type so a good proxy ping (130ms) is not
// unfairly penalised against a good direct ping (50ms).
// ─────────────────────────────────────────────
static float CL_BR_Score(float total_ping, float jitter, float loss,
                          qbool via_proxy)
{
	float ping_ref    = via_proxy ? PING_REF_PROXY_MS : PING_REF_DIRECT_MS;
	float norm_ping   = total_ping / (ping_ref * 2.0f);
	float norm_jitter = jitter     / 100.0f;
	float norm_loss   = loss       / 100.0f;

	return (WEIGHT_PING   * norm_ping)   +
	       (WEIGHT_JITTER * norm_jitter) +
	       (WEIGHT_LOSS   * norm_loss);
}

// ─────────────────────────────────────────────
// Parse the FIRST proxy in a chain (closest to us).
// Format: "proxy1@proxy2@proxy3" — client connects to proxy1 first.
// ─────────────────────────────────────────────
static void CL_BR_GetFirstHop(const char *proxylist, char *out, size_t outsz)
{
	const char *at = strchr(proxylist, '@');
	if (at) {
		size_t len = (size_t)(at - proxylist);
		if (len >= outsz) len = outsz - 1;
		memcpy(out, proxylist, len);
		out[len] = '\0';
	} else {
		strlcpy(out, proxylist, outsz);
	}
}

// ─────────────────────────────────────────────
// Build candidate list.
//
// Order: ping tree best path first, then individual proxies from the
// server list, then direct connection last.
//
// The ping tree candidate uses the proxy address it resolved —
// we do NOT re-invoke SB_PingTree_ConnectBestPath() during connect
// to avoid it interfering with the actual connection attempt.
// ─────────────────────────────────────────────
static int CL_BR_BuildCandidates(const netadr_t *addr,
                                  route_candidate_t *candidates)
{
	extern cvar_t cl_proxyaddr;
	int count = 0;
	int i;
	char saved_proxy[512];
	int pathlen;

	memset(candidates, 0, sizeof(route_candidate_t) * CONNECTBR_MAX_ROUTES);
	strlcpy(saved_proxy, cl_proxyaddr.string, sizeof(saved_proxy));

	// --- Ping tree best path ---
	// We call ConnectBestPath once here only to READ the resolved proxy
	// string, then immediately restore the original value.
	// The actual connect command will set cl_proxyaddr from the saved
	// proxylist — the ping tree is NOT called again at connect time.
	pathlen = SB_PingTree_GetPathLen(addr);
	if (pathlen > 0) {
		SB_PingTree_ConnectBestPath(addr);
		strlcpy(candidates[count].proxylist,
		        cl_proxyaddr.string,
		        sizeof(candidates[count].proxylist));
		Cvar_Set(&cl_proxyaddr, saved_proxy); // restore immediately
		snprintf(candidates[count].label, sizeof(candidates[count].label),
		         "ping tree best (%d hop%s)", pathlen, pathlen > 1 ? "s" : "");
		candidates[count].ping_ms   = 0; // measured below
		candidates[count].via_proxy = (candidates[count].proxylist[0] != '\0');
		count++;
	}

	// --- Individual proxies from server list ---
	SB_ServerList_Lock();
	for (i = 0; i < serversn && count < CONNECTBR_MAX_ROUTES - 1; i++) {
		server_data *s = servers[i];
		char proxy_ip[64];
		float total_estimated_ping;

		if (!s->qwfwd) continue;
		if (s->ping < 0) continue;

		snprintf(proxy_ip, sizeof(proxy_ip), "%d.%d.%d.%d:%d",
		         s->address.ip[0], s->address.ip[1],
		         s->address.ip[2], s->address.ip[3],
		         ntohs(s->address.port));

		// Skip if already covered by ping tree candidate
		if (count > 0 && strcmp(candidates[0].proxylist, proxy_ip) == 0)
			continue;

#ifdef HAVE_PROXY_SERVER_PING
		total_estimated_ping = (float)s->ping + (float)s->ping_to_server;
#else
		// Conservative: assume proxy->server ≈ our ping to proxy.
		// Prevents a distant proxy with low our->proxy ping (e.g. Lisboa)
		// from ranking above a local proxy with a shorter total path.
		total_estimated_ping = (float)s->ping * 2.0f;
#endif

		strlcpy(candidates[count].proxylist, proxy_ip,
		        sizeof(candidates[count].proxylist));
		snprintf(candidates[count].label, sizeof(candidates[count].label),
		         "via proxy %s", s->display.name[0] ? s->display.name : proxy_ip);
		candidates[count].ping_ms       = total_estimated_ping;
		candidates[count].proxy_ping_ms = (float)s->ping;
		candidates[count].via_proxy     = true;
		count++;
	}
	SB_ServerList_Unlock();

	// --- Direct connection (always last candidate) ---
	candidates[count].proxylist[0] = '\0';
	strlcpy(candidates[count].label, "direct connection",
	        sizeof(candidates[count].label));
	candidates[count].ping_ms   = 0; // measured below
	candidates[count].via_proxy = false;
	count++;

	return count;
}

// ─────────────────────────────────────────────
// Apply route idx and issue the connect command.
// cl_proxyaddr is set from the saved proxylist — no ping tree
// call happens here, so it cannot interfere with the connection.
// ─────────────────────────────────────────────
static void CL_BR_ApplyRoute(int idx)
{
	extern cvar_t cl_proxyaddr;
	route_candidate_t *r = &br_routes[idx];
	const char *pc = CL_BR_PingColor(r->ping_ms);

	// Set proxy from the stored string (empty = direct, no proxy)
	Cvar_Set(&cl_proxyaddr, r->proxylist);

	Com_Printf("\n&cf80connectbr:&r route #%d — %s\n", idx + 1, r->label);
	Com_Printf("  ping: %s%.0fms&r  jitter: %s%.0fms&r  loss: %s%.0f%%&r\n",
	           pc, r->ping_ms,
	           CL_BR_PingColor(r->jitter_ms), r->jitter_ms,
	           r->loss_pct > 5 ? "&cf00" : "&c0f0", r->loss_pct);

	if (idx + 1 < br_route_count) {
		Com_Printf("  type &cf80connectnext&r for route #%d (%s)\n",
		           idx + 2, br_routes[idx + 1].label);
	} else {
		Com_Printf("  no more routes available.\n");
	}

	// Issue connect directly — cl_proxyaddr is already set above.
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
		Com_Printf("Tests up to %d routes and connects via the best one.\n",
		           CONNECTBR_MAX_ROUTES - 1);
		Com_Printf("Use 'connectnext' to try the next route if needed.\n");
		Com_Printf("Requires: sb_findroutes 1 + server browser refreshed.\n");
		return;
	}

	if (!NET_StringToAdr(Cmd_Argv(1), &br_target_addr)) {
		Com_Printf("connectbr: invalid address\n");
		return;
	}
	if (br_target_addr.port == 0)
		br_target_addr.port = htons(27500);

	if (SB_PingTree_IsBuilding()) {
		Com_Printf("connectbr: ping tree still building, please wait...\n");
		return;
	}

	if (!SB_PingTree_Built()) {
		Com_Printf("connectbr: no route data.\n");
		Com_Printf("  Enable 'sb_findroutes 1', refresh browser, then try again.\n");
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

	Com_Printf("\n&cf80connectbr:&r testing %d route(s) to %s...\n\n",
	           candidate_count, Cmd_Argv(1));

	br_route_count   = 0;
	br_current_route = 0;
	br_active        = false;

	for (i = 0; i < candidate_count && br_route_count < CONNECTBR_MAX_ROUTES; i++) {
		float hop_ping, jitter, loss, total_ping;
		qbool ok;
		netadr_t hop_addr;
		char first_hop[64];

		Com_Printf("  [%d/%d] %s... ", i + 1, candidate_count, candidates[i].label);

		if (candidates[i].proxylist[0]) {
			// Proxy: measure RTT to the first (closest) hop via A2A_PING.
			// Proxies respond to this reliably without priority distortion.
			CL_BR_GetFirstHop(candidates[i].proxylist, first_hop, sizeof(first_hop));
			NET_StringToAdr(first_hop, &hop_addr);
			ok = CL_BR_MeasureHop(&hop_addr, &hop_ping, &jitter, &loss);
		} else {
			// Direct: reuse server browser ping to avoid A2A_PING distortion.
			// (A2A_PING on game servers can read 10x higher than actual in-game ping.)
			int browser_ping = CL_BR_GetBrowserPing(&br_target_addr);
			if (browser_ping >= 0) {
				hop_ping = (float)browser_ping;
				jitter   = 0;
				loss     = 0;
				ok       = true;
			} else {
				// Not in browser cache — fall back to A2A_PING
				hop_addr = br_target_addr;
				ok = CL_BR_MeasureHop(&hop_addr, &hop_ping, &jitter, &loss);
			}
		}

		if (!ok) {
			Com_Printf("&cf00unreachable&r\n");
			continue;
		}

		// For proxy routes: total = measured first hop + remaining estimated hops.
		// This replaces only the component we actually measured, keeping the
		// proxy->server estimate from BuildCandidates for the rest of the path.
		if (candidates[i].via_proxy && candidates[i].proxy_ping_ms > 0) {
			float remaining = candidates[i].ping_ms - candidates[i].proxy_ping_ms;
			if (remaining < 0) remaining = 0;
			total_ping = hop_ping + remaining;
		} else {
			total_ping = hop_ping;
		}

		{
			const char *pc = CL_BR_PingColor(total_ping);
			const char *jc = CL_BR_PingColor(jitter);
			Com_Printf("hop=%s%.0fms&r  total=%s%.0fms&r  jitter=%s%.0fms&r  loss=%.0f%%\n",
			           CL_BR_PingColor(hop_ping), hop_ping,
			           pc, total_ping,
			           jc, jitter,
			           loss);
		}

		br_routes[br_route_count]               = candidates[i];
		br_routes[br_route_count].ping_ms       = total_ping;
		br_routes[br_route_count].proxy_ping_ms = hop_ping;
		br_routes[br_route_count].jitter_ms     = jitter;
		br_routes[br_route_count].loss_pct      = loss;
		br_routes[br_route_count].score         = CL_BR_Score(total_ping, jitter, loss,
		                                                       candidates[i].via_proxy);
		br_routes[br_route_count].valid         = true;
		br_route_count++;
	}

	if (br_route_count == 0) {
		Com_Printf("\nconnectbr: all routes failed.\n");
		return;
	}

	// Sort by score (lower = better)
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

	// Show ranking with colour-coded pings
	Com_Printf("\n&cf80--- route ranking ---&r\n");
	for (i = 0; i < br_route_count; i++) {
		const char *pc = CL_BR_PingColor(br_routes[i].ping_ms);
		Com_Printf("  #%d %s\n"
		           "     hop=%s%.0fms&r  total=%s%.0fms&r  jitter=%s%.0fms&r  loss=%.0f%%\n",
		           i + 1, br_routes[i].label,
		           CL_BR_PingColor(br_routes[i].proxy_ping_ms), br_routes[i].proxy_ping_ms,
		           pc, br_routes[i].ping_ms,
		           CL_BR_PingColor(br_routes[i].jitter_ms), br_routes[i].jitter_ms,
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
