/*
Copyright (C) 2024 unezQuake team

cl_connectbr.c - Smart route selection for connectbr/connectnext commands

Enumerates proxy routes from the ping tree and server browser,
measures real ping and packet loss to each proxy hop, and connects
via the best one. No speculative total estimates — only real measurements.
*/

#include "quakedef.h"
#include "EX_browser.h"
#include "cl_connectbr.h"

#define CONNECTBR_MAX_ROUTES     12
#define CONNECTBR_TEST_PACKETS   20
#define CONNECTBR_TIMEOUT_MS     600
#define CONNECTBR_PACKET_DELAY   15

// Score weights — loss penalised heavily since it directly breaks gameplay
#define WEIGHT_PING     0.6f
#define WEIGHT_LOSS     0.4f

// Ping colour thresholds
#define PING_GREEN      70
#define PING_ORANGE     130

// Ping normalisation references
#define PING_REF_DIRECT_MS    80.0f
#define PING_REF_PROXY_MS    160.0f

typedef struct {
	char    proxylist[512]; // cl_proxyaddr value (empty = direct)
	char    label[128];
	float   ping_ms;        // measured ping to first hop (or browser ping)
	float   loss_pct;       // measured packet loss to first hop
	float   score;          // lower = better
	qbool   via_proxy;
	qbool   valid;
} route_t;

static route_t  br_routes[CONNECTBR_MAX_ROUTES];
static int      br_route_count   = 0;
static int      br_current_route = 0;
static netadr_t br_target_addr;
static qbool    br_active        = false;

static const char *CL_BR_PingColor(float ms)
{
	if (ms <= PING_GREEN)  return "&c0f0";
	if (ms <= PING_ORANGE) return "&cfa0";
	return "&cf00";
}

static const char *CL_BR_LossColor(float pct)
{
	if (pct == 0)   return "&c0f0";
	if (pct <= 5)   return "&cfa0";
	return "&cf00";
}

// Browser ping lookup — most accurate, no protocol distortion
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

// A2A_PING measurement — fallback when proxy not in browser
static qbool CL_BR_MeasureHop(const netadr_t *dest,
                               float *out_ping,
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
	double ping_sum   = 0;
	char   packet[]   = "\xff\xff\xff\xffk\n";

	memset(received,   0, sizeof(received));
	memset(send_times, 0, sizeof(send_times));
	memset(recv_times, 0, sizeof(recv_times));

	sock = UDP_OpenSocket(PORT_ANY);
	if (sock == INVALID_SOCKET) {
		*out_ping = 9999;
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
			if (buf[0] != 'l') continue;

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
		*out_ping = 9999;
		*out_loss = 100;
		return false;
	}

	for (i = 0; i < CONNECTBR_TEST_PACKETS; i++) {
		if (received[i])
			ping_sum += (recv_times[i] - send_times[i]) * 1000.0;
	}

	*out_ping = (float)(ping_sum / recv_count);
	*out_loss = (float)((CONNECTBR_TEST_PACKETS - recv_count) * 100)
	            / CONNECTBR_TEST_PACKETS;

	return true;
}

static float CL_BR_Score(float ping_ms, float loss_pct, qbool via_proxy)
{
	float ping_ref  = via_proxy ? PING_REF_PROXY_MS : PING_REF_DIRECT_MS;
	float norm_ping = ping_ms   / (ping_ref * 2.0f);
	float norm_loss = loss_pct  / 100.0f;

	return (WEIGHT_PING * norm_ping) + (WEIGHT_LOSS * norm_loss);
}

// First proxy in chain = closest hop to us
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

// Measure a candidate route and fill route_t if reachable.
// Returns true if route is valid.
static qbool CL_BR_MeasureCandidate(const char *proxylist, qbool via_proxy,
                                     float *out_ping, float *out_loss)
{
	if (proxylist[0]) {
		// Proxy: measure first hop
		char first_hop[64];
		netadr_t hop_addr;

		CL_BR_GetFirstHop(proxylist, first_hop, sizeof(first_hop));
		NET_StringToAdr(first_hop, &hop_addr);

		// Browser ping is always preferred — it uses the real QW protocol
		int bp = CL_BR_GetBrowserPing(&hop_addr);
		if (bp >= 0) {
			*out_ping = (float)bp;
			*out_loss = 0;
			return true;
		}

		// Not in browser — fall back to A2A_PING
		return CL_BR_MeasureHop(&hop_addr, out_ping, out_loss);
	} else {
		// Direct: always use browser ping (A2A_PING on game servers is unreliable)
		int bp = CL_BR_GetBrowserPing(&br_target_addr);
		if (bp >= 0) {
			*out_ping = (float)bp;
			*out_loss = 0;
			return true;
		}
		return CL_BR_MeasureHop(&br_target_addr, out_ping, out_loss);
	}
}

static int CL_BR_BuildAndMeasure(void)
{
	int count = 0;
	int pathlen;
	int i;

	// ── Ping tree best proxy path ──────────────────────────────────────
	pathlen = SB_PingTree_GetPathLen(&br_target_addr);
	if (pathlen > 0) {
		int   dummy_ping = 0;
		char  proxy_str[512];

		if (SB_PingTree_GetProxyString(&br_target_addr, proxy_str, sizeof(proxy_str),
		                                &dummy_ping)) {
			float ping, loss;

			Com_Printf("  [ping tree best (%d hop%s)]... ",
			           pathlen, pathlen > 1 ? "s" : "");

			if (CL_BR_MeasureCandidate(proxy_str, true, &ping, &loss)) {
				Com_Printf("ping=%s%.0fms&r  loss=%s%.0f%%&r\n",
				           CL_BR_PingColor(ping), ping,
				           CL_BR_LossColor(loss), loss);

				strlcpy(br_routes[count].proxylist, proxy_str,
				        sizeof(br_routes[count].proxylist));
				snprintf(br_routes[count].label, sizeof(br_routes[count].label),
				         "ping tree best (%d hop%s)", pathlen, pathlen > 1 ? "s" : "");
				br_routes[count].ping_ms   = ping;
				br_routes[count].loss_pct  = loss;
				br_routes[count].score     = CL_BR_Score(ping, loss, true);
				br_routes[count].via_proxy = true;
				br_routes[count].valid     = true;
				count++;
			} else {
				Com_Printf("&cf00unreachable&r\n");
			}
		}
	}

	// ── Individual proxies from server browser ──────────────────────────
	// We collect ALL qwfwd proxies first (ignoring sb_showproxies filter),
	// then measure them. We skip proxies whose IP matches the target server
	// (no point routing through the server's own proxy to reach itself).
	{
		// Collect proxy candidates into a temp list first (unlock-safe)
		char proxy_ips[32][64];
		char proxy_names[32][128];
		int  proxy_count = 0;
		int  j;

		SB_ServerList_Lock();
		for (i = 0; i < serversn && proxy_count < 32; i++) {
			server_data *s = servers[i];
			char proxy_ip[64];
			qbool dup = false;

			if (!s->qwfwd) continue;
			if (s->ping < 0) continue;

			snprintf(proxy_ip, sizeof(proxy_ip), "%d.%d.%d.%d:%d",
			         s->address.ip[0], s->address.ip[1],
			         s->address.ip[2], s->address.ip[3],
			         ntohs(s->address.port));

			// Skip if proxy IP matches target server IP (same machine)
			if (memcmp(s->address.ip, br_target_addr.ip, 4) == 0)
				continue;

			// Skip duplicates already in br_routes (ping tree)
			for (j = 0; j < count; j++) {
				if (strcmp(br_routes[j].proxylist, proxy_ip) == 0) {
					dup = true; break;
				}
			}
			if (dup) continue;

			// Skip duplicates within our temp list
			for (j = 0; j < proxy_count; j++) {
				if (strcmp(proxy_ips[j], proxy_ip) == 0) {
					dup = true; break;
				}
			}
			if (dup) continue;

			strlcpy(proxy_ips[proxy_count], proxy_ip, sizeof(proxy_ips[0]));
			strlcpy(proxy_names[proxy_count],
			        s->display.name[0] ? s->display.name : proxy_ip,
			        sizeof(proxy_names[0]));
			proxy_count++;
		}
		SB_ServerList_Unlock();

		// Now measure each proxy (no lock held during network I/O)
		for (i = 0; i < proxy_count && count < CONNECTBR_MAX_ROUTES - 1; i++) {
			float ping, loss;

			Com_Printf("  [%s]... ", proxy_names[i]);

			if (CL_BR_MeasureCandidate(proxy_ips[i], true, &ping, &loss)) {
				Com_Printf("ping=%s%.0fms&r  loss=%s%.0f%%&r\n",
				           CL_BR_PingColor(ping), ping,
				           CL_BR_LossColor(loss), loss);

				strlcpy(br_routes[count].proxylist, proxy_ips[i],
				        sizeof(br_routes[count].proxylist));
				snprintf(br_routes[count].label, sizeof(br_routes[count].label),
				         "via proxy %s", proxy_names[i]);
				br_routes[count].ping_ms   = ping;
				br_routes[count].loss_pct  = loss;
				br_routes[count].score     = CL_BR_Score(ping, loss, true);
				br_routes[count].via_proxy = true;
				br_routes[count].valid     = true;
				count++;
			} else {
				Com_Printf("&cf00unreachable&r\n");
			}
		}
	}

	// ── Direct connection ───────────────────────────────────────────────
	{
		float ping, loss;
		Com_Printf("  [direct]... ");

		if (CL_BR_MeasureCandidate("", false, &ping, &loss)) {
			Com_Printf("ping=%s%.0fms&r  loss=%s%.0f%%&r\n",
			           CL_BR_PingColor(ping), ping,
			           CL_BR_LossColor(loss), loss);

			br_routes[count].proxylist[0] = '\0';
			strlcpy(br_routes[count].label, "direct connection",
			        sizeof(br_routes[count].label));
			br_routes[count].ping_ms   = ping;
			br_routes[count].loss_pct  = loss;
			br_routes[count].score     = CL_BR_Score(ping, loss, false);
			br_routes[count].via_proxy = false;
			br_routes[count].valid     = true;
			count++;
		} else {
			Com_Printf("&cf00unreachable&r\n");
		}
	}

	return count;
}

static void CL_BR_ApplyRoute(int idx)
{
	extern cvar_t cl_proxyaddr;
	route_t *r = &br_routes[idx];

	Cvar_Set(&cl_proxyaddr, "");
	if (r->proxylist[0])
		Cvar_Set(&cl_proxyaddr, r->proxylist);

	Com_Printf("\n&cf80connectbr:&r route #%d — %s\n", idx + 1, r->label);
	Com_Printf("  ping: %s%.0fms&r  loss: %s%.0f%%&r\n",
	           CL_BR_PingColor(r->ping_ms), r->ping_ms,
	           CL_BR_LossColor(r->loss_pct), r->loss_pct);

	if (idx + 1 < br_route_count) {
		Com_Printf("  type &cf80connectnext&r for route #%d (%s)\n",
		           idx + 2, br_routes[idx + 1].label);
	} else {
		Com_Printf("  no more routes available.\n");
	}

	Cbuf_AddText(va("connect %s\n", NET_AdrToString(br_target_addr)));
}

void CL_Connect_BestRoute_f(void)
{
	extern cvar_t cl_proxyaddr;

	if (Cmd_Argc() != 2) {
		Com_Printf("Usage: connectbr <address>\n");
		Com_Printf("Tests proxy routes (ping + loss) and connects via the best one.\n");
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
		Com_Printf("  Enable 'sb_findroutes 1', refresh browser, then retry.\n");
		Com_Printf("  Falling back to direct connection...\n");
		Cvar_Set(&cl_proxyaddr, "");
		Cbuf_AddText(va("connect %s\n", Cmd_Argv(1)));
		return;
	}

	Cvar_Set(&cl_proxyaddr, "");

	Com_Printf("\n&cf80connectbr:&r testing routes to %s...\n\n", Cmd_Argv(1));

	br_route_count   = 0;
	br_current_route = 0;
	br_active        = false;

	br_route_count = CL_BR_BuildAndMeasure();

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
					route_t tmp  = br_routes[a];
					br_routes[a] = br_routes[b];
					br_routes[b] = tmp;
				}
			}
		}
	}

	Com_Printf("\n&cf80--- route ranking ---&r\n");
	{
		int i;
		for (i = 0; i < br_route_count; i++) {
			Com_Printf("  #%d %s\n"
			           "     ping=%s%.0fms&r  loss=%s%.0f%%&r\n",
			           i + 1, br_routes[i].label,
			           CL_BR_PingColor(br_routes[i].ping_ms), br_routes[i].ping_ms,
			           CL_BR_LossColor(br_routes[i].loss_pct), br_routes[i].loss_pct);
		}
	}

	br_current_route = 0;
	br_active        = true;
	CL_BR_ApplyRoute(0);
}

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
