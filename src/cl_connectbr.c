/*
Copyright (C) 2024 unezQuake team

cl_connectbr.c - Smart route selection for connectbr/connectnext commands

Enumerates proxy routes from the ping tree and server browser,
measures real ping and packet loss to each proxy hop, and connects
via the best one.

CVars:
  cl_connectbr_test_packets   - number of UDP probes per route (default 25)
  cl_connectbr_timeout_ms     - receive timeout in ms (default 600)
  cl_connectbr_packet_delay   - ms between probes (default 15)
  cl_connectbr_ping_green     - ping threshold for green colour (default 70)
  cl_connectbr_ping_orange    - ping threshold for orange colour (default 130)
  cl_connectbr_weight_ping    - score weight for ping (default 0.6)
  cl_connectbr_weight_loss    - score weight for loss (default 0.4)
  cl_connectbr_verbose        - verbosity level 0/1/2 (default 1)
  cl_connectbr_debug          - debug logging 0/1 (default 0)
*/

#include "quakedef.h"
#include "EX_browser.h"
#include "cl_connectbr.h"

// ─────────────────────────────────────────────
// CVars
// ─────────────────────────────────────────────
cvar_t cl_connectbr_test_packets  = {"cl_connectbr_test_packets",  "25",   CVAR_ARCHIVE};
cvar_t cl_connectbr_timeout_ms    = {"cl_connectbr_timeout_ms",    "600",  CVAR_ARCHIVE};
cvar_t cl_connectbr_packet_delay  = {"cl_connectbr_packet_delay",  "15",   CVAR_ARCHIVE};
cvar_t cl_connectbr_ping_green    = {"cl_connectbr_ping_green",    "70",   CVAR_ARCHIVE};
cvar_t cl_connectbr_ping_orange   = {"cl_connectbr_ping_orange",   "130",  CVAR_ARCHIVE};
cvar_t cl_connectbr_weight_ping   = {"cl_connectbr_weight_ping",   "0.6",  CVAR_ARCHIVE};
cvar_t cl_connectbr_weight_loss   = {"cl_connectbr_weight_loss",   "0.4",  CVAR_ARCHIVE};
cvar_t cl_connectbr_verbose       = {"cl_connectbr_verbose",       "1",    CVAR_ARCHIVE};
cvar_t cl_connectbr_debug         = {"cl_connectbr_debug",         "0",    CVAR_ARCHIVE};

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────
#define CONNECTBR_MAX_ROUTES    12
#define CONNECTBR_MAX_PROXIES   32
#define MAX_PROXYLIST           256
#define MAX_ADDRESS_LENGTH      128

#define PING_REF_DIRECT_MS      80.0f
#define PING_REF_PROXY_MS       160.0f

// Proxy measurement cache
#define PROXY_CACHE_SIZE        16
#define PROXY_CACHE_TTL_SEC     5.0

// Debug macro
#define BR_Debug(...) \
	do { if (cl_connectbr_debug.value) Com_Printf("[connectbr] " __VA_ARGS__); } while(0)

// ─────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────
typedef struct {
	char    proxylist[MAX_PROXYLIST];
	char    label[128];
	float   ping_ms;
	float   loss_pct;
	float   score;
	qbool   via_proxy;
	qbool   valid;
} route_t;

typedef struct {
	char    proxy_ip[64];
	float   ping_ms;
	float   loss_pct;
	double  last_measure;
} proxy_cache_entry_t;

// ─────────────────────────────────────────────
// State
// ─────────────────────────────────────────────
static route_t              br_routes[CONNECTBR_MAX_ROUTES];
static int                  br_route_count   = 0;
static int                  br_current_route = 0;
static netadr_t             br_target_addr;
static qbool                br_active        = false;
static qbool                br_measuring     = false;

static proxy_cache_entry_t  proxy_cache[PROXY_CACHE_SIZE];
static int                  proxy_cache_count = 0;

// ─────────────────────────────────────────────
// Colour helpers
// ─────────────────────────────────────────────
static const char *CL_BR_PingColor(float ms)
{
	int g = (int)cl_connectbr_ping_green.value;
	int o = (int)cl_connectbr_ping_orange.value;
	if (ms <= g) return "&c0f0";
	if (ms <= o) return "&cfa0";
	return "&cf00";
}

static const char *CL_BR_LossColor(float pct)
{
	if (pct == 0)  return "&c0f0";
	if (pct <= 5)  return "&cfa0";
	return "&cf00";
}

// ─────────────────────────────────────────────
// Proxy measurement cache
// ─────────────────────────────────────────────
static qbool CL_BR_GetCached(const char *proxy_ip, float *ping, float *loss)
{
	int i;
	double now = Sys_DoubleTime();
	for (i = 0; i < proxy_cache_count; i++) {
		if (strcmp(proxy_cache[i].proxy_ip, proxy_ip) == 0 &&
		    (now - proxy_cache[i].last_measure) < PROXY_CACHE_TTL_SEC) {
			*ping = proxy_cache[i].ping_ms;
			*loss = proxy_cache[i].loss_pct;
			BR_Debug("cache hit for %s: ping=%.0f loss=%.0f\n",
			         proxy_ip, *ping, *loss);
			return true;
		}
	}
	return false;
}

static void CL_BR_StoreCached(const char *proxy_ip, float ping, float loss)
{
	int i;
	double now = Sys_DoubleTime();

	for (i = 0; i < proxy_cache_count; i++) {
		if (strcmp(proxy_cache[i].proxy_ip, proxy_ip) == 0) {
			proxy_cache[i].ping_ms      = ping;
			proxy_cache[i].loss_pct     = loss;
			proxy_cache[i].last_measure = now;
			return;
		}
	}

	if (proxy_cache_count < PROXY_CACHE_SIZE) {
		strlcpy(proxy_cache[proxy_cache_count].proxy_ip, proxy_ip,
		        sizeof(proxy_cache[0].proxy_ip));
		proxy_cache[proxy_cache_count].ping_ms      = ping;
		proxy_cache[proxy_cache_count].loss_pct     = loss;
		proxy_cache[proxy_cache_count].last_measure = now;
		proxy_cache_count++;
	} else {
		// Replace oldest entry
		int oldest = 0;
		double oldest_time = proxy_cache[0].last_measure;
		for (i = 1; i < PROXY_CACHE_SIZE; i++) {
			if (proxy_cache[i].last_measure < oldest_time) {
				oldest_time = proxy_cache[i].last_measure;
				oldest = i;
			}
		}
		strlcpy(proxy_cache[oldest].proxy_ip, proxy_ip,
		        sizeof(proxy_cache[oldest].proxy_ip));
		proxy_cache[oldest].ping_ms      = ping;
		proxy_cache[oldest].loss_pct     = loss;
		proxy_cache[oldest].last_measure = now;
	}
}

// ─────────────────────────────────────────────
// Browser ping lookup
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
// A2A_PING measurement (proxy fallback only)
// ─────────────────────────────────────────────
static qbool CL_BR_MeasureHop(const netadr_t *dest,
                               float *out_ping, float *out_loss)
{
	socket_t sock = INVALID_SOCKET;
	struct sockaddr_storage to_addr;
	struct timeval tv;
	fd_set fd;
	int i, ret;
	int test_packets, recv_count = 0;
	double *send_times = NULL;
	double *recv_times = NULL;
	qbool  *received   = NULL;
	double ping_sum    = 0;
	char   packet[]    = "\xff\xff\xff\xffk\n";
	qbool  success     = false;

	if (!out_ping || !out_loss) return false;

	test_packets = (int)cl_connectbr_test_packets.value;
	if (test_packets < 5)  test_packets = 5;
	if (test_packets > 50) test_packets = 50;

	send_times = (double *)Q_malloc(test_packets * sizeof(double));
	recv_times = (double *)Q_malloc(test_packets * sizeof(double));
	received   = (qbool  *)Q_malloc(test_packets * sizeof(qbool));

	memset(received,   0, test_packets * sizeof(qbool));
	memset(send_times, 0, test_packets * sizeof(double));
	memset(recv_times, 0, test_packets * sizeof(double));

	sock = UDP_OpenSocket(PORT_ANY);
	if (sock == INVALID_SOCKET) {
		BR_Debug("failed to open socket\n");
		goto cleanup;
	}

	NetadrToSockadr(dest, &to_addr);

	for (i = 0; i < test_packets; i++) {
		send_times[i] = Sys_DoubleTime();
		sendto(sock, packet, strlen(packet), 0,
		       (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
		Sys_MSleep((int)cl_connectbr_packet_delay.value);
	}

	{
		int timeout_ms = (int)cl_connectbr_timeout_ms.value;
		double deadline = Sys_DoubleTime() + (timeout_ms / 1000.0);

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
			for (i = 0; i < test_packets; i++) {
				if (!received[i]) {
					received[i]   = true;
					recv_times[i] = now;
					recv_count++;
					break;
				}
			}
		}
	}

	if (recv_count == 0) {
		*out_ping = 9999;
		*out_loss = 100;
		goto cleanup;
	}

	for (i = 0; i < test_packets; i++) {
		if (received[i])
			ping_sum += (recv_times[i] - send_times[i]) * 1000.0;
	}

	*out_ping = (float)(ping_sum / recv_count);
	*out_loss = (float)((test_packets - recv_count) * 100) / test_packets;
	success   = true;

cleanup:
	if (sock != INVALID_SOCKET) closesocket(sock);
	Q_free(send_times);
	Q_free(recv_times);
	Q_free(received);
	return success;
}

// ─────────────────────────────────────────────
// Score — lower is better
// Proxy routes are scored on their own scale so a good proxy
// (e.g. 50ms) is not penalised against a direct 12ms.
// ─────────────────────────────────────────────
static float CL_BR_Score(float ping_ms, float loss_pct, qbool via_proxy)
{
	float ping_ref  = via_proxy ? PING_REF_PROXY_MS : PING_REF_DIRECT_MS;
	float norm_ping = ping_ms  / (ping_ref * 2.0f);
	float norm_loss = loss_pct / 100.0f;
	float w_ping    = cl_connectbr_weight_ping.value;
	float w_loss    = cl_connectbr_weight_loss.value;
	return w_ping * norm_ping + w_loss * norm_loss;
}

// ─────────────────────────────────────────────
// qsort comparator
// ─────────────────────────────────────────────
static int CL_BR_RouteCompare(const void *a, const void *b)
{
	const route_t *ra = (const route_t *)a;
	const route_t *rb = (const route_t *)b;
	if (ra->score < rb->score) return -1;
	if (ra->score > rb->score) return  1;
	return 0;
}

// ─────────────────────────────────────────────
// First proxy in chain (closest hop to us)
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
// Measure a candidate — browser ping preferred,
// A2A_PING as fallback, cache for both.
// ─────────────────────────────────────────────
static qbool CL_BR_MeasureCandidate(const char *proxylist, qbool via_proxy,
                                     float *out_ping, float *out_loss)
{
	if (!out_ping || !out_loss) return false;

	if (proxylist && proxylist[0]) {
		char first_hop[64];
		netadr_t hop_addr;

		CL_BR_GetFirstHop(proxylist, first_hop, sizeof(first_hop));

		// Try cache first
		if (CL_BR_GetCached(first_hop, out_ping, out_loss))
			return true;

		NET_StringToAdr(first_hop, &hop_addr);

		// Browser ping is most accurate
		{
			int bp = CL_BR_GetBrowserPing(&hop_addr);
			if (bp >= 0) {
				*out_ping = (float)bp;
				*out_loss = 0;
				CL_BR_StoreCached(first_hop, *out_ping, *out_loss);
				return true;
			}
		}

		// Fallback: A2A_PING
		if (CL_BR_MeasureHop(&hop_addr, out_ping, out_loss)) {
			CL_BR_StoreCached(first_hop, *out_ping, *out_loss);
			return true;
		}
		return false;

	} else {
		// Direct: browser ping only (A2A_PING on game servers is unreliable)
		int bp = CL_BR_GetBrowserPing(&br_target_addr);
		if (bp >= 0) {
			*out_ping = (float)bp;
			*out_loss = 0;
			return true;
		}
		// Last resort: A2A_PING
		return CL_BR_MeasureHop(&br_target_addr, out_ping, out_loss);
	}
}

// ─────────────────────────────────────────────
// Apply route idx and connect
// ─────────────────────────────────────────────
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

// ─────────────────────────────────────────────
// PUBLIC: connectbr <address>
// ─────────────────────────────────────────────
void CL_Connect_BestRoute_f(void)
{
	extern cvar_t cl_proxyaddr;
	const char *addr;
	int i;

	// Guard against re-entry
	if (br_measuring) {
		Com_Printf("connectbr: measurement already in progress, please wait.\n");
		return;
	}

	if (Cmd_Argc() != 2) {
		Com_Printf("Usage: connectbr <address>\n");
		Com_Printf("Tests all proxy routes (ping + loss) and connects via the best one.\n");
		Com_Printf("Use 'connectnext' to try the next route if needed.\n");
		Com_Printf("Requires: sb_findroutes 1 + server browser refreshed.\n");
		return;
	}

	addr = Cmd_Argv(1);
	if (!addr || *addr == '\0') {
		Com_Printf("connectbr: empty address\n");
		return;
	}
	if (strlen(addr) > MAX_ADDRESS_LENGTH) {
		Com_Printf("connectbr: address too long\n");
		return;
	}

	if (!NET_StringToAdr(addr, &br_target_addr)) {
		Com_Printf("connectbr: invalid address '%s'\n", addr);
		return;
	}
	if (br_target_addr.port == 0)
		br_target_addr.port = htons(27500);

	if (SB_PingTree_IsBuilding()) {
		Com_Printf("connectbr: ping tree still building — please wait and retry.\n");
		return;
	}

	if (!SB_PingTree_Built()) {
		Com_Printf("connectbr: no route data.\n");
		Com_Printf("  Enable 'sb_findroutes 1', refresh the browser, then retry.\n");
		Com_Printf("  Falling back to direct connection...\n");
		Cvar_Set(&cl_proxyaddr, "");
		Cbuf_AddText(va("connect %s\n", addr));
		return;
	}

	br_measuring = true;
	Cvar_Set(&cl_proxyaddr, "");
	br_route_count   = 0;
	br_current_route = 0;
	br_active        = false;

	if ((int)cl_connectbr_verbose.value >= 1) {
		Com_Printf("\n&cf80connectbr:&r testing routes to %s...\n", addr);
		if ((int)cl_connectbr_verbose.value >= 2) {
			Com_Printf("  packets=%d  timeout=%dms  delay=%dms\n",
			           (int)cl_connectbr_test_packets.value,
			           (int)cl_connectbr_timeout_ms.value,
			           (int)cl_connectbr_packet_delay.value);
			Com_Printf("  score weights: ping=%.2f loss=%.2f\n",
			           cl_connectbr_weight_ping.value,
			           cl_connectbr_weight_loss.value);
		}
		Com_Printf("\n");
	}

	// ── Ping tree best proxy path ─────────────────────────────────────
	{
		int pathlen = SB_PingTree_GetPathLen(&br_target_addr);
		if (pathlen > 0) {
			int  dummy = 0;
			char proxy_str[MAX_PROXYLIST];

			if (SB_PingTree_GetProxyString(&br_target_addr, proxy_str,
			                               sizeof(proxy_str), &dummy)) {
				float ping, loss;
				Com_Printf("  [ping tree best (%d hop%s)]... ",
				           pathlen, pathlen > 1 ? "s" : "");

				if (CL_BR_MeasureCandidate(proxy_str, true, &ping, &loss)) {
					Com_Printf("ping=%s%.0fms&r  loss=%s%.0f%%&r\n",
					           CL_BR_PingColor(ping), ping,
					           CL_BR_LossColor(loss), loss);
					strlcpy(br_routes[br_route_count].proxylist, proxy_str,
					        sizeof(br_routes[0].proxylist));
					snprintf(br_routes[br_route_count].label,
					         sizeof(br_routes[0].label),
					         "ping tree best (%d hop%s)",
					         pathlen, pathlen > 1 ? "s" : "");
					br_routes[br_route_count].ping_ms   = ping;
					br_routes[br_route_count].loss_pct  = loss;
					br_routes[br_route_count].score     = CL_BR_Score(ping, loss, true);
					br_routes[br_route_count].via_proxy = true;
					br_routes[br_route_count].valid     = true;
					br_route_count++;
				} else {
					Com_Printf("&cf00unreachable&r\n");
				}
			}
		}
	}

	// ── Individual proxies from server browser ────────────────────────
	// Collect all qwfwd proxies while holding the lock, then measure
	// them without holding the lock (network I/O must not hold the lock).
	// Skip proxies whose IP matches the target server (pointless hop).
	{
		char proxy_ips  [CONNECTBR_MAX_PROXIES][64];
		char proxy_names[CONNECTBR_MAX_PROXIES][128];
		int  proxy_count = 0;

		SB_ServerList_Lock();
		for (i = 0; i < serversn && proxy_count < CONNECTBR_MAX_PROXIES; i++) {
			server_data *s = servers[i];
			char proxy_ip[64];
			int j;
			qbool dup = false;

			if (!s->qwfwd) continue;
			if (s->ping  < 0) continue;

			// Skip proxy if same IP as target server
			if (memcmp(s->address.ip, br_target_addr.ip, 4) == 0)
				continue;

			snprintf(proxy_ip, sizeof(proxy_ip), "%d.%d.%d.%d:%d",
			         s->address.ip[0], s->address.ip[1],
			         s->address.ip[2], s->address.ip[3],
			         ntohs(s->address.port));

			// Skip duplicates already in br_routes (ping tree)
			for (j = 0; j < br_route_count && !dup; j++)
				if (strcmp(br_routes[j].proxylist, proxy_ip) == 0) dup = true;

			// Skip duplicates in temp list
			for (j = 0; j < proxy_count && !dup; j++)
				if (strcmp(proxy_ips[j], proxy_ip) == 0) dup = true;

			if (dup) continue;

			strlcpy(proxy_ips  [proxy_count], proxy_ip,
			        sizeof(proxy_ips[0]));
			strlcpy(proxy_names[proxy_count],
			        s->display.name[0] ? s->display.name : proxy_ip,
			        sizeof(proxy_names[0]));
			proxy_count++;
		}
		SB_ServerList_Unlock();

		// Measure each collected proxy
		for (i = 0; i < proxy_count && br_route_count < CONNECTBR_MAX_ROUTES - 1; i++) {
			float ping, loss;
			Com_Printf("  [%s]... ", proxy_names[i]);

			if (CL_BR_MeasureCandidate(proxy_ips[i], true, &ping, &loss)) {
				Com_Printf("ping=%s%.0fms&r  loss=%s%.0f%%&r\n",
				           CL_BR_PingColor(ping), ping,
				           CL_BR_LossColor(loss), loss);
				strlcpy(br_routes[br_route_count].proxylist, proxy_ips[i],
				        sizeof(br_routes[0].proxylist));
				snprintf(br_routes[br_route_count].label,
				         sizeof(br_routes[0].label),
				         "via proxy %s", proxy_names[i]);
				br_routes[br_route_count].ping_ms   = ping;
				br_routes[br_route_count].loss_pct  = loss;
				br_routes[br_route_count].score     = CL_BR_Score(ping, loss, true);
				br_routes[br_route_count].via_proxy = true;
				br_routes[br_route_count].valid     = true;
				br_route_count++;
			} else {
				Com_Printf("&cf00unreachable&r\n");
			}
		}
	}

	// ── Direct connection ─────────────────────────────────────────────
	{
		float ping, loss;
		Com_Printf("  [direct]... ");
		if (CL_BR_MeasureCandidate("", false, &ping, &loss)) {
			Com_Printf("ping=%s%.0fms&r  loss=%s%.0f%%&r\n",
			           CL_BR_PingColor(ping), ping,
			           CL_BR_LossColor(loss), loss);
			br_routes[br_route_count].proxylist[0] = '\0';
			strlcpy(br_routes[br_route_count].label, "direct connection",
			        sizeof(br_routes[0].label));
			br_routes[br_route_count].ping_ms   = ping;
			br_routes[br_route_count].loss_pct  = loss;
			br_routes[br_route_count].score     = CL_BR_Score(ping, loss, false);
			br_routes[br_route_count].via_proxy = false;
			br_routes[br_route_count].valid     = true;
			br_route_count++;
		} else {
			Com_Printf("&cf00unreachable&r\n");
		}
	}

	br_measuring = false;

	if (br_route_count == 0) {
		Com_Printf("\nconnectbr: all routes failed.\n");
		return;
	}

	// Sort by score
	qsort(br_routes, br_route_count, sizeof(route_t), CL_BR_RouteCompare);

	// Show ranking
	Com_Printf("\n&cf80--- route ranking ---&r\n");
	for (i = 0; i < br_route_count; i++) {
		Com_Printf("  #%d %s\n     ping=%s%.0fms&r  loss=%s%.0f%%&r\n",
		           i + 1, br_routes[i].label,
		           CL_BR_PingColor(br_routes[i].ping_ms), br_routes[i].ping_ms,
		           CL_BR_LossColor(br_routes[i].loss_pct), br_routes[i].loss_pct);
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

// ─────────────────────────────────────────────
// PUBLIC: register cvars (call from CL_InitLocal)
// ─────────────────────────────────────────────
void CL_ConnectBR_Init(void)
{
	Cvar_SetCurrentGroup(CVAR_GROUP_NETWORK);
	Cvar_Register(&cl_connectbr_test_packets);
	Cvar_Register(&cl_connectbr_timeout_ms);
	Cvar_Register(&cl_connectbr_packet_delay);
	Cvar_Register(&cl_connectbr_ping_green);
	Cvar_Register(&cl_connectbr_ping_orange);
	Cvar_Register(&cl_connectbr_weight_ping);
	Cvar_Register(&cl_connectbr_weight_loss);
	Cvar_Register(&cl_connectbr_verbose);
	Cvar_Register(&cl_connectbr_debug);
	Cvar_ResetCurrentGroup();
}
