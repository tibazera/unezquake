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
  cl_connectbr_ping_green     - ping threshold for green colour (default 40 ms)
  cl_connectbr_ping_yellow    - ping threshold for yellow colour (default 80 ms)
  cl_connectbr_ping_orange    - ping threshold for orange colour (default 200 ms); above = red (unplayable)
  cl_connectbr_weight_ping    - score weight for ping (default 0.6)
  cl_connectbr_weight_loss    - score weight for loss (default 0.4)
  cl_connectbr_verbose        - verbosity level 0/1/2 (default 1)
  cl_connectbr_debug          - debug logging 0/1 (default 0)
*/

#include "quakedef.h"
#include "EX_browser.h"
#include "cl_connectbr.h"

// --------------------------------------------
// CVars
// --------------------------------------------
cvar_t cl_connectbr_test_packets  = {"cl_connectbr_test_packets",  "25",   CVAR_ARCHIVE};
cvar_t cl_connectbr_timeout_ms    = {"cl_connectbr_timeout_ms",    "600",  CVAR_ARCHIVE};
cvar_t cl_connectbr_packet_delay  = {"cl_connectbr_packet_delay",  "15",   CVAR_ARCHIVE};
cvar_t cl_connectbr_ping_green    = {"cl_connectbr_ping_green",    "40",   CVAR_ARCHIVE};
cvar_t cl_connectbr_ping_yellow   = {"cl_connectbr_ping_yellow",   "80",   CVAR_ARCHIVE};
cvar_t cl_connectbr_ping_orange   = {"cl_connectbr_ping_orange",   "200",  CVAR_ARCHIVE};
cvar_t cl_connectbr_weight_ping   = {"cl_connectbr_weight_ping",   "0.6",  CVAR_ARCHIVE};
cvar_t cl_connectbr_weight_loss   = {"cl_connectbr_weight_loss",   "0.4",  CVAR_ARCHIVE};
cvar_t cl_connectbr_verbose       = {"cl_connectbr_verbose",       "1",    CVAR_ARCHIVE};
cvar_t cl_connectbr_debug         = {"cl_connectbr_debug",         "0",    CVAR_ARCHIVE};

// --------------------------------------------
// Constants
// --------------------------------------------
#define CONNECTBR_MAX_ROUTES    12
#define CONNECTBR_MAX_PROXIES   32
#define MAX_PROXYLIST           256
#define MAX_ADDRESS_LENGTH      128

#define BR_Debug(...) \
	do { if (cl_connectbr_debug.value) Com_Printf("[connectbr] " __VA_ARGS__); } while(0)

// --------------------------------------------
// Types
// --------------------------------------------
typedef struct {
	char    proxylist[MAX_PROXYLIST];
	char    label[128];
	float   ping_ms;
	float   loss_pct;
	float   score;
	qbool   via_proxy;
	qbool   valid;
} route_t;

// --------------------------------------------
// State
// --------------------------------------------
static route_t   br_routes[CONNECTBR_MAX_ROUTES];
static int       br_route_count   = 0;
static int       br_current_route = 0;
static netadr_t  br_target_addr;
static qbool     br_active        = false;
static qbool     br_measuring     = false;

// --------------------------------------------
// Known QW proxy fallback list
// --------------------------------------------
static const char *br_known_proxies[] = {
	"177.93.132.220:30000",
	"103.63.29.40:30000",
	"arenacamper.ddns.net:30000",
	"berlin.qwsv.net:30000",
	NULL
};

// --------------------------------------------
// Colour helpers
// --------------------------------------------
static const char *CL_BR_PingColor(float ms)
{
	int g = (int)cl_connectbr_ping_green.value;
	int y = (int)cl_connectbr_ping_yellow.value;
	int o = (int)cl_connectbr_ping_orange.value;
	if (g <= 0) g = 40;
	if (y <= 0) y = 80;
	if (o <= 0) o = 200;
	if (ms <= g) return "&c0f0";
	if (ms <= y) return "&cff0";
	if (ms <= o) return "&cfa0";
	return "&cf00";
}

static const char *CL_BR_LossColor(float pct)
{
	if (pct <= 0) return "&c0f0";
	if (pct <= 5) return "&cff0";
	return "&cf00";
}

// --------------------------------------------
// Browser ping lookup
// --------------------------------------------
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

// --------------------------------------------
// A2A_PING measurement
// --------------------------------------------
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

	{
		int pkt_delay = (int)cl_connectbr_packet_delay.value;
		if (pkt_delay < 5) pkt_delay = 5;
		for (i = 0; i < test_packets; i++) {
			send_times[i] = Sys_DoubleTime();
			sendto(sock, packet, strlen(packet), 0,
			       (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
			Sys_MSleep(pkt_delay);
		}
	}

	{
		int timeout_ms = (int)cl_connectbr_timeout_ms.value;
		if (timeout_ms <= 0) timeout_ms = 600;
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

// --------------------------------------------
// Query a single proxy for its ping to the destination server.
// Uses the qwfwd "pingstatus" packet -- same protocol the ping tree uses.
// Returns proxy->dest ping in ms, or -1 if not found.
// This is called only ONCE per connectbr (for the chosen proxy),
// not in a loop -- so it does NOT cause freezing.
// --------------------------------------------
static int CL_BR_GetProxyToDestPing(const netadr_t *proxy_addr,
                                     const netadr_t *dest_addr)
{
	char packet[] = "\xff\xff\xff\xffpingstatus";
	byte buf[8 * 512];
	struct sockaddr_storage addr_to, addr_from;
	socklen_t from_len;
	struct timeval tv;
	fd_set fd;
	socket_t sock;
	int ret, timeout_ms, result = -1;

	sock = UDP_OpenSocket(PORT_ANY);
	if (sock == INVALID_SOCKET) return -1;

	NetadrToSockadr(proxy_addr, &addr_to);
	ret = sendto(sock, packet, strlen(packet), 0,
	             (struct sockaddr *)&addr_to, sizeof(struct sockaddr));
	if (ret < 0) { closesocket(sock); return -1; }

	timeout_ms = (int)cl_connectbr_timeout_ms.value;
	if (timeout_ms <= 0) timeout_ms = 600;

	FD_ZERO(&fd);
	FD_SET(sock, &fd);
	tv.tv_sec  = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	ret = select(sock + 1, &fd, NULL, NULL, &tv);
	if (ret > 0) {
		from_len = sizeof(addr_from);
		ret = recvfrom(sock, (char *)buf, sizeof(buf), 0,
		               (struct sockaddr *)&addr_from, &from_len);
		if (ret > 5 && memcmp(buf, "\xff\xff\xff\xffn", 5) == 0) {
			const byte *p   = buf + 5;
			const byte *end = buf + ret;
			while (p + 8 <= end) {
				if (memcmp(p, dest_addr->ip, 4) == 0) {
					short dist;
					memcpy(&dist, p + 6, 2);
					dist = (short)LittleShort(dist);
					if (dist >= 0) result = (int)dist;
					break;
				}
				p += 8;
			}
		}
	}
	closesocket(sock);
	return result;
}

// --------------------------------------------
// Score -- lower is better, single absolute scale.
// --------------------------------------------
static float CL_BR_Score(float ping_ms, float loss_pct, qbool via_proxy)
{
	float o       = cl_connectbr_ping_orange.value > 0 ? cl_connectbr_ping_orange.value : 200.0f;
	float w_ping  = cl_connectbr_weight_ping.value > 0 ? cl_connectbr_weight_ping.value : 0.6f;
	float w_loss  = cl_connectbr_weight_loss.value > 0 ? cl_connectbr_weight_loss.value : 0.4f;
	float norm_ping = ping_ms  / (o * 2.0f);
	float norm_loss = loss_pct / 100.0f;
	(void)via_proxy;
	return w_ping * norm_ping + w_loss * norm_loss;
}

// --------------------------------------------
// qsort comparator
// --------------------------------------------
static int CL_BR_RouteCompare(const void *a, const void *b)
{
	const route_t *ra = (const route_t *)a;
	const route_t *rb = (const route_t *)b;
	if (ra->score < rb->score) return -1;
	if (ra->score > rb->score) return  1;
	return 0;
}

// --------------------------------------------
// Apply route and connect
// --------------------------------------------
static void CL_BR_ApplyRoute(int idx)
{
	extern cvar_t cl_proxyaddr;
	route_t *r = &br_routes[idx];

	Cvar_Set(&cl_proxyaddr, "");
	if (r->proxylist[0])
		Cvar_Set(&cl_proxyaddr, r->proxylist);

	Com_Printf("\n&cf80connectbr:&r route #%d - %s\n", idx + 1, r->label);
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

// --------------------------------------------
// PUBLIC: connectbr <address>
// --------------------------------------------
void CL_Connect_BestRoute_f(void)
{
	extern cvar_t cl_proxyaddr;
	const char *addr;
	int i;

	if (br_measuring) {
		Com_Printf("connectbr: measurement already in progress, please wait.\n");
		return;
	}

	if (Cmd_Argc() != 2) {
		Com_Printf("Usage: connectbr <address>\n");
		Com_Printf("Tests all proxy routes and connects via the best one.\n");
		Com_Printf("Use 'connectnext' to try the next route if needed.\n");
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
		Com_Printf("connectbr: ping tree still building -- please wait and retry.\n");
		return;
	}

	br_measuring     = true;
	Cvar_Set(&cl_proxyaddr, "");
	br_route_count   = 0;
	br_current_route = 0;
	br_active        = false;

	if ((int)cl_connectbr_verbose.value >= 1) {
		Com_Printf("\n&cf80connectbr:&r testing routes to %s...\n", addr);
		Com_Printf("\n");
	}

	// ── Step 1: ping tree best route (includes real multi-hop via Dijkstra) ──
	// SB_PingTree_GetProxyString already returns the full chain with correct
	// total ping calculated by the ping tree's own Dijkstra -- this is the
	// authoritative multi-hop result when the ping tree is available.
	if (SB_PingTree_Built() && br_route_count < CONNECTBR_MAX_ROUTES - 1) {
		int pathlen = SB_PingTree_GetPathLen(&br_target_addr);
		if (pathlen > 0) {
			int  total_ping_ms = 0;
			char proxy_str[MAX_PROXYLIST];
			if (SB_PingTree_GetProxyString(&br_target_addr, proxy_str,
			                               sizeof(proxy_str), &total_ping_ms)
			    && total_ping_ms > 0) {
				float ping = (float)total_ping_ms;
				Com_Printf("  [ping tree best (%d hop%s)]... ping=%s%.0fms&r  loss=%s0%%&r\n",
				           pathlen, pathlen > 1 ? "s" : "",
				           CL_BR_PingColor(ping), ping,
				           CL_BR_LossColor(0));
				strlcpy(br_routes[br_route_count].proxylist, proxy_str,
				        sizeof(br_routes[0].proxylist));
				snprintf(br_routes[br_route_count].label,
				         sizeof(br_routes[0].label),
				         "ping tree best (%d hop%s)",
				         pathlen, pathlen > 1 ? "s" : "");
				br_routes[br_route_count].ping_ms   = ping;
				br_routes[br_route_count].loss_pct  = 0;
				br_routes[br_route_count].score     = CL_BR_Score(ping, 0, true);
				br_routes[br_route_count].via_proxy = true;
				br_routes[br_route_count].valid     = true;
				br_route_count++;
			}
		}
	}

	// ── Step 2: individual proxies from browser + hardcoded fallback ──
	// For each proxy: measure you->proxy ping, then query that single proxy
	// for its ping to the destination (proxy->dest). Total = you->proxy + proxy->dest.
	// This is ONE pingstatus call per proxy -- not a full graph scan -- so it
	// does not block the client.
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

			if (!s) continue;
			if (!s->qwfwd) continue;
			if (s->ping < 0) continue;
			if (memcmp(s->address.ip, br_target_addr.ip, 4) == 0) continue;

			snprintf(proxy_ip, sizeof(proxy_ip), "%d.%d.%d.%d:%d",
			         s->address.ip[0], s->address.ip[1],
			         s->address.ip[2], s->address.ip[3],
			         ntohs(s->address.port));

			for (j = 0; j < br_route_count && !dup; j++)
				if (strcmp(br_routes[j].proxylist, proxy_ip) == 0) dup = true;
			for (j = 0; j < proxy_count && !dup; j++)
				if (strcmp(proxy_ips[j], proxy_ip) == 0) dup = true;
			if (dup) continue;

			strlcpy(proxy_ips  [proxy_count], proxy_ip, sizeof(proxy_ips[0]));
			strlcpy(proxy_names[proxy_count],
			        s->display.name[0] ? s->display.name : proxy_ip,
			        sizeof(proxy_names[0]));
			proxy_count++;
		}
		SB_ServerList_Unlock();

		// Hardcoded fallback if browser empty
		if (proxy_count == 0) {
			int k;
			for (k = 0; br_known_proxies[k] && proxy_count < CONNECTBR_MAX_PROXIES; k++) {
				netadr_t kaddr;
				int j;
				qbool dup = false;
				if (!NET_StringToAdr(br_known_proxies[k], &kaddr)) continue;
				if (memcmp(kaddr.ip, br_target_addr.ip, 4) == 0) continue;
				for (j = 0; j < br_route_count && !dup; j++)
					if (strcmp(br_routes[j].proxylist, br_known_proxies[k]) == 0) dup = true;
				for (j = 0; j < proxy_count && !dup; j++)
					if (strcmp(proxy_ips[j], br_known_proxies[k]) == 0) dup = true;
				if (dup) continue;
				strlcpy(proxy_ips  [proxy_count], br_known_proxies[k], sizeof(proxy_ips[0]));
				strlcpy(proxy_names[proxy_count], br_known_proxies[k], sizeof(proxy_names[0]));
				proxy_count++;
			}
		}

		// Measure each proxy: you->proxy + proxy->dest
		for (i = 0; i < proxy_count && br_route_count < CONNECTBR_MAX_ROUTES - 1; i++) {
			netadr_t proxy_adr;
			int ping_you_proxy, proxy_to_dest, total_ping;
			float fping, floss;

			if (!NET_StringToAdr(proxy_ips[i], &proxy_adr)) continue;

			// you -> proxy
			ping_you_proxy = CL_BR_GetBrowserPing(&proxy_adr);
			if (ping_you_proxy < 0) {
				if (!CL_BR_MeasureHop(&proxy_adr, &fping, &floss)) {
					Com_Printf("  [%s]... &cf00unreachable&r\n", proxy_names[i]);
					continue;
				}
				ping_you_proxy = (int)fping;
			}

			// proxy -> dest (single pingstatus query -- does NOT block for long)
			proxy_to_dest = CL_BR_GetProxyToDestPing(&proxy_adr, &br_target_addr);
			if (proxy_to_dest < 0) {
				// proxy doesn't know about dest -- use direct ping as estimate
				int direct = CL_BR_GetBrowserPing(&br_target_addr);
				proxy_to_dest = (direct > 0) ? direct : ping_you_proxy;
			}

			total_ping = ping_you_proxy + proxy_to_dest;

			Com_Printf("  [%s]... ping=%s%dms&r  loss=%s0%%&r\n",
			           proxy_names[i],
			           CL_BR_PingColor((float)total_ping), total_ping,
			           CL_BR_LossColor(0));

			strlcpy(br_routes[br_route_count].proxylist, proxy_ips[i],
			        sizeof(br_routes[0].proxylist));
			snprintf(br_routes[br_route_count].label,
			         sizeof(br_routes[0].label),
			         "via proxy %s", proxy_names[i]);
			br_routes[br_route_count].ping_ms   = (float)total_ping;
			br_routes[br_route_count].loss_pct  = 0;
			br_routes[br_route_count].score     = CL_BR_Score((float)total_ping, 0, true);
			br_routes[br_route_count].via_proxy = true;
			br_routes[br_route_count].valid     = true;
			br_route_count++;
		}
	}

	// ── Step 3: direct connection ──
	if (br_route_count < CONNECTBR_MAX_ROUTES) {
		int dp = CL_BR_GetBrowserPing(&br_target_addr);
		if (dp < 0) {
			float fping, floss;
			if (CL_BR_MeasureHop(&br_target_addr, &fping, &floss))
				dp = (int)fping;
		}
		if (dp > 0) {
			Com_Printf("  [direct]... ping=%s%dms&r  loss=%s0%%&r\n",
			           CL_BR_PingColor((float)dp), dp,
			           CL_BR_LossColor(0));
			br_routes[br_route_count].proxylist[0] = '\0';
			strlcpy(br_routes[br_route_count].label, "direct connection",
			        sizeof(br_routes[0].label));
			br_routes[br_route_count].ping_ms   = (float)dp;
			br_routes[br_route_count].loss_pct  = 0;
			br_routes[br_route_count].score     = CL_BR_Score((float)dp, 0, false);
			br_routes[br_route_count].via_proxy = false;
			br_routes[br_route_count].valid     = true;
			br_route_count++;
		} else {
			Com_Printf("  [direct]... &cf00unreachable&r\n");
		}
	}

	br_measuring = false;

	if (br_route_count == 0) {
		Com_Printf("\nconnectbr: all routes failed.\n");
		return;
	}

	// Sort by score
	qsort(br_routes, br_route_count, sizeof(route_t), CL_BR_RouteCompare);

	// Filter unplayable routes
	{
		int max_ping = (int)cl_connectbr_ping_orange.value;
		int usable   = 0;
		if (max_ping <= 0) max_ping = 200;
		for (i = 0; i < br_route_count; i++) {
			if (br_routes[i].ping_ms <= max_ping) {
				if (i != usable)
					br_routes[usable] = br_routes[i];
				usable++;
			}
		}
		if (usable < br_route_count) {
			Com_Printf("  (%d route(s) with ping >%dms removed -- unplayable)\n",
			           br_route_count - usable, max_ping);
			br_route_count = usable;
		}
	}

	if (br_route_count == 0) {
		Com_Printf("\nconnectbr: all routes have ping above %dms -- unplayable.\n",
		           (int)cl_connectbr_ping_orange.value > 0 ? (int)cl_connectbr_ping_orange.value : 200);
		br_active = false;
		return;
	}

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

// --------------------------------------------
// PUBLIC: connectnext
// --------------------------------------------
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

// --------------------------------------------
// PUBLIC: register cvars
// --------------------------------------------
void CL_ConnectBR_Init(void)
{
	Cvar_SetCurrentGroup(CVAR_GROUP_NETWORK);
	Cvar_Register(&cl_connectbr_test_packets);
	Cvar_Register(&cl_connectbr_timeout_ms);
	Cvar_Register(&cl_connectbr_packet_delay);
	Cvar_Register(&cl_connectbr_ping_green);
	Cvar_Register(&cl_connectbr_ping_yellow);
	Cvar_Register(&cl_connectbr_ping_orange);
	Cvar_Register(&cl_connectbr_weight_ping);
	Cvar_Register(&cl_connectbr_weight_loss);
	Cvar_Register(&cl_connectbr_verbose);
	Cvar_Register(&cl_connectbr_debug);
	Cvar_ResetCurrentGroup();
}
