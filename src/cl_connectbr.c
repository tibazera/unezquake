/*
Copyright (C) 2024 unezQuake team

cl_connectbr.c - Smart route selection for connectbr/connectnext commands

Multi-hop logic (proxy chaining):
  For each proxy P1 known, query P1's full pingstatus reply.
  The reply contains every server/proxy P1 can reach with its ping.
  If P1 knows other proxies (port 30000), those become P2 candidates.
  For each P2, query P2's pingstatus to get P2->dest ping.
  Route cost = you->P1 + P1->P2 + P2->dest.
  This discovers chains like: you -> nordeste_proxy -> lisboa_proxy -> dest.

CVars:
  cl_connectbr_test_packets   - number of UDP probes per route (default 25)
  cl_connectbr_timeout_ms     - receive timeout in ms (default 600)
  cl_connectbr_packet_delay   - ms between probes (default 15)
  cl_connectbr_ping_green     - ping threshold for green colour (default 40 ms)
  cl_connectbr_ping_yellow    - ping threshold for yellow colour (default 80 ms)
  cl_connectbr_ping_orange    - ping threshold for orange colour (default 200 ms)
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
#define CONNECTBR_MAX_ROUTES      16
#define CONNECTBR_MAX_PROXIES     32
#define CONNECTBR_MAX_NEIGHBORS   64
#define MAX_PROXYLIST             256
#define MAX_ADDRESS_LENGTH        128

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

typedef struct {
	netadr_t addr;
	int      dist_ms;
} pingstatus_entry_t;

typedef struct {
	pingstatus_entry_t entries[CONNECTBR_MAX_NEIGHBORS];
	int                count;
	int                dest_ping;  /* -1 if dest not found in reply */
} pingstatus_reply_t;

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
// Always tested regardless of server browser state.
// --------------------------------------------
static const char *br_known_proxies[] = {
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
// Query a proxy's full pingstatus reply.
//
// Parses ALL entries:
//   - sets reply->dest_ping to proxy's ping to dest (-1 if not found)
//   - fills reply->entries[] with every host the proxy knows,
//     including other proxies (port 30000) for multi-hop discovery
//
// Returns true if a valid reply was received.
// --------------------------------------------
static qbool CL_BR_QueryPingstatus(const netadr_t *proxy_addr,
                                    const netadr_t *dest_addr,
                                    pingstatus_reply_t *reply)
{
	char     packet[] = "\xff\xff\xff\xffpingstatus";
	byte     buf[8 * 512];
	struct   sockaddr_storage addr_to, addr_from;
	socklen_t from_len;
	struct   timeval tv;
	fd_set   fd;
	socket_t sock;
	int      ret, timeout_ms;
	const byte *p, *end;

	reply->count     = 0;
	reply->dest_ping = -1;

	sock = UDP_OpenSocket(PORT_ANY);
	if (sock == INVALID_SOCKET) return false;

	NetadrToSockadr(proxy_addr, &addr_to);
	ret = sendto(sock, packet, strlen(packet), 0,
	             (struct sockaddr *)&addr_to, sizeof(struct sockaddr));
	if (ret < 0) { closesocket(sock); return false; }

	timeout_ms = (int)cl_connectbr_timeout_ms.value;
	if (timeout_ms <= 0) timeout_ms = 600;

	FD_ZERO(&fd);
	FD_SET(sock, &fd);
	tv.tv_sec  = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	ret = select(sock + 1, &fd, NULL, NULL, &tv);
	if (ret <= 0) { closesocket(sock); return false; }

	from_len = sizeof(addr_from);
	ret = recvfrom(sock, (char *)buf, sizeof(buf), 0,
	               (struct sockaddr *)&addr_from, &from_len);
	closesocket(sock);

	if (ret <= 5 || memcmp(buf, "\xff\xff\xff\xffn", 5) != 0)
		return false;

	p   = buf + 5;
	end = buf + ret;

	while (p + 8 <= end) {
		/* entry: 4B IP | 2B port (network order) | 2B ping (little-endian) */
		unsigned short port_net;
		short  dist_raw;
		int    dist_ms;

		memcpy(&port_net, p + 4, 2);
		memcpy(&dist_raw, p + 6, 2);
		dist_ms = (int)(short)LittleShort(dist_raw);

		if (dist_ms >= 0) {
			if (dest_addr &&
			    memcmp(p, dest_addr->ip, 4) == 0 &&
			    memcmp(p + 4, &dest_addr->port, 2) == 0) {
				reply->dest_ping = dist_ms;
			}
			if (reply->count < CONNECTBR_MAX_NEIGHBORS) {
				pingstatus_entry_t *e = &reply->entries[reply->count++];
				e->addr.type = NA_IP;
				memcpy(e->addr.ip, p, 4);
				e->addr.port = port_net;
				e->dist_ms   = dist_ms;
			}
		}
		p += 8;
	}

	return true;
}

// --------------------------------------------
// Score -- lower is better.
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
// Add a route if not duplicate and within slot limit
// --------------------------------------------
static void CL_BR_AddRoute(const char *proxylist, const char *label,
                            float ping_ms, qbool via_proxy)
{
	int i;
	if (br_route_count >= CONNECTBR_MAX_ROUTES) return;
	for (i = 0; i < br_route_count; i++)
		if (strcmp(br_routes[i].proxylist, proxylist) == 0) return;

	strlcpy(br_routes[br_route_count].proxylist, proxylist, MAX_PROXYLIST);
	strlcpy(br_routes[br_route_count].label,     label,     sizeof(br_routes[0].label));
	br_routes[br_route_count].ping_ms   = ping_ms;
	br_routes[br_route_count].loss_pct  = 0;
	br_routes[br_route_count].score     = CL_BR_Score(ping_ms, 0, via_proxy);
	br_routes[br_route_count].via_proxy = via_proxy;
	br_routes[br_route_count].valid     = true;
	br_route_count++;
}

// --------------------------------------------
// Helpers
// --------------------------------------------
static void CL_BR_AdrToStr(const netadr_t *a, char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "%d.%d.%d.%d:%d",
	         a->ip[0], a->ip[1], a->ip[2], a->ip[3], (int)ntohs(a->port));
}

static qbool CL_BR_IsTarget(const netadr_t *a)
{
	return (memcmp(a->ip, br_target_addr.ip, 4) == 0 &&
	        a->port == br_target_addr.port);
}

static qbool CL_BR_AdrEqual(const netadr_t *a, const netadr_t *b)
{
	return (memcmp(a->ip, b->ip, 4) == 0 && a->port == b->port);
}

// --------------------------------------------
// PUBLIC: connectbr <address>
// --------------------------------------------
void CL_Connect_BestRoute_f(void)
{
	extern cvar_t cl_proxyaddr;
	const char *addr;
	int i;

	netadr_t proxy_adr  [CONNECTBR_MAX_PROXIES];
	char     proxy_ip   [CONNECTBR_MAX_PROXIES][64];
	char     proxy_name [CONNECTBR_MAX_PROXIES][128];
	int      proxy_ping [CONNECTBR_MAX_PROXIES];
	int      proxy_count = 0;

	if (br_measuring) {
		Com_Printf("connectbr: measurement already in progress, please wait.\n");
		return;
	}

	if (Cmd_Argc() != 2) {
		Com_Printf("Usage: connectbr <address>\n");
		Com_Printf("Tests all proxy routes (1-hop and 2-hop chains) and connects via the best one.\n");
		Com_Printf("Use 'connectnext' to try the next route if needed.\n");
		return;
	}

	addr = Cmd_Argv(1);
	if (!addr || *addr == '\0') { Com_Printf("connectbr: empty address\n"); return; }
	if (strlen(addr) > MAX_ADDRESS_LENGTH) { Com_Printf("connectbr: address too long\n"); return; }

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

	// ══════════════════════════════════════════════════════════════════
	// Step 1: ping tree (Dijkstra multi-hop, if already built)
	// ══════════════════════════════════════════════════════════════════
	if (SB_PingTree_Built() && !SB_PingTree_IsBuilding()) {
		int pathlen = SB_PingTree_GetPathLen(&br_target_addr);
		if (pathlen > 0) {
			int  total_ping_ms = 0;
			char proxy_str[MAX_PROXYLIST];
			char target_str[64];
			proxy_str[0] = '\0';
			CL_BR_AdrToStr(&br_target_addr, target_str, sizeof(target_str));
			if (SB_PingTree_GetProxyString(&br_target_addr, proxy_str,
			                               sizeof(proxy_str), &total_ping_ms)
			    && proxy_str[0] != '\0'
			    && strcmp(proxy_str, target_str) != 0) {
				float ping = (total_ping_ms > 0) ? (float)total_ping_ms : 1.0f;
				char lbl[128];
				snprintf(lbl, sizeof(lbl), "ping tree (%d hop%s)",
				         pathlen, pathlen > 1 ? "s" : "");
				Com_Printf("  [%s]... ping=%s%.0fms&r\n",
				           lbl, CL_BR_PingColor(ping), ping);
				CL_BR_AddRoute(proxy_str, lbl, ping, true);
			}
		} else if ((int)cl_connectbr_verbose.value >= 1) {
			Com_Printf("  [ping tree] %s\n",
			           pathlen == 0 ? "rota direta e a melhor." : "sem caminho para este servidor.");
		}
	} else if (!SB_PingTree_Built() && (int)cl_connectbr_verbose.value >= 1) {
		Com_Printf("  [ping tree] nao construido -- use 'sb_findroutes 1' + 'sb_buildpingtree'.\n");
	}

	// ══════════════════════════════════════════════════════════════════
	// Step 2: collect proxy candidates
	// ══════════════════════════════════════════════════════════════════

	/* 2a: from server browser (port 30000 only) */
	SB_ServerList_Lock();
	for (i = 0; i < serversn && proxy_count < CONNECTBR_MAX_PROXIES; i++) {
		server_data *s = servers[i];
		int j; qbool dup = false;
		if (!s || ntohs(s->address.port) != 30000) continue;
		if (s->ping < 0) continue;
		if (CL_BR_IsTarget(&s->address)) continue;
		for (j = 0; j < proxy_count && !dup; j++)
			if (CL_BR_AdrEqual(&proxy_adr[j], &s->address)) dup = true;
		if (dup) continue;
		proxy_adr [proxy_count] = s->address;
		CL_BR_AdrToStr(&s->address, proxy_ip[proxy_count], sizeof(proxy_ip[0]));
		strlcpy(proxy_name[proxy_count],
		        s->display.name[0] ? s->display.name : proxy_ip[proxy_count],
		        sizeof(proxy_name[0]));
		proxy_ping[proxy_count] = s->ping;
		proxy_count++;
	}
	SB_ServerList_Unlock();

	/* 2b: hardcoded list -- always merged */
	for (i = 0; br_known_proxies[i] && proxy_count < CONNECTBR_MAX_PROXIES; i++) {
		netadr_t ka; int j; qbool dup = false;
		if (!NET_StringToAdr(br_known_proxies[i], &ka)) continue;
		if (CL_BR_IsTarget(&ka)) continue;
		for (j = 0; j < proxy_count && !dup; j++)
			if (CL_BR_AdrEqual(&proxy_adr[j], &ka)) dup = true;
		if (dup) continue;
		proxy_adr [proxy_count] = ka;
		strlcpy(proxy_ip  [proxy_count], br_known_proxies[i], sizeof(proxy_ip  [0]));
		strlcpy(proxy_name[proxy_count], br_known_proxies[i], sizeof(proxy_name[0]));
		proxy_ping[proxy_count] = 9999;
		proxy_count++;
	}

	/* Sort by browser ping ascending */
	{
		int ii, jj;
		for (ii = 1; ii < proxy_count; ii++) {
			netadr_t tmp_adr  = proxy_adr [ii];
			char     tmp_ip  [64];
			char     tmp_name[128];
			int      tmp_ping = proxy_ping[ii];
			strlcpy(tmp_ip,   proxy_ip  [ii], sizeof(tmp_ip));
			strlcpy(tmp_name, proxy_name[ii], sizeof(tmp_name));
			for (jj = ii - 1; jj >= 0 && proxy_ping[jj] > tmp_ping; jj--) {
				proxy_adr [jj + 1] = proxy_adr [jj];
				proxy_ping[jj + 1] = proxy_ping[jj];
				strlcpy(proxy_ip  [jj + 1], proxy_ip  [jj], sizeof(proxy_ip  [0]));
				strlcpy(proxy_name[jj + 1], proxy_name[jj], sizeof(proxy_name[0]));
			}
			proxy_adr [jj + 1] = tmp_adr;
			proxy_ping[jj + 1] = tmp_ping;
			strlcpy(proxy_ip  [jj + 1], tmp_ip,   sizeof(proxy_ip  [0]));
			strlcpy(proxy_name[jj + 1], tmp_name, sizeof(proxy_name[0]));
		}
	}

	if ((int)cl_connectbr_verbose.value >= 1)
		Com_Printf("  [proxies] %d candidato(s)\n\n", proxy_count);

	// ══════════════════════════════════════════════════════════════════
	// Step 3: probe each proxy P1 -- build 1-hop and 2-hop routes
	//
	//  1-hop:  você ──► P1 ──► dest
	//  2-hop:  você ──► P1 ──► P2 ──► dest
	//          P2 is any proxy (port 30000) found inside P1's pingstatus
	// ══════════════════════════════════════════════════════════════════
	for (i = 0; i < proxy_count; i++) {
		pingstatus_reply_t p1_reply;
		int   ping_you_p1;
		float fping, floss;
		char  proxylist[MAX_PROXYLIST];
		char  lbl[128];
		int   j;

		/* you -> P1 */
		ping_you_p1 = CL_BR_GetBrowserPing(&proxy_adr[i]);
		if (ping_you_p1 < 0) {
			if (!CL_BR_MeasureHop(&proxy_adr[i], &fping, &floss)) {
				Com_Printf("  [%s] &cf00unreachable&r\n", proxy_name[i]);
				continue;
			}
			ping_you_p1 = (int)fping;
		}

		/* Query P1's full pingstatus */
		if (!CL_BR_QueryPingstatus(&proxy_adr[i], &br_target_addr, &p1_reply)) {
			/* No reply -- add 1-hop with estimated dest */
			int direct = CL_BR_GetBrowserPing(&br_target_addr);
			int est    = (direct > 0) ? direct / 2 : ping_you_p1;
			Com_Printf("  [%s] ping_voce_proxy=%dms  &cfa0sem pingstatus (dest estimado)&r\n",
			           proxy_name[i], ping_you_p1);
			snprintf(lbl, sizeof(lbl), "via %s [1 hop, dest est.]", proxy_name[i]);
			CL_BR_AddRoute(proxy_ip[i], lbl, (float)(ping_you_p1 + est), true);
			continue;
		}

		/* ── 1-hop ── */
		if (p1_reply.dest_ping >= 0) {
			int total = ping_you_p1 + p1_reply.dest_ping;
			Com_Printf("  [%s] ping=%s%dms&r  "
			           "(voce->P1 &cff0%dms&r + P1->dest &cff0%dms&r)  &c0f01 hop&r\n",
			           proxy_name[i],
			           CL_BR_PingColor((float)total), total,
			           ping_you_p1, p1_reply.dest_ping);
			snprintf(lbl, sizeof(lbl), "via %s [1 hop]", proxy_name[i]);
			CL_BR_AddRoute(proxy_ip[i], lbl, (float)total, true);
		} else {
			int direct = CL_BR_GetBrowserPing(&br_target_addr);
			int est    = (direct > 0) ? direct / 2 : ping_you_p1;
			int total  = ping_you_p1 + est;
			Com_Printf("  [%s] ping=%s%dms&r  "
			           "(voce->P1 &cff0%dms&r + dest &cfa0estimado %dms&r)  &c0f01 hop&r\n",
			           proxy_name[i],
			           CL_BR_PingColor((float)total), total,
			           ping_you_p1, est);
			snprintf(lbl, sizeof(lbl), "via %s [1 hop, dest est.]", proxy_name[i]);
			CL_BR_AddRoute(proxy_ip[i], lbl, (float)total, true);
		}

		/* ── 2-hop: scan P1's pingstatus for other proxies (P2) ── */
		for (j = 0; j < p1_reply.count; j++) {
			pingstatus_entry_t *nb = &p1_reply.entries[j];
			pingstatus_reply_t  p2_reply;
			int  ping_p1_p2, ping_p2_dest, total2;
			char p2_ip[64];

			if (ntohs(nb->addr.port) != 30000)             continue;
			if (CL_BR_IsTarget(&nb->addr))                 continue;
			if (CL_BR_AdrEqual(&nb->addr, &proxy_adr[i]))  continue;
			/* skip 0.0.0.0 */
			if (nb->addr.ip[0] == 0 && nb->addr.ip[1] == 0 &&
			    nb->addr.ip[2] == 0 && nb->addr.ip[3] == 0) continue;

			ping_p1_p2 = nb->dist_ms;
			CL_BR_AdrToStr(&nb->addr, p2_ip, sizeof(p2_ip));

			BR_Debug("  chain candidato: %s -> %s -> dest\n", proxy_name[i], p2_ip);

			if (!CL_BR_QueryPingstatus(&nb->addr, &br_target_addr, &p2_reply))
				continue;
			if (p2_reply.dest_ping < 0)
				continue;

			ping_p2_dest = p2_reply.dest_ping;
			total2       = ping_you_p1 + ping_p1_p2 + ping_p2_dest;

			Com_Printf("  [%s -> %s] ping=%s%dms&r  "
			           "(voce->P1 &cff0%dms&r + P1->P2 &cff0%dms&r + P2->dest &cff0%dms&r)  "
			           "&cf802 hops&r\n",
			           proxy_name[i], p2_ip,
			           CL_BR_PingColor((float)total2), total2,
			           ping_you_p1, ping_p1_p2, ping_p2_dest);

			/* proxylist for 2-hop: "P1:port@P2:port" */
			snprintf(proxylist, sizeof(proxylist), "%s@%s", proxy_ip[i], p2_ip);
			snprintf(lbl, sizeof(lbl), "via %s -> %s [2 hops]", proxy_name[i], p2_ip);
			CL_BR_AddRoute(proxylist, lbl, (float)total2, true);
		}
	}

	// ══════════════════════════════════════════════════════════════════
	// Step 4: direct connection
	// ══════════════════════════════════════════════════════════════════
	{
		int dp = CL_BR_GetBrowserPing(&br_target_addr);
		if (dp < 0) {
			float fping, floss;
			if (CL_BR_MeasureHop(&br_target_addr, &fping, &floss))
				dp = (int)fping;
		}
		if (dp > 0) {
			Com_Printf("  [direto] ping=%s%dms&r\n", CL_BR_PingColor((float)dp), dp);
			CL_BR_AddRoute("", "direct connection", (float)dp, false);
		} else {
			Com_Printf("  [direto] &cf00unreachable&r\n");
		}
	}

	br_measuring = false;

	if (br_route_count == 0) {
		Com_Printf("\nconnectbr: all routes failed.\n");
		return;
	}

	qsort(br_routes, br_route_count, sizeof(route_t), CL_BR_RouteCompare);

	/* Remove unplayable routes */
	{
		int max_ping = (int)cl_connectbr_ping_orange.value;
		int usable   = 0;
		if (max_ping <= 0) max_ping = 200;
		for (i = 0; i < br_route_count; i++) {
			if (br_routes[i].ping_ms <= max_ping) {
				if (i != usable) br_routes[usable] = br_routes[i];
				usable++;
			}
		}
		if (usable < br_route_count) {
			Com_Printf("  (%d rota(s) acima de %dms removida(s))\n",
			           br_route_count - usable, max_ping);
			br_route_count = usable;
		}
	}

	if (br_route_count == 0) {
		int max_ping = (int)cl_connectbr_ping_orange.value;
		if (max_ping <= 0) max_ping = 200;
		Com_Printf("\nconnectbr: todas as rotas acima de %dms -- injogavel.\n", max_ping);
		br_active = false;
		return;
	}

	Com_Printf("\n&cf80--- ranking de rotas ---&r\n");
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
