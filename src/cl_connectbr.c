/*
Copyright (C) 2024 unezQuake team

cl_connectbr.c - Smart route selection for connectbr/connectnext commands

Multi-hop logic (Dijkstra):
  Batch-queries all proxy candidates simultaneously.
  Discovers extra proxies from pingstatus replies (P2, P3, P4...).
  Runs full Dijkstra over the proxy graph (any number of hops).
  Measures real packet loss with inter-packet delay.
*/

#include "quakedef.h"
#include "EX_browser.h"
#include "cl_connectbr.h"

// cl_proxyaddr is declared in cl_main.c
extern cvar_t cl_proxyaddr;

// --------------------------------------------
// CVars
// --------------------------------------------
cvar_t cl_connectbr_timeout_ms    = {"cl_connectbr_timeout_ms",    "600",  CVAR_ARCHIVE};
cvar_t cl_connectbr_ping_green    = {"cl_connectbr_ping_green",    "40",   CVAR_ARCHIVE};
cvar_t cl_connectbr_ping_yellow   = {"cl_connectbr_ping_yellow",   "80",   CVAR_ARCHIVE};
cvar_t cl_connectbr_ping_orange   = {"cl_connectbr_ping_orange",   "200",  CVAR_ARCHIVE};
cvar_t cl_connectbr_weight_ping   = {"cl_connectbr_weight_ping",   "1.0",  CVAR_ARCHIVE};
cvar_t cl_connectbr_weight_loss   = {"cl_connectbr_weight_loss",   "0.4",  CVAR_ARCHIVE};
cvar_t cl_connectbr_test_packets  = {"cl_connectbr_test_packets",  "10",   CVAR_ARCHIVE};
cvar_t cl_connectbr_packet_delay  = {"cl_connectbr_packet_delay",  "15",   CVAR_ARCHIVE};
cvar_t cl_connectbr_verbose       = {"cl_connectbr_verbose",       "1",    CVAR_ARCHIVE};
cvar_t cl_connectbr_debug         = {"cl_connectbr_debug",         "0",    CVAR_ARCHIVE};

// --------------------------------------------
// Constants
// --------------------------------------------
#define CONNECTBR_MAX_PROXIES     192
#define CONNECTBR_MAX_NEIGHBORS   64
#define CONNECTBR_MAX_ROUTES      256
#define MAX_PROXYLIST             256
#define MAX_ADDRESS_LENGTH        128

#define DIJKSTRA_MAX_NODES        (CONNECTBR_MAX_PROXIES + 1)
#define DIJKSTRA_INF              999999

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
} ps_entry_t;

typedef struct {
	ps_entry_t entries[CONNECTBR_MAX_NEIGHBORS];
	int        count;
	int        dest_ping;
} ps_reply_t;

typedef struct {
	netadr_t  addr;
	char      ip_str[64];
	char      name[128];
	int       you_ms;
	float     loss_pct;
	socket_t  sock;
	qbool     replied;
	ps_reply_t ps;
} proxy_t;

// --------------------------------------------
// State
// --------------------------------------------
static route_t   br_routes[CONNECTBR_MAX_ROUTES];
static int       br_route_count   = 0;
static int       br_current_route = 0;
static netadr_t  br_target_addr;
static qbool     br_active        = false;
static qbool     br_measuring     = false;
static qbool     br_done          = false;
static char      br_ranking_buf[4096];

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

static int CL_BR_FindNodeIndex(const proxy_t *proxies, int count, const netadr_t *adr)
{
	int i;
	for (i = 0; i < count; i++)
		if (CL_BR_AdrEqual(&proxies[i].addr, adr))
			return i;
	return -1;
}

// --------------------------------------------
// Parse pingstatus reply
// --------------------------------------------
static void CL_BR_ParsePingstatus(const byte *buf, int len,
                                  const netadr_t *dest, ps_reply_t *ps)
{
	const byte *p   = buf;
	const byte *end = buf + len;

	ps->count     = 0;
	ps->dest_ping = -1;

	while (p + 8 <= end) {
		unsigned short port_net;
		short dist_raw;
		int   dist_ms;

		memcpy(&port_net, p + 4, 2);
		memcpy(&dist_raw, p + 6, 2);
		dist_ms = (int)(short)LittleShort(dist_raw);

		if (dist_ms >= 0) {
			if (dest &&
			    memcmp(p, dest->ip, 4) == 0 &&
			    memcmp(p + 4, &dest->port, 2) == 0) {
				ps->dest_ping = dist_ms;
			}
			if (ps->count < CONNECTBR_MAX_NEIGHBORS) {
				ps_entry_t *e = &ps->entries[ps->count++];
				e->addr.type = NA_IP;
				memcpy(e->addr.ip, p, 4);
				e->addr.port = port_net;
				e->dist_ms   = dist_ms;
			}
		}
		p += 8;
	}
}

// --------------------------------------------
// Batch pingstatus (com delay entre pacotes)
// --------------------------------------------
static void CL_BR_BatchPingstatus(proxy_t *proxies, int count,
                                  const netadr_t *dest, int timeout_ms)
{
	const char *packet       = "\xff\xff\xff\xffpingstatus";
	size_t      packet_len   = strlen(packet);   // 14 bytes - CORRIGIDO
	int         packet_count = (int)cl_connectbr_test_packets.value;
	double      delay_sec    = cl_connectbr_packet_delay.value / 1000.0;
	double     *send_times   = NULL;
	int        *recv_count   = NULL;
	int         i, pkt;
	double      deadline;
	struct timeval tv;

	if (packet_count < 1)  packet_count = 1;
	if (packet_count > 20) packet_count = 20;
	if (timeout_ms   <= 0) timeout_ms   = 600;
	if (delay_sec    < 0)  delay_sec    = 0;

	send_times = (double *)Q_malloc(count * sizeof(double));
	recv_count = (int    *)Q_malloc(count * sizeof(int));
	if (!send_times || !recv_count) {
		Q_free(send_times);
		Q_free(recv_count);
		return;
	}
	memset(recv_count, 0, count * sizeof(int));

	/* Open sockets */
	for (i = 0; i < count; i++) {
		proxies[i].replied      = false;
		proxies[i].loss_pct     = 100.0f;
		proxies[i].ps.count     = 0;
		proxies[i].ps.dest_ping = -1;
		send_times[i]           = 0;
		proxies[i].sock         = UDP_OpenSocket(PORT_ANY);
	}

	/* Send with inter-packet delay */
	for (pkt = 0; pkt < packet_count; pkt++) {
		if (pkt > 0 && delay_sec > 0) {
			double next_send = Sys_DoubleTime() + delay_sec;
			while (Sys_DoubleTime() < next_send) /* spin */;
		}
		for (i = 0; i < count; i++) {
			struct sockaddr_storage addr_to;
			if (proxies[i].sock == INVALID_SOCKET) continue;
			NetadrToSockadr(&proxies[i].addr, &addr_to);
			if (pkt == 0) send_times[i] = Sys_DoubleTime();
			sendto(proxies[i].sock, packet, packet_len, 0,
			       (struct sockaddr *)&addr_to, sizeof(struct sockaddr));
		}
	}

	deadline = Sys_DoubleTime() + timeout_ms / 1000.0;

	while (Sys_DoubleTime() < deadline) {
		fd_set fd;
		int    maxsock = 0;
		qbool  any     = false;

		FD_ZERO(&fd);
		for (i = 0; i < count; i++) {
			if (recv_count[i] < packet_count && proxies[i].sock != INVALID_SOCKET) {
				FD_SET(proxies[i].sock, &fd);
				if ((int)proxies[i].sock > maxsock) maxsock = (int)proxies[i].sock;
				any = true;
			}
		}
		if (!any) break;

		tv.tv_sec = 0; tv.tv_usec = 20000;
		if (select(maxsock + 1, &fd, NULL, NULL, &tv) <= 0) continue;

		for (i = 0; i < count; i++) {
			if (recv_count[i] < packet_count
			    && proxies[i].sock != INVALID_SOCKET
			    && FD_ISSET(proxies[i].sock, &fd)) {
				byte buf[8 * 512];
				struct sockaddr_storage from;
				socklen_t from_len = sizeof(from);
				double    now      = Sys_DoubleTime();
				int ret = recvfrom(proxies[i].sock, (char *)buf, sizeof(buf), 0,
				                   (struct sockaddr *)&from, &from_len);
				if (ret > 5 && memcmp(buf, "\xff\xff\xff\xffn", 5) == 0) {
					recv_count[i]++;
					if (!proxies[i].replied) {
						CL_BR_ParsePingstatus(buf + 5, ret - 5, dest, &proxies[i].ps);
						proxies[i].replied = true;
						if (proxies[i].you_ms < 0 && send_times[i] > 0) {
							int ms = (int)((now - send_times[i]) * 1000.0);
							proxies[i].you_ms = (ms < 1) ? 1 : ms;
						}
					}
				}
			}
		}
	}

	/* Compute loss + debug */
	for (i = 0; i < count; i++) {
		if (proxies[i].replied && recv_count[i] > 0) {
			float loss = 100.0f * (1.0f - (float)recv_count[i] / (float)packet_count);
			proxies[i].loss_pct = (loss < 0) ? 0 : loss;
		}
		if ((int)cl_connectbr_verbose.value >= 2)
			BR_Debug("  %s → %d/%d replies (loss %.1f%%)\n",
			         proxies[i].ip_str, recv_count[i], packet_count, proxies[i].loss_pct);
	}

	Q_free(send_times);
	Q_free(recv_count);

	for (i = 0; i < count; i++) {
		if (proxies[i].sock != INVALID_SOCKET) {
			closesocket(proxies[i].sock);
			proxies[i].sock = INVALID_SOCKET;
		}
	}
}

// --------------------------------------------
// Score
// --------------------------------------------
static float CL_BR_Score(float ping_ms, float loss_pct)
{
	float o      = cl_connectbr_ping_orange.value > 0 ? cl_connectbr_ping_orange.value : 200.0f;
	float w_ping = cl_connectbr_weight_ping.value  > 0 ? cl_connectbr_weight_ping.value  : 1.0f;
	float w_loss = cl_connectbr_weight_loss.value  > 0 ? cl_connectbr_weight_loss.value  : 0.4f;
	float norm_ping = ping_ms / (o * 2.0f);
	if (norm_ping > 1.0f) norm_ping = 1.0f;
	float norm_loss = loss_pct / 100.0f;
	if (norm_loss > 1.0f) norm_loss = 1.0f;
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
// AddRoute / ApplyRoute
// --------------------------------------------
static void CL_BR_AddRoute(const char *proxylist, const char *label,
                            float ping_ms, float loss_pct, qbool via_proxy)
{
	int i;

	if (br_route_count >= CONNECTBR_MAX_ROUTES) return;
	if (strlen(proxylist) >= MAX_PROXYLIST) {
		BR_Debug("route '%s' skipped: proxylist too long\n", label);
		return;
	}

	for (i = 0; i < br_route_count; i++)
		if (strcmp(br_routes[i].proxylist, proxylist) == 0) return;

	strlcpy(br_routes[br_route_count].proxylist, proxylist, MAX_PROXYLIST);
	strlcpy(br_routes[br_route_count].label,     label,     sizeof(br_routes[0].label));
	br_routes[br_route_count].ping_ms   = ping_ms;
	br_routes[br_route_count].loss_pct  = loss_pct;
	br_routes[br_route_count].score     = CL_BR_Score(ping_ms, loss_pct);
	br_routes[br_route_count].via_proxy = via_proxy;
	br_routes[br_route_count].valid     = true;
	br_route_count++;
}

static void CL_BR_ApplyRoute(int idx)
{
	route_t *r = &br_routes[idx];

	Cvar_Set(&cl_proxyaddr, "");
	if (r->proxylist[0])
		Cvar_Set(&cl_proxyaddr, r->proxylist);

	Com_Printf("\n&cf80connectbr:&r route #%d - %s\n", idx + 1, r->label);
	Com_Printf("  ping: %s%.0fms&r  loss: %s%.1f%%&r\n",
	           CL_BR_PingColor(r->ping_ms), r->ping_ms,
	           CL_BR_LossColor(r->loss_pct), r->loss_pct);

	if (r->proxylist[0] && strchr(r->proxylist, '@'))
		Com_Printf("  chain: %s\n", r->proxylist);

	if (idx + 1 < br_route_count)
		Com_Printf("  type &cf80connectnext&r for route #%d (%s)\n",
		           idx + 2, br_routes[idx + 1].label);
	else
		Com_Printf("  no more routes available.\n");

	Cbuf_AddText(va("connect %s\n", NET_AdrToString(br_target_addr)));
}

// --------------------------------------------
// DIJKSTRA
// --------------------------------------------
static qbool CL_BR_Dijkstra(const proxy_t *proxies, int pcount,
                            const netadr_t *target, int direct_ping,
                            char *best_chain, size_t chain_bufsz,
                            int *best_ping_ms, float *best_loss_pct)
{
	int dist[DIJKSTRA_MAX_NODES];
	int prev[DIJKSTRA_MAX_NODES];
	float loss[DIJKSTRA_MAX_NODES];
	int i, j, iter;
	int total_nodes, target_idx;
	int cur;

	if (pcount <= 0) return false;

	total_nodes = pcount + 1;
	target_idx  = pcount;
	if (total_nodes > DIJKSTRA_MAX_NODES) total_nodes = DIJKSTRA_MAX_NODES;

	for (i = 0; i < total_nodes; i++) {
		dist[i] = DIJKSTRA_INF;
		prev[i] = -1;
		loss[i] = 0.0f;
	}

	/* you → proxies */
	for (i = 0; i < pcount; i++) {
		if (!proxies[i].replied) continue;
		int cost = (proxies[i].you_ms >= 0) ? proxies[i].you_ms : DIJKSTRA_INF;
		if (cost < dist[i]) {
			dist[i] = cost;
			prev[i] = -1;
			loss[i] = proxies[i].loss_pct;
		}
	}

	/* you → target direct */
	if (direct_ping > 0 && direct_ping < dist[target_idx]) {
		dist[target_idx] = direct_ping;
		prev[target_idx] = -1;
		loss[target_idx] = 0.0f;
	}

	/* Bellman-Ford */
	for (iter = 0; iter < total_nodes - 1; iter++) {
		qbool updated = false;
		for (i = 0; i < pcount; i++) {
			if (dist[i] == DIJKSTRA_INF || !proxies[i].replied) continue;

			/* proxy → target */
			if (proxies[i].ps.dest_ping >= 0) {
				int newd = dist[i] + proxies[i].ps.dest_ping;
				if (newd < dist[target_idx]) {
					dist[target_idx] = newd;
					prev[target_idx] = i;
					loss[target_idx] = proxies[i].loss_pct;
					updated = true;
				}
			}

			/* proxy → proxy */
			for (j = 0; j < proxies[i].ps.count; j++) {
				const ps_entry_t *e = &proxies[i].ps.entries[j];
				int to, newd;

				if (ntohs(e->addr.port) != 30000 || e->dist_ms < 0 || CL_BR_IsTarget(&e->addr)) continue;
				to = CL_BR_FindNodeIndex(proxies, pcount, &e->addr);
				if (to < 0 || !proxies[to].replied) continue;

				newd = dist[i] + e->dist_ms;
				if (newd < dist[to]) {
					dist[to] = newd;
					prev[to] = i;
					loss[to] = proxies[to].loss_pct;
					updated = true;
				}
			}
		}
		if (!updated) break;
	}

	*best_ping_ms  = dist[target_idx];
	*best_loss_pct = loss[target_idx];

	if (*best_ping_ms >= DIJKSTRA_INF || prev[target_idx] < 0) {
		best_chain[0] = '\0';
		return false;
	}

	/* Reconstruct chain */
	{
		int stack[DIJKSTRA_MAX_NODES];
		int depth = 0;
		cur = prev[target_idx];
		while (cur >= 0 && depth < DIJKSTRA_MAX_NODES) {
			stack[depth++] = cur;
			cur = prev[cur];
		}
		best_chain[0] = '\0';
		for (i = depth - 1; i >= 0; i--) {
			if (best_chain[0]) strlcat(best_chain, "@", chain_bufsz);
			strlcat(best_chain, proxies[stack[i]].ip_str, chain_bufsz);
		}
	}
	return true;
}

// --------------------------------------------
// MeasureProc (thread)
// --------------------------------------------
static int CL_BR_MeasureProc(void *ignored)
{
	int i, j;
	int timeout_ms = (int)cl_connectbr_timeout_ms.value;
	int verbose    = (int)cl_connectbr_verbose.value;
	int direct_ping;
	int p1_count_orig;
	proxy_t *proxies = NULL;
	int pcount = 0;

	if (timeout_ms <= 0) timeout_ms = 600;
	direct_ping = CL_BR_GetBrowserPing(&br_target_addr);

	/* Step 1: SB_PingTree (opcional) */
	if (SB_PingTree_Built() && !SB_PingTree_IsBuilding()) {
		int pathlen = SB_PingTree_GetPathLen(&br_target_addr);
		if (pathlen > 0) {
			int total_ping_ms = 0;
			char proxy_str[MAX_PROXYLIST];
			char target_str[64];
			proxy_str[0] = '\0';
			CL_BR_AdrToStr(&br_target_addr, target_str, sizeof(target_str));
			if (SB_PingTree_GetProxyString(&br_target_addr, proxy_str,
			                               sizeof(proxy_str), &total_ping_ms)
			    && proxy_str[0] && strcmp(proxy_str, target_str) != 0) {
				float ping = (total_ping_ms > 0) ? (float)total_ping_ms : 1.0f;
				char lbl[128];
				snprintf(lbl, sizeof(lbl), "ping tree (%d hop%s)",
				         pathlen, pathlen > 1 ? "s" : "");
				CL_BR_AddRoute(proxy_str, lbl, ping, 0.0f, true);
			}
		}
	}

	/* Step 2: coletar proxies */
	proxies = (proxy_t *)Q_malloc(CONNECTBR_MAX_PROXIES * sizeof(proxy_t));
	if (!proxies) {
		Com_Printf("connectbr: out of memory.\n");
		goto add_direct;
	}
	memset(proxies, 0, CONNECTBR_MAX_PROXIES * sizeof(proxy_t));

	SB_ServerList_Lock();
	for (i = 0; i < serversn && pcount < CONNECTBR_MAX_PROXIES; i++) {
		server_data *s = servers[i];
		qbool dup = false;
		int k;
		if (!s || ntohs(s->address.port) != 30000) continue;
		if (CL_BR_IsTarget(&s->address)) continue;
		for (k = 0; k < pcount && !dup; k++)
			if (CL_BR_AdrEqual(&proxies[k].addr, &s->address)) dup = true;
		if (dup) continue;

		proxies[pcount].addr   = s->address;
		proxies[pcount].you_ms = (s->ping >= 0) ? s->ping : -1;
		CL_BR_AdrToStr(&s->address, proxies[pcount].ip_str, sizeof(proxies[0].ip_str));
		strlcpy(proxies[pcount].name,
		        s->display.name[0] ? s->display.name : proxies[pcount].ip_str,
		        sizeof(proxies[0].name));
		pcount++;
	}
	SB_ServerList_Unlock();

	if (pcount == 0) {
		if (verbose >= 1) Com_Printf("  No proxies found in server browser.\n");
		goto add_direct;
	}

	if (verbose >= 1)
		Com_Printf("  Testing %d prox%s (batch 1)...\n", pcount, pcount == 1 ? "y" : "ies");

	CL_BR_BatchPingstatus(proxies, pcount, &br_target_addr, timeout_ms);
	p1_count_orig = pcount;

	/* Step 3: descobrir proxies extras */
	for (i = 0; i < p1_count_orig; i++) {
		if (!proxies[i].replied) continue;
		for (j = 0; j < proxies[i].ps.count && pcount < CONNECTBR_MAX_PROXIES; j++) {
			ps_entry_t *nb = &proxies[i].ps.entries[j];
			qbool dup = false;
			int k;

			if (ntohs(nb->addr.port) != 30000) continue;
			if (CL_BR_IsTarget(&nb->addr)) continue;
			if (nb->addr.ip[0] == 0 && nb->addr.ip[1] == 0 &&
			    nb->addr.ip[2] == 0 && nb->addr.ip[3] == 0) continue;

			for (k = 0; k < pcount && !dup; k++)
				if (CL_BR_AdrEqual(&proxies[k].addr, &nb->addr)) dup = true;
			if (dup) continue;

			proxies[pcount].addr   = nb->addr;
			proxies[pcount].you_ms = -1;
			CL_BR_AdrToStr(&nb->addr, proxies[pcount].ip_str, sizeof(proxies[0].ip_str));
			strlcpy(proxies[pcount].name, proxies[pcount].ip_str, sizeof(proxies[0].name));
			pcount++;
		}
	}

	if (pcount > p1_count_orig) {
		if (verbose >= 2)
			Com_Printf("  +%d extra proxies discovered -- batch 2...\n", pcount - p1_count_orig);
		CL_BR_BatchPingstatus(proxies + p1_count_orig, pcount - p1_count_orig,
		                      &br_target_addr, timeout_ms);
	}

	/* Step 4: Dijkstra */
	{
		char  best_chain[MAX_PROXYLIST] = "";
		int   best_ping = 0;
		float best_loss = 0.0f;
		int   hop_count = 0;
		char *p;

		if (CL_BR_Dijkstra(proxies, pcount, &br_target_addr, direct_ping,
		                   best_chain, sizeof(best_chain),
		                   &best_ping, &best_loss) && best_chain[0]) {
			char lbl[128];

			hop_count = 1;
			for (p = best_chain; *p; p++)
				if (*p == '@') hop_count++;

			snprintf(lbl, sizeof(lbl), "best chain (%d hop%s)",
			         hop_count, hop_count > 1 ? "s" : "");

			CL_BR_AddRoute(best_chain, lbl, (float)best_ping, best_loss, true);

			if (verbose >= 1)
				Com_Printf("  BEST: [%s] %s%dms&r loss=%s%.1f%%&r  %d hop%s\n",
				           best_chain,
				           CL_BR_PingColor((float)best_ping), best_ping,
				           CL_BR_LossColor(best_loss), best_loss,
				           hop_count, hop_count > 1 ? "s" : "");
		}
	}

	/* Step 5: 1-hop routes para ranking */
	for (i = 0; i < pcount; i++) {
		if (!proxies[i].replied || proxies[i].ps.dest_ping < 0 || proxies[i].you_ms < 0) continue;
		int total = proxies[i].you_ms + proxies[i].ps.dest_ping;
		if (total <= 0) continue;

		char lbl[128];
		snprintf(lbl, sizeof(lbl), "via %s [1 hop]", proxies[i].name);
		CL_BR_AddRoute(proxies[i].ip_str, lbl, (float)total, proxies[i].loss_pct, true);
	}

add_direct:
	if (direct_ping > 0) {
		if (verbose >= 1)
			Com_Printf("  [direct] %s%dms&r\n", CL_BR_PingColor((float)direct_ping), direct_ping);
		CL_BR_AddRoute("", "direct", (float)direct_ping, 0.0f, false);
	}

	Q_free(proxies);
	br_measuring = false;

	if (br_route_count == 0) {
		Com_Printf("connectbr: no routes found.\n");
		return 0;
	}

	qsort(br_routes, br_route_count, sizeof(route_t), CL_BR_RouteCompare);
	if (br_route_count > 10) br_route_count = 10;

	/* Ranking buffer */
	{
		int  show = (br_route_count < 6) ? br_route_count : 6;
		char tmp[256];
		br_ranking_buf[0] = '\0';
		snprintf(tmp, sizeof(tmp), "\n&cf80connectbr: top %d routes&r\n", show);
		strlcat(br_ranking_buf, tmp, sizeof(br_ranking_buf));
		for (i = 0; i < show; i++) {
			snprintf(tmp, sizeof(tmp), "  &cf80#%d&r  %s%.0fms&r  %s%.1f%%&r  %s\n",
			         i + 1,
			         CL_BR_PingColor(br_routes[i].ping_ms), br_routes[i].ping_ms,
			         CL_BR_LossColor(br_routes[i].loss_pct), br_routes[i].loss_pct,
			         br_routes[i].label);
			strlcat(br_ranking_buf, tmp, sizeof(br_ranking_buf));
		}
	}

	br_current_route = 0;
	br_active        = true;
	br_done          = true;
	return 0;
}

// --------------------------------------------
// Public commands
// --------------------------------------------
void CL_Connect_BestRoute_f(void)
{
	const char *addr;

	if (br_measuring) {
		Com_Printf("connectbr: measurement already in progress.\n");
		return;
	}

	if (Cmd_Argc() != 2) {
		Com_Printf("Usage: connectbr <address>\n");
		Com_Printf("  Tests routes (Dijkstra multi-hop) and connects via the best one.\n");
		Com_Printf("  Use connectnext to try the next route.\n");
		return;
	}

	addr = Cmd_Argv(1);
	if (!addr || !*addr)                    { Com_Printf("connectbr: empty address\n");    return; }
	if (strlen(addr) > MAX_ADDRESS_LENGTH)  { Com_Printf("connectbr: address too long\n"); return; }

	if (!NET_StringToAdr(addr, &br_target_addr)) {
		Com_Printf("connectbr: invalid address '%s'\n", addr);
		return;
	}
	if (br_target_addr.port == 0)
		br_target_addr.port = htons(27500);

	if (SB_PingTree_IsBuilding()) {
		Com_Printf("connectbr: ping tree still building -- retry later.\n");
		return;
	}

	br_measuring     = true;
	br_route_count   = 0;
	br_current_route = 0;
	br_active        = false;
	br_done          = false;
	br_ranking_buf[0] = '\0';
	Cvar_Set(&cl_proxyaddr, "");

	if ((int)cl_connectbr_verbose.value >= 1)
		Com_Printf("\n&cf80connectbr:&r testing routes to %s\n", addr);

	if (Sys_CreateDetachedThread(CL_BR_MeasureProc, NULL) < 0) {
		Com_Printf("connectbr: failed to create measurement thread.\n");
		br_measuring = false;
	}
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

void CL_ConnectBR_Frame(void)
{
	if (!br_done) return;
	br_done = false;

	if (br_route_count == 0) return;

	if (br_ranking_buf[0])
		Com_Printf("%s", br_ranking_buf);

	CL_BR_ApplyRoute(0);
}

void CL_ConnectBR_Init(void)
{
	Cvar_SetCurrentGroup(CVAR_GROUP_NETWORK);
	Cvar_Register(&cl_connectbr_timeout_ms);
	Cvar_Register(&cl_connectbr_ping_green);
	Cvar_Register(&cl_connectbr_ping_yellow);
	Cvar_Register(&cl_connectbr_ping_orange);
	Cvar_Register(&cl_connectbr_weight_ping);
	Cvar_Register(&cl_connectbr_weight_loss);
	Cvar_Register(&cl_connectbr_test_packets);
	Cvar_Register(&cl_connectbr_packet_delay);
	Cvar_Register(&cl_connectbr_verbose);
	Cvar_Register(&cl_connectbr_debug);
	Cvar_ResetCurrentGroup();
}
