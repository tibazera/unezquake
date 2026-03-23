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

// ─────────────────────────────────────────────
// CVars
// ─────────────────────────────────────────────
cvar_t cl_connectbr_test_packets  = {"cl_connectbr_test_packets",  "25",   CVAR_ARCHIVE};
cvar_t cl_connectbr_timeout_ms    = {"cl_connectbr_timeout_ms",    "600",  CVAR_ARCHIVE};
cvar_t cl_connectbr_packet_delay  = {"cl_connectbr_packet_delay",  "15",   CVAR_ARCHIVE};
cvar_t cl_connectbr_ping_green    = {"cl_connectbr_ping_green",    "40",   CVAR_ARCHIVE};  // <= 40ms green
cvar_t cl_connectbr_ping_yellow   = {"cl_connectbr_ping_yellow",   "80",   CVAR_ARCHIVE};  // <= 80ms yellow
cvar_t cl_connectbr_ping_orange   = {"cl_connectbr_ping_orange",   "200",  CVAR_ARCHIVE};  // <= 200ms orange, >200ms red (unplayable)
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

// Proxy measurement cache
#define PROXY_CACHE_SIZE        16
#define PROXY_CACHE_TTL_SEC     5.0

// Debug macro
#define BR_Debug(...) \
	do { if (cl_connectbr_debug.value) Com_Printf("[connectbr] " __VA_ARGS__); } while(0)

// ─────────────────────────────────────────────
// Mini ping graph -- Dijkstra for multi-hop routes
// ─────────────────────────────────────────────
#define BR_GRAPH_MAX_NODES   64   // you + proxies + destination
#define BR_GRAPH_MAX_EDGES   512
#define BR_DIST_INF          32767

// Node 0 is always "you" (the client).
// Nodes 1..N are proxies.
// The destination server is looked up by IP after Dijkstra.

typedef struct {
	byte     ip[4];
	unsigned short port;       // network byte order; 0 = not a proxy
	int      dist;             // Dijkstra distance from node 0 (you)
	int      prev;             // previous node on shortest path
	qbool    visited;
} br_node_t;

typedef struct {
	int  from;
	int  to;
	int  dist;
} br_edge_t;

static br_node_t  br_graph_nodes[BR_GRAPH_MAX_NODES];
static int        br_graph_node_count = 0;
static br_edge_t  br_graph_edges[BR_GRAPH_MAX_EDGES];
static int        br_graph_edge_count = 0;

static void CL_BR_Graph_Clear(void)
{
	br_graph_node_count = 0;
	br_graph_edge_count = 0;
}

// Returns existing node index or adds a new one. Port in network byte order.
static int CL_BR_Graph_AddNode(const byte ip[4], unsigned short port)
{
	int i;
	for (i = 0; i < br_graph_node_count; i++) {
		if (memcmp(br_graph_nodes[i].ip, ip, 4) == 0)
			return i;
	}
	if (br_graph_node_count >= BR_GRAPH_MAX_NODES)
		return -1;
	memcpy(br_graph_nodes[br_graph_node_count].ip, ip, 4);
	br_graph_nodes[br_graph_node_count].port    = port;
	br_graph_nodes[br_graph_node_count].dist    = BR_DIST_INF;
	br_graph_nodes[br_graph_node_count].prev    = -1;
	br_graph_nodes[br_graph_node_count].visited = false;
	return br_graph_node_count++;
}

static void CL_BR_Graph_AddEdge(int from, int to, int dist)
{
	if (from < 0 || to < 0) return;
	if (br_graph_edge_count >= BR_GRAPH_MAX_EDGES) return;
	if (dist <= 0) return;
	br_graph_edges[br_graph_edge_count].from = from;
	br_graph_edges[br_graph_edge_count].to   = to;
	br_graph_edges[br_graph_edge_count].dist = dist;
	br_graph_edge_count++;
}

// Simple O(N^2) Dijkstra -- node count is small (< 64)
static void CL_BR_Graph_Dijkstra(int start)
{
	int i;
	br_graph_nodes[start].dist = 0;
	for (;;) {
		int cur = -1, best = BR_DIST_INF;
		for (i = 0; i < br_graph_node_count; i++) {
			if (!br_graph_nodes[i].visited && br_graph_nodes[i].dist < best) {
				best = br_graph_nodes[i].dist;
				cur  = i;
			}
		}
		if (cur < 0) break;
		br_graph_nodes[cur].visited = true;
		for (i = 0; i < br_graph_edge_count; i++) {
			int alt, nb;
			if (br_graph_edges[i].from != cur) continue;
			nb  = br_graph_edges[i].to;
			alt = br_graph_nodes[cur].dist + br_graph_edges[i].dist;
			if (alt < br_graph_nodes[nb].dist) {
				br_graph_nodes[nb].dist = alt;
				br_graph_nodes[nb].prev = cur;
			}
		}
	}
}

// Build proxylist string "ip:port" or "ip1:port1@ip2:port2" from Dijkstra path
// walking backwards from node_id to start (node 0).
// Returns the total Dijkstra ping.
static int CL_BR_Graph_BuildProxyString(int node_id, char *out, size_t outsz)
{
	char buf[BR_GRAPH_MAX_NODES][32];
	int  hops = 0, n = br_graph_nodes[node_id].prev;

	out[0] = '\0';
	// collect proxies on path (skip node 0 = you, skip destination node)
	while (n > 0 && hops < BR_GRAPH_MAX_NODES) {
		snprintf(buf[hops], sizeof(buf[0]), "%d.%d.%d.%d:%d",
		         br_graph_nodes[n].ip[0], br_graph_nodes[n].ip[1],
		         br_graph_nodes[n].ip[2], br_graph_nodes[n].ip[3],
		         (int)ntohs(br_graph_nodes[n].port));
		hops++;
		n = br_graph_nodes[n].prev;
	}
	// proxies were collected destination->you, reverse to you->destination
	if (hops > 0) {
		int h;
		char tmp[MAX_PROXYLIST];
		tmp[0] = '\0';
		for (h = hops - 1; h >= 0; h--) {
			if (tmp[0]) strlcat(tmp, "@", sizeof(tmp));
			strlcat(tmp, buf[h], sizeof(tmp));
		}
		strlcpy(out, tmp, outsz);
	}
	return br_graph_nodes[node_id].dist;
}


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
	int y = (int)cl_connectbr_ping_yellow.value;
	int o = (int)cl_connectbr_ping_orange.value;
	// Safety fallbacks in case cvars are not yet initialised (value == 0)
	if (g <= 0) g = 40;
	if (y <= 0) y = 80;
	if (o <= 0) o = 200;
	if (ms <= g) return "&c0f0";   // green   <= 40ms
	if (ms <= y) return "&cff0";   // yellow  <= 80ms
	if (ms <= o) return "&cfa0";   // orange  <= 200ms
	return "&cf00";                // red     >200ms -- unplayable
}

static const char *CL_BR_LossColor(float pct)
{
	if (pct <= 0) return "&c0f0";  // green  -- 0% loss
	if (pct <= 5) return "&cff0";  // yellow -- up to 5%
	return "&cf00";                // red    -- >5% unacceptable
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

	{
		int pkt_delay = (int)cl_connectbr_packet_delay.value;
		if (pkt_delay < 5) pkt_delay = 5;  // minimum 5ms between probes
		for (i = 0; i < test_packets; i++) {
			send_times[i] = Sys_DoubleTime();
			sendto(sock, packet, strlen(packet), 0,
			       (struct sockaddr *)&to_addr, sizeof(struct sockaddr));
			Sys_MSleep(pkt_delay);
		}
	}

	{
		int timeout_ms = (int)cl_connectbr_timeout_ms.value;
		if (timeout_ms <= 0) timeout_ms = 600;  // fallback 600ms
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
// Score -- lower is better.
// Single absolute scale so direct 11ms always beats proxy 193ms.
// The old dual-scale (proxy ref 160ms vs direct ref 80ms) was the
// root cause of wrong route selection.
// Uses hardcoded fallbacks in case cvars are not yet initialised (value==0).
// --------------------------------------------
static float CL_BR_Score(float ping_ms, float loss_pct, qbool via_proxy)
{
	float o        = cl_connectbr_ping_orange.value  > 0 ? cl_connectbr_ping_orange.value  : 200.0f;
	float w_ping   = cl_connectbr_weight_ping.value  > 0 ? cl_connectbr_weight_ping.value  : 0.6f;
	float w_loss   = cl_connectbr_weight_loss.value  > 0 ? cl_connectbr_weight_loss.value  : 0.4f;
	float ping_ref = o * 2.0f;  // 260ms as full scale
	float norm_ping = ping_ms  / ping_ref;
	float norm_loss = loss_pct / 100.0f;
	(void)via_proxy;  // no bonus/penalty by route type -- pure ping wins
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
// Query a proxy for its full pingstatus list.
// For each entry calls the callback with (ip, port_net, ping_ms).
// ─────────────────────────────────────────────
typedef void (*br_pingstatus_cb)(const byte ip[4], unsigned short port_net,
                                  int ping_ms, void *userdata);

static void CL_BR_QueryPingStatus(const netadr_t *proxy_addr,
                                   br_pingstatus_cb cb, void *userdata)
{
	char packet[]    = "\xff\xff\xff\xffpingstatus";
	byte buf[8 * 512];
	struct sockaddr_storage addr_to, addr_from;
	socklen_t from_len;
	struct timeval tv;
	fd_set fd;
	socket_t sock;
	int ret, timeout_ms;

	sock = UDP_OpenSocket(PORT_ANY);
	if (sock == INVALID_SOCKET) return;

	NetadrToSockadr(proxy_addr, &addr_to);
	ret = sendto(sock, packet, strlen(packet), 0,
	             (struct sockaddr *)&addr_to, sizeof(struct sockaddr));
	if (ret < 0) { closesocket(sock); return; }

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
				unsigned short port_net, ping_raw;
				memcpy(&port_net, p + 4, 2);
				memcpy(&ping_raw, p + 6, 2);
				if ((short)LittleShort(ping_raw) >= 0)
					cb(p, port_net, (int)(short)LittleShort(ping_raw), userdata);
				p += 8;
			}
		}
	}
	closesocket(sock);
}

// callback: adds proxy->neighbour edge into the graph
typedef struct { int proxy_node; } br_edge_cb_data_t;

static void CL_BR_EdgeCallback(const byte ip[4], unsigned short port_net,
                                int ping_ms, void *userdata)
{
	br_edge_cb_data_t *d = (br_edge_cb_data_t *)userdata;
	static const byte zero[4] = {0,0,0,0};
	int nb;
	if (memcmp(ip, zero, 4) == 0) return;
	nb = CL_BR_Graph_AddNode(ip, port_net);
	CL_BR_Graph_AddEdge(d->proxy_node, nb, ping_ms);
}

// ─────────────────────────────────────────────
// Build multi-hop graph, run Dijkstra, extract all routes.
// ─────────────────────────────────────────────
static void CL_BR_BuildGraphRoutes(void)
{
	int i, j;
	static const byte zero_ip[4] = {0,0,0,0};
	int start, dest_node;

	CL_BR_Graph_Clear();

	// Node 0 = you
	start = CL_BR_Graph_AddNode(zero_ip, 0);
	br_graph_nodes[start].dist = 0;

	// Collect proxies from browser
	{
		int proxy_count = 0;
		netadr_t proxy_addrs[CONNECTBR_MAX_PROXIES];
		char     proxy_labels[CONNECTBR_MAX_PROXIES][64];

		SB_ServerList_Lock();
		for (i = 0; i < serversn && proxy_count < CONNECTBR_MAX_PROXIES; i++) {
			server_data *s = servers[i];
			qbool dup = false;
			if (!s || !s->qwfwd || s->ping < 0) continue;
			if (memcmp(s->address.ip, br_target_addr.ip, 4) == 0) continue;
			for (j = 0; j < proxy_count && !dup; j++)
				if (memcmp(proxy_addrs[j].ip, s->address.ip, 4) == 0 &&
				    proxy_addrs[j].port == s->address.port) dup = true;
			if (dup) continue;
			proxy_addrs[proxy_count] = s->address;
			snprintf(proxy_labels[proxy_count], sizeof(proxy_labels[0]),
			         "%s", s->display.name[0] ? s->display.name : "proxy");
			proxy_count++;
		}
		SB_ServerList_Unlock();

		// Hardcoded fallback if browser empty
		if (proxy_count == 0) {
			int k;
			for (k = 0; br_known_proxies[k] && proxy_count < CONNECTBR_MAX_PROXIES; k++) {
				netadr_t a;
				qbool dup = false;
				if (!NET_StringToAdr(br_known_proxies[k], &a)) continue;
				if (memcmp(a.ip, br_target_addr.ip, 4) == 0) continue;
				for (j = 0; j < proxy_count && !dup; j++)
					if (memcmp(proxy_addrs[j].ip, a.ip, 4) == 0) dup = true;
				if (dup) continue;
				proxy_addrs[proxy_count] = a;
				strlcpy(proxy_labels[proxy_count], br_known_proxies[k],
				        sizeof(proxy_labels[0]));
				proxy_count++;
			}
		}

		// Add proxy nodes + you->proxy edges
		for (i = 0; i < proxy_count; i++) {
			int node_id, ping_you_proxy = -1;
			float fping, floss;

			ping_you_proxy = CL_BR_GetBrowserPing(&proxy_addrs[i]);
			if (ping_you_proxy < 0 && CL_BR_MeasureHop(&proxy_addrs[i], &fping, &floss))
				ping_you_proxy = (int)fping;
			if (ping_you_proxy <= 0) {
				Com_Printf("  [%s]... &cf00unreachable&r\n", proxy_labels[i]);
				continue;
			}

			node_id = CL_BR_Graph_AddNode(proxy_addrs[i].ip, proxy_addrs[i].port);
			CL_BR_Graph_AddEdge(start, node_id, ping_you_proxy);

			Com_Printf("  [%s]... ping=%s%dms&r\n",
			           proxy_labels[i],
			           CL_BR_PingColor((float)ping_you_proxy), ping_you_proxy);
		}
	}

	// Add destination node + direct edge
	dest_node = CL_BR_Graph_AddNode(br_target_addr.ip, br_target_addr.port);
	{
		int dp = CL_BR_GetBrowserPing(&br_target_addr);
		if (dp < 0) {
			float fping, floss;
			if (CL_BR_MeasureHop(&br_target_addr, &fping, &floss))
				dp = (int)fping;
		}
		if (dp > 0) {
			CL_BR_Graph_AddEdge(start, dest_node, dp);
			Com_Printf("  [direct]... ping=%s%dms&r\n",
			           CL_BR_PingColor((float)dp), dp);
		} else {
			Com_Printf("  [direct]... &cf00unreachable&r\n");
		}
	}

	// Query each proxy for pingstatus -- builds proxy->* edges (multi-hop)
	for (i = 1; i < br_graph_node_count; i++) {
		br_edge_cb_data_t d;
		netadr_t padr;
		if (br_graph_nodes[i].port == 0) continue;
		if (i == dest_node) continue;
		d.proxy_node = i;
		padr.type = NA_IP;
		memcpy(padr.ip, br_graph_nodes[i].ip, 4);
		padr.port = br_graph_nodes[i].port;
		CL_BR_QueryPingStatus(&padr, CL_BR_EdgeCallback, &d);
	}

	// Run Dijkstra
	CL_BR_Graph_Dijkstra(start);
}

static void CL_BR_ExtractGraphRoutes(void)
{
	int dest_node = -1, i, j;
	char proxystr[MAX_PROXYLIST];
	int  total_ping;

	for (i = 0; i < br_graph_node_count; i++) {
		if (memcmp(br_graph_nodes[i].ip, br_target_addr.ip, 4) == 0) {
			dest_node = i; break;
		}
	}
	if (dest_node < 0 || br_graph_nodes[dest_node].dist >= BR_DIST_INF) return;

	// Best route from Dijkstra
	if (br_route_count < CONNECTBR_MAX_ROUTES) {
		int hops = 0;
		const char *p;
		total_ping = CL_BR_Graph_BuildProxyString(dest_node, proxystr, sizeof(proxystr));
		if (proxystr[0]) {
			hops = 1;
			p = proxystr;
			while ((p = strchr(p, '@')) != NULL) { hops++; p++; }
			snprintf(br_routes[br_route_count].label, sizeof(br_routes[0].label),
			         "best route (%d hop%s)", hops, hops > 1 ? "s" : "");
		} else {
			strlcpy(br_routes[br_route_count].label, "direct connection",
			        sizeof(br_routes[0].label));
		}
		strlcpy(br_routes[br_route_count].proxylist, proxystr, sizeof(br_routes[0].proxylist));
		br_routes[br_route_count].ping_ms   = (float)total_ping;
		br_routes[br_route_count].loss_pct  = 0;
		br_routes[br_route_count].score     = CL_BR_Score((float)total_ping, 0, proxystr[0] != '\0');
		br_routes[br_route_count].via_proxy = (proxystr[0] != '\0');
		br_routes[br_route_count].valid     = true;
		br_route_count++;
	}

	// Add each single-hop proxy as alternative for connectnext
	for (i = 1; i < br_graph_node_count && br_route_count < CONNECTBR_MAX_ROUTES - 1; i++) {
		char single[64];
		int  single_total = -1, proxy_to_dest = -1;
		qbool already = false;

		if (br_graph_nodes[i].port == 0) continue;
		if (i == dest_node) continue;
		if (br_graph_nodes[i].dist >= BR_DIST_INF) continue;

		// Need you->proxy edge
		for (j = 0; j < br_graph_edge_count; j++)
			if (br_graph_edges[j].from == 0 && br_graph_edges[j].to == i) {
				single_total = br_graph_edges[j].dist; break;
			}
		if (single_total < 0) continue;

		// Need proxy->dest edge
		for (j = 0; j < br_graph_edge_count; j++)
			if (br_graph_edges[j].from == i && br_graph_edges[j].to == dest_node) {
				proxy_to_dest = br_graph_edges[j].dist; break;
			}
		if (proxy_to_dest < 0) continue;
		single_total += proxy_to_dest;

		snprintf(single, sizeof(single), "%d.%d.%d.%d:%d",
		         br_graph_nodes[i].ip[0], br_graph_nodes[i].ip[1],
		         br_graph_nodes[i].ip[2], br_graph_nodes[i].ip[3],
		         (int)ntohs(br_graph_nodes[i].port));

		for (j = 0; j < br_route_count; j++)
			if (strcmp(br_routes[j].proxylist, single) == 0) { already = true; break; }
		if (already) continue;

		snprintf(br_routes[br_route_count].label, sizeof(br_routes[0].label),
		         "via proxy %s", single);
		strlcpy(br_routes[br_route_count].proxylist, single, sizeof(br_routes[0].proxylist));
		br_routes[br_route_count].ping_ms   = (float)single_total;
		br_routes[br_route_count].loss_pct  = 0;
		br_routes[br_route_count].score     = CL_BR_Score((float)single_total, 0, true);
		br_routes[br_route_count].via_proxy = true;
		br_routes[br_route_count].valid     = true;
		br_route_count++;
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

// ─────────────────────────────────────────────
// Known QW proxy fallback list (used when server browser is empty)
// ─────────────────────────────────────────────
static const char *br_known_proxies[] = {
	"177.93.132.220:30000",   // ! Pent @ Ilha QWFWD
	"103.63.29.40:30000",     // ! Qlash Lisbon | Antilag QWFWD
	"arenacamper.ddns.net:30000",
	"berlin.qwsv.net:30000",
	NULL
};

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

	// If ping tree is still building, wait briefly rather than failing
	if (SB_PingTree_IsBuilding()) {
		Com_Printf("connectbr: ping tree still building -- please wait and retry.\n");
		return;
	}

	br_measuring     = true;
	Cvar_Set(&cl_proxyaddr, "");
	br_route_count   = 0;
	br_current_route = 0;
	br_active        = false;

	// Clear proxy cache so stale data from a previous connectbr call is not reused
	proxy_cache_count = 0;

	if ((int)cl_connectbr_verbose.value >= 1) {
		Com_Printf("\n&cf80connectbr:&r testing routes to %s...\n", addr);
		if ((int)cl_connectbr_verbose.value >= 2) {
			int pkts  = (int)cl_connectbr_test_packets.value > 0 ? (int)cl_connectbr_test_packets.value : 25;
			int toms  = (int)cl_connectbr_timeout_ms.value   > 0 ? (int)cl_connectbr_timeout_ms.value   : 600;
			int delay = (int)cl_connectbr_packet_delay.value > 0 ? (int)cl_connectbr_packet_delay.value : 15;
			Com_Printf("  packets=%d  timeout=%dms  delay=%dms\n", pkts, toms, delay);
			Com_Printf("  score weights: ping=%.2f loss=%.2f\n",
			           cl_connectbr_weight_ping.value  > 0 ? cl_connectbr_weight_ping.value  : 0.6f,
			           cl_connectbr_weight_loss.value  > 0 ? cl_connectbr_weight_loss.value  : 0.4f);
		}
		Com_Printf("\n");
	}

	// ── Build multi-hop graph + Dijkstra ─────────────────────────────
	// This queries every known proxy with "pingstatus" to discover
	// proxy->proxy and proxy->server pings, then runs Dijkstra to find
	// the true best route including multi-hop chains.
	// If the ping tree is already built, its result is added first as
	// an authoritative cross-check.
	Com_Printf("  Building route graph...\n");
	CL_BR_BuildGraphRoutes();
	CL_BR_ExtractGraphRoutes();

	// If ping tree is available, add its best route too (deduped)
	if (SB_PingTree_Built()) {
		int pathlen = SB_PingTree_GetPathLen(&br_target_addr);
		if (pathlen > 0 && br_route_count < CONNECTBR_MAX_ROUTES) {
			int  total_ping_ms = 0;
			char proxy_str[MAX_PROXYLIST];
			if (SB_PingTree_GetProxyString(&br_target_addr, proxy_str,
			                               sizeof(proxy_str), &total_ping_ms)
			    && total_ping_ms > 0) {
				qbool dup = false;
				int r;
				for (r = 0; r < br_route_count; r++)
					if (strcmp(br_routes[r].proxylist, proxy_str) == 0) { dup = true; break; }
				if (!dup) {
					float ping = (float)total_ping_ms;
					snprintf(br_routes[br_route_count].label,
					         sizeof(br_routes[0].label),
					         "ping tree best (%d hop%s)",
					         pathlen, pathlen > 1 ? "s" : "");
					strlcpy(br_routes[br_route_count].proxylist, proxy_str,
					        sizeof(br_routes[0].proxylist));
					br_routes[br_route_count].ping_ms   = ping;
					br_routes[br_route_count].loss_pct  = 0;
					br_routes[br_route_count].score     = CL_BR_Score(ping, 0, true);
					br_routes[br_route_count].via_proxy = true;
					br_routes[br_route_count].valid     = true;
					br_route_count++;
				}
			}
		}
	}

	br_measuring = false;

	if (br_route_count == 0) {
		Com_Printf("\nconnectbr: all routes failed.\n");
		return;
	}

	// Sort by score (absolute ping, lowest first)
	qsort(br_routes, br_route_count, sizeof(route_t), CL_BR_RouteCompare);

	// Filter out routes with ping > orange threshold (unplayable)
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

	// Show ranking: usable routes only, lowest ping first
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
	Cvar_Register(&cl_connectbr_ping_yellow);
	Cvar_Register(&cl_connectbr_ping_orange);
	Cvar_Register(&cl_connectbr_weight_ping);
	Cvar_Register(&cl_connectbr_weight_loss);
	Cvar_Register(&cl_connectbr_verbose);
	Cvar_Register(&cl_connectbr_debug);
	Cvar_ResetCurrentGroup();
}
