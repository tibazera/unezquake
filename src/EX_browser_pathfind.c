/// Returns the proxy chain string for the best path to addr.
/// Does NOT modify cl_proxyaddr, does NOT issue any connect command.
///
/// out receives the proxylist string, e.g. "1.2.3.4:30000" or
/// "1.2.3.4:30000@5.6.7.8:30000" for multi-hop routes.
///
/// out_total_ping_ms receives the Dijkstra total ping estimate.
///
/// Returns true  if a proxy route was found and written to out.
/// Returns false if direct connection is best, or no route exists
/// (in both cases out is set to empty string).
qbool SB_PingTree_GetProxyString(const netadr_t *addr, char *out, size_t outsz,
                                  int *out_total_ping_ms)
{
	nodeid_t target = SB_PingTree_FindIp(SB_Netaddr2Ipaddr(addr));

	out[0] = '\0';
	*out_total_ping_ms = 0;

	if (target == INVALID_NODE || ping_nodes[target].prev == INVALID_NODE) {
		// No route found
		return false;
	}

	*out_total_ping_ms = (int)ping_nodes[target].dist;

	if (ping_nodes[target].prev == startnode_id) {
		// Direct connection is best — no proxy needed
		return false;
	}

	{
		char proxylist_buf[32 * MAX_NONLEAVES];
		nodeid_t current = ping_nodes[target].prev;

		proxylist_buf[0] = '\0';

		while (current != startnode_id && current != INVALID_NODE) {
			byte *ip = ping_nodes[current].ipaddr.data;
			char newval[2048];

			snprintf(&newval[0], sizeof(newval), "%d.%d.%d.%d:%d%s%s",
			         (int)ip[0], (int)ip[1], (int)ip[2], (int)ip[3],
			         (int)ntohs(ping_nodes[current].proxport),
			         *proxylist_buf ? "@" : "",
			         proxylist_buf);
			strlcpy(proxylist_buf, newval, sizeof(proxylist_buf));

			current = ping_nodes[current].prev;
		}

		strlcpy(out, proxylist_buf, outsz);
	}

	return (out[0] != '\0');
}
