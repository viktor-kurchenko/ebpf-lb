// go:build ignore

#include "xdp_lb_kern.h"

#define BE_MAX_ENTRIES 8
#define CLIENT_MAX_ENTRIES 64512 // < 1023 and <= 65535 (65535 - 1023 = 64512)

struct
{
	__uint(type, BPF_MAP_TYPE_STACK);
	__uint(max_entries, CLIENT_MAX_ENTRIES);
	__type(value, __be16);
} ports SEC(".maps");

struct lb_cfg
{
	__u32 ip;
	__be16 port;
	unsigned char mac[ETH_ALEN];
	__be16 be_count;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __be16); // always = 0
	__type(value, struct lb_cfg);
} lb_cfg_map SEC(".maps");

struct client_tupple
{
	__be32 ip;
	__be16 port;
	unsigned char mac[ETH_ALEN];
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLIENT_MAX_ENTRIES);
	__type(key, struct client_tupple); // unique client tuple
	__type(value, __be16);			   // unique port
} client_tupple_port_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLIENT_MAX_ENTRIES);
	__type(key, __be16);				 // unique port
	__type(value, struct client_tupple); // unique client tuple
} port_client_tupple_map SEC(".maps");

struct server_cfg
{
	__be32 ip;
	__be16 port;
	unsigned char mac[ETH_ALEN];
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BE_MAX_ENTRIES);
	__type(key, __be16); // index: 0, 1, 2, ...
	__type(value, struct server_cfg);
} be_cfg_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLIENT_MAX_ENTRIES);
	__type(key, __be16);			  // unique port
	__type(value, struct server_cfg); // backend config
} port_be_cfg_map SEC(".maps");

struct conn_track
{
	long ts;		  // latest connection activity timestamp
	__u16 client_fin; // client TCP FIN indicator
	__u16 be_fin;	  // backend TCP FIN indicator
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLIENT_MAX_ENTRIES);
	__type(key, __be16);			  // unique port
	__type(value, struct conn_track); // connection track stats
} port_conn_track_map SEC(".maps");

volatile const __u16 lb_cfg_key;
volatile const __u16 port;

static __always_inline void
push_back_port(__be16 port)
{
	if (bpf_map_push_elem(&ports, &port, BPF_ANY) != 0)
	{
		bpf_printk("FATAL: failed to push back new port!");
	}
}

static __always_inline void
cleanup_port_mappings(__be16 port)
{
	struct client_tupple *ct = bpf_map_lookup_elem(&port_client_tupple_map, &port);
	if (ct != NULL)
	{
		if (bpf_map_delete_elem(&client_tupple_port_map, ct) != 0)
		{
			bpf_printk("FATAL: failed to cleanup client tupple -> port mapping!");
		}
	}
	if (bpf_map_delete_elem(&port_client_tupple_map, &port) != 0)
	{
		bpf_printk("FATAL: failed to cleanup port -> client tupple mapping!");
	}
	if (bpf_map_delete_elem(&port_be_cfg_map, &port) != 0)
	{
		bpf_printk("FATAL: failed to cleanup port -> be config mapping!");
	}
	if (bpf_map_delete_elem(&port_conn_track_map, &port) != 0)
	{
		bpf_printk("FATAL: failed to cleanup port -> conn track mapping!");
	}
}

static __always_inline int
process_new_client(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, struct lb_cfg *lb_cfg, struct client_tupple ct)
{
	__be16 cport;
	if (bpf_map_pop_elem(&ports, &cport) != 0)
	{
		bpf_printk("FATAL: failed to lookup port for new client!");
		return -1;
	}
	bpf_printk("selected port: %d", cport);
	if (bpf_map_update_elem(&client_tupple_port_map, &ct, &cport, BPF_NOEXIST) != 0)
	{
		bpf_printk("FATAL: failed to save client tupple -> new port mapping!");
		push_back_port(cport);
		return -1;
	}
	if (bpf_map_update_elem(&port_client_tupple_map, &cport, &ct, BPF_NOEXIST) != 0)
	{
		bpf_printk("FATAL: failed to save new port -> client tupple mapping!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
		return -1;
	}
	// Lookup backend for a new client
	__be16 be_idx = bpf_ktime_get_ns() % lb_cfg->be_count;
	struct server_cfg *be_cfg = bpf_map_lookup_elem(&be_cfg_map, &be_idx);
	if (be_cfg == NULL)
	{
		bpf_printk("FATAL: backend config not found [index: %d]!", be_idx);
		cleanup_port_mappings(cport);
		push_back_port(cport);
		return -1;
	}
	bpf_printk("selected Be: %d", be_idx);
	if (bpf_map_update_elem(&port_be_cfg_map, &cport, be_cfg, BPF_NOEXIST) != 0)
	{
		bpf_printk("FATAL: failed to save new port -> backend config mapping!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
		return -1;
	}
	struct conn_track conn = {};
	conn.ts = bpf_ktime_get_ns();
	conn.client_fin = tcp->fin;
	if (bpf_map_update_elem(&port_conn_track_map, &cport, &conn, BPF_NOEXIST) != 0)
	{
		bpf_printk("FATAL: failed to save new port -> connection tracking mapping!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
		return -1;
	}
	// Update source/destination Port, IP and MAC
	tcp->source = bpf_ntohs(cport);
	tcp->dest = bpf_ntohs(be_cfg->port);
	ip->daddr = be_cfg->ip;
	copy_mac(be_cfg->mac, eth->h_dest);
	return 0;
}

static __always_inline int
process_existing_client(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, struct lb_cfg *lb_cfg, __be16 cport)
{
	struct server_cfg *be_cfg = bpf_map_lookup_elem(&port_be_cfg_map, &cport);
	if (be_cfg == NULL)
	{
		bpf_printk("FATAL: failed to lookup backend config for existing client!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
		return -1;
	}
	struct conn_track *conn = bpf_map_lookup_elem(&port_conn_track_map, &cport);
	if (conn == NULL)
	{
		bpf_printk("FATAL: failed to lookup conn track for existing client!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
		return -1;
	}
	else if (conn->be_fin == 1 && conn->client_fin == 1 && tcp->ack == 1)
	{
		bpf_printk("INFO: session finished!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
	}
	else if (tcp->rst == 1)
	{
		bpf_printk("WARN: client session reset!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
	}
	else
	{
		conn->ts = bpf_ktime_get_ns();
		if (conn->client_fin == 0)
		{
			conn->client_fin = tcp->fin;
		}
		if (bpf_map_update_elem(&port_conn_track_map, &cport, conn, BPF_EXIST) != 0)
		{
			bpf_printk("FATAL: failed to update conn track for existing client by client port!");
			cleanup_port_mappings(cport);
			push_back_port(cport);
			return -1;
		}
	}
	// Update source/destination Port, IP and MAC
	tcp->source = bpf_ntohs(cport);
	tcp->dest = bpf_ntohs(be_cfg->port);
	ip->daddr = be_cfg->ip;
	copy_mac(be_cfg->mac, eth->h_dest);
	return 0;
}

static __always_inline int
process_be_traffic(struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp)
{
	// TODO: remove it!
	bpf_printk("BE TCP [%d / %d]", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));

	__be16 cport = bpf_ntohs(tcp->dest);
	struct client_tupple *ct = bpf_map_lookup_elem(&port_client_tupple_map, &cport);
	if (ct == NULL)
	{
		bpf_printk("FATAL: failed to lookup existing client by destination port!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
		return -1;
	}
	struct conn_track *conn = bpf_map_lookup_elem(&port_conn_track_map, &cport);
	if (conn == NULL)
	{
		bpf_printk("FATAL: failed to lookup conn track by destination port!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
		return -1;
	}
	else if (conn->be_fin == 1 && conn->client_fin == 1 && tcp->ack == 1)
	{
		bpf_printk("INFO: session finished!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
	}
	else if (tcp->rst == 1)
	{
		bpf_printk("WARN: backend session reset!");
		cleanup_port_mappings(cport);
		push_back_port(cport);
	}
	else
	{
		conn->ts = bpf_ktime_get_ns();
		if (conn->be_fin == 0)
		{
			conn->be_fin = tcp->fin;
		}
		if (bpf_map_update_elem(&port_conn_track_map, &cport, conn, BPF_EXIST) != 0)
		{
			bpf_printk("FATAL: failed to update conn track mapping by destination port!");
			cleanup_port_mappings(cport);
			push_back_port(cport);
			return -1;
		}
	}

	// Update destination IP and MAC
	tcp->source = bpf_ntohs(port);
	tcp->dest = ct->port;
	ip->daddr = ct->ip;
	copy_mac(ct->mac, eth->h_dest);
	bpf_printk("BE %d -> CL %d", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
	return 0;
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
	{
		bpf_printk("ERROR: L2 verification failed!");
		return XDP_ABORTED;
	}

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
	{
		bpf_printk("INFO: Not IP packet, skipping ...");
		return XDP_PASS;
	}

	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
	{
		bpf_printk("ERROR: L3 verification failed!");
		return XDP_ABORTED;
	}

	if (ip->protocol != IPPROTO_TCP)
	{
		bpf_printk("INFO: Not TCP segment, skipping ...");
		return XDP_PASS;
	}

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
	{
		bpf_printk("WARN: TCP segment data check failed, skipping ...");
		return XDP_PASS;
	}

	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

	__be16 uport = bpf_ntohs(tcp->dest);
	struct client_tupple *ct = bpf_map_lookup_elem(&port_client_tupple_map, &uport); // if traffic source is backend
	if (tcp->dest != bpf_ntohs(port) && ct == NULL)
	{
		bpf_printk("INFO: TCP segment port mistmatch, skipping [s: %d, d: %d]...", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
		return XDP_PASS;
	}

	// Lookup LB config
	struct lb_cfg *lb_cfg = bpf_map_lookup_elem(&lb_cfg_map, &lb_cfg_key);
	if (lb_cfg == NULL)
	{
		bpf_printk("FATAL: load balancer config not found!");
		return XDP_ABORTED;
	}

	if (tcp->dest == bpf_ntohs(port))
	{
		struct client_tupple tupple = {
			.ip = ip->saddr,
			.port = tcp->source,
		};
		copy_mac(eth->h_source, tupple.mac);
		__be16 *client_port = bpf_map_lookup_elem(&client_tupple_port_map, &tupple);
		if (client_port == NULL)
		{
			if (process_new_client(eth, ip, tcp, lb_cfg, tupple) != 0)
			{
				return XDP_ABORTED;
			}
		}
		else if (process_existing_client(eth, ip, tcp, lb_cfg, *client_port) != 0)
		{
			return XDP_ABORTED;
		}
	}
	else if (process_be_traffic(eth, ip, tcp) != 0)
	{
		return XDP_ABORTED;
	}

	ip->saddr = lb_cfg->ip;
	copy_mac(lb_cfg->mac, eth->h_source);

	ip->check = iph_csum(ip);
	tcp->check = tcp_csum(tcp);

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
