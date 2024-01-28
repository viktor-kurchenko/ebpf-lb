// go:build ignore

#include "xdp_lb_kern.h"

#define BE_MAX_ENTRIES 8
#define CLIENT_MAX_ENTRIES 8

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
	__type(key, __be16);			  // client port (must be unique)
	__type(value, struct server_cfg); // client properties
} clients_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CLIENT_MAX_ENTRIES);
	__type(key, __be16);   // client port
	__type(value, __be16); // backend index -> be_cfg_map
} client_port_be_map SEC(".maps");

volatile const __u16 lb_cfg_key;
volatile const __u16 port;

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

	__be16 *be_idx = bpf_map_lookup_elem(&client_port_be_map, &tcp->dest); // if traffic source is backend
	if (tcp->dest != bpf_ntohs(port) && be_idx == NULL)
	{
		bpf_printk("INFO: TCP segment port mistmatch, skipping [s: %d, d: %d]...", tcp->source, tcp->dest);
		return XDP_PASS;
	}

	// Lookup LB config
	struct lb_cfg *lb_cfg = bpf_map_lookup_elem(&lb_cfg_map, &lb_cfg_key);
	if (lb_cfg == NULL)
	{
		bpf_printk("FATAL: load balancer config not found!");
		return XDP_ABORTED;
	}

	// Traffic from clients
	if (tcp->dest == bpf_ntohs(port))
	{
		bpf_printk("Traffic from client");
		struct server_cfg *be_cfg;
		struct server_cfg *client = bpf_map_lookup_elem(&clients_map, &tcp->source);
		// Add a new client
		if (client == NULL)
		{
			// Lookup backend for a new client
			__be16 be_idx = bpf_ktime_get_ns() % lb_cfg->be_count;
			be_cfg = bpf_map_lookup_elem(&be_cfg_map, &be_idx);
			if (be_cfg == NULL)
			{
				bpf_printk("FATAL: backend config not found [index: %d]!", be_idx);
				return XDP_ABORTED;
			}

			struct server_cfg new_client = {
				// TODO: can we avoid this var?
				.port = tcp->source,
				.ip = ip->saddr,
				.mac = {eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]},
			};
			long res = bpf_map_update_elem(&clients_map, &tcp->source, &new_client, BPF_NOEXIST);
			if (res != 0)
			{
				bpf_printk("ERROR: failed to save new client!");
				return XDP_ABORTED;
			}

			// Save client to backend mapping
			res = bpf_map_update_elem(&client_port_be_map, &tcp->source, &be_idx, BPF_NOEXIST);
			if (res != 0)
			{
				bpf_printk("ERROR: failed to save client -> backend mapping!");
				return XDP_ABORTED;
			}
		}
		// Lookup backend config for existing client
		else
		{
			__be16 *be_idx = bpf_map_lookup_elem(&client_port_be_map, &client->port);
			if (be_idx == NULL)
			{
				bpf_printk("FATAL: backend config not found [port: %d]!", client->port);
				return XDP_ABORTED;
			}

			be_cfg = bpf_map_lookup_elem(&be_cfg_map, be_idx);
			if (be_cfg == NULL)
			{
				bpf_printk("FATAL: backend config not found [index: %d]!", *be_idx);
				return XDP_ABORTED;
			}
		}

		// Update destination Port, IP and MAC
		tcp->dest = bpf_ntohs(be_cfg->port);
		ip->daddr = be_cfg->ip;
		eth->h_dest[0] = be_cfg->mac[0]; // TODO: can we simplify this assignment?
		eth->h_dest[1] = be_cfg->mac[1];
		eth->h_dest[2] = be_cfg->mac[2];
		eth->h_dest[3] = be_cfg->mac[3];
		eth->h_dest[4] = be_cfg->mac[4];
		eth->h_dest[5] = be_cfg->mac[5];
	}
	// Traffic from backends
	else
	{
		// 1. Lookup client by port
		// 2. Update destination IP and MAC
		struct server_cfg *client = bpf_map_lookup_elem(&clients_map, &tcp->dest);
		if (client == NULL)
		{
			bpf_printk("FATAL: client not found [port: %d]!", tcp->dest);
			return XDP_ABORTED;
		}

		// Update destination IP and MAC
		tcp->source = bpf_ntohs(port);
		ip->daddr = client->ip;
		eth->h_dest[0] = client->mac[0]; // TODO: can we simplify this assignment?
		eth->h_dest[1] = client->mac[1];
		eth->h_dest[2] = client->mac[2];
		eth->h_dest[3] = client->mac[3];
		eth->h_dest[4] = client->mac[4];
		eth->h_dest[5] = client->mac[5];
	}

	ip->saddr = lb_cfg->ip;
	eth->h_source[0] = lb_cfg->mac[0];
	eth->h_source[1] = lb_cfg->mac[1];
	eth->h_source[2] = lb_cfg->mac[2];
	eth->h_source[3] = lb_cfg->mac[3];
	eth->h_source[4] = lb_cfg->mac[4];
	eth->h_source[5] = lb_cfg->mac[5];

	ip->check = iph_csum(ip);
	tcp->check = tcp_csum(tcp);

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
