// go:build ignore

#include "xdp_lb_kern.h"
#include "xdp_lb_net.h"

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

	__be16 dport = bpf_ntohs(tcp->dest);
	struct client_tupple *ct = bpf_map_lookup_elem(&port_client_tupple_map, &dport); // if traffic source is backend
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
