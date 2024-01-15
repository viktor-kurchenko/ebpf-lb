//go:build ignore

#include "xdp_lb_kern.h"

#define PORT 8080
#define IP_ADDRESS(x) (unsigned int)(192 + (168 << 8) + (122 << 16) + (x << 24))

#define BACKEND_A 2
#define CLIENT 7
#define LB 1

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_ABORTED;
	}

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
		return XDP_PASS;
	}

	struct iphdr *ip = data + sizeof(struct ethhdr);
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
		return XDP_ABORTED;
	}

	if (ip->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
		return XDP_PASS;
	}


	struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	// Handle traffic from backend
	if (ip->saddr == IP_ADDRESS(BACKEND_A) && tcp->source == bpf_ntohs(PORT))
	{
		ip->daddr = IP_ADDRESS(CLIENT);
		eth->h_dest[5] = CLIENT;
		bpf_printk("back -> client");
	}
	// Handle traffic from client
	else if (ip->saddr == IP_ADDRESS(CLIENT) && tcp->dest == bpf_ntohs(PORT))
	{
		ip->daddr = IP_ADDRESS(BACKEND_A);
		eth->h_dest[5] = BACKEND_A;
		bpf_printk("client -> back");
	}
	else
	{
		return XDP_PASS;
	}

	ip->saddr = IP_ADDRESS(LB);
	eth->h_source[3] = 9;
	eth->h_source[4] = 217;
	eth->h_source[5] = 139;

	ip->check = iph_csum(ip);

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
