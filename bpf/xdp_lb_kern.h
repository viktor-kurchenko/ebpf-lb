#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

static __always_inline __u16
tcp_csum(struct tcphdr *tcp)
{
    tcp->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)tcp, sizeof(struct tcphdr), 0);
    return csum_fold_helper(csum);
}

static __always_inline void
copy_mac(unsigned char src[ETH_ALEN], unsigned char dst[ETH_ALEN])
{
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
    dst[4] = src[4];
    dst[5] = src[5];
}
