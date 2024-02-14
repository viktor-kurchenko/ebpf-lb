#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define BE_MAX_ENTRIES 8
#define CLIENT_MAX_ENTRIES 64512 // > 1023 and <= 65535 (65535 - 1023 = 64512)

struct
{
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, CLIENT_MAX_ENTRIES);
    __type(value, __be16);
} ports SEC(".maps");

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
    __type(value, __be16);             // unique port
} client_tupple_port_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CLIENT_MAX_ENTRIES);
    __type(key, __be16);                 // unique port
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
    __type(key, __be16);              // unique port
    __type(value, struct server_cfg); // backend config
} port_be_cfg_map SEC(".maps");

struct conn_track
{
    long ts;          // latest connection activity timestamp
    __u16 client_fin; // client TCP FIN indicator
    __u16 be_fin;     // backend TCP FIN indicator
    __be32 last_seq;  // last and biggest SEQ number
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, CLIENT_MAX_ENTRIES);
    __type(key, __be16);              // unique port
    __type(value, struct conn_track); // connection track stats
} port_conn_track_map SEC(".maps");

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
finish_session(struct tcphdr *tcp, struct conn_track *conn)
{
    if (tcp->rst == 1)
    {
        bpf_printk("WARN: client session reset!");
        return 1;
    }
    if (conn != NULL && conn->be_fin == 1 && conn->client_fin == 1 && tcp->ack == 1)
    {
        return 1;
    }
    if (conn != NULL && ((conn->be_fin == 1 && conn->client_fin == 0) || (conn->be_fin == 0 && conn->client_fin == 1)) && tcp->fin == 0 && tcp->ack == 1 && conn->last_seq >= tcp->seq)
    {
        bpf_printk("WARN: out of order detected!");
        return 1;
    }
    return 0;
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
    conn.last_seq = tcp->seq;
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
    else if (finish_session(tcp, conn) == 1)
    {
        cleanup_port_mappings(cport);
        push_back_port(cport);
        bpf_printk("INFO: session finished!");
    }
    else
    {
        conn->ts = bpf_ktime_get_ns();
        if (conn->client_fin == 0)
        {
            conn->client_fin = tcp->fin;
        }
        if (conn->last_seq < tcp->seq)
        {
            conn->last_seq = tcp->seq;
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
    else if (finish_session(tcp, conn) == 1)
    {
        cleanup_port_mappings(cport);
        push_back_port(cport);
        bpf_printk("INFO: session finished!");
    }
    else
    {
        conn->ts = bpf_ktime_get_ns();
        if (conn->be_fin == 0)
        {
            conn->be_fin = tcp->fin;
        }
        if (conn->last_seq < tcp->seq)
        {
            conn->last_seq = tcp->seq;
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
    return 0;
}
