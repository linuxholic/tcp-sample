// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"

#define SAMPLE_SIZE 1024ul
#define SAMPLE_COUNT 5
#define MAX_CPUS 128
#define MAX_FLOWS 1024

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

/* better zero out whole struct before usage, so union padding
 * is all zero, which is neccessary for hash */
struct flow_key {

    union {
        __be32 ip;
        struct in6_addr ip6;
    } src_ip;

    union {
        __be32 ip;
        struct in6_addr ip6;
    } dst_ip;

    __be16 src_port;
    __be16 dst_port;
};

struct flow_info {
    __u64 flow_bytes;
    __u64 flow_pkts;
	__u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_info);
    __uint(max_entries, MAX_FLOWS);
} flow_map SEC(".maps");

/* Metadata will be in the perf event before the packet data. */
struct S {
    __u16 cookie;
    __u16 pkt_len;
} __packed;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, __u32);
    __uint(max_entries, MAX_CPUS);
} my_map SEC(".maps");

static __always_inline void save_packet(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size = (__u16)(data_end - data);
    int ret;
    struct S metadata = {0};

    metadata.cookie = 0xdead;
    metadata.pkt_len = min(sample_size, SAMPLE_SIZE);

    flags |= (__u64)sample_size << 32;

    ret = bpf_perf_event_output(ctx, &my_map, flags,
            &metadata, sizeof(metadata));
    if (ret)
        bpf_printk("perf_event_output failed: %d\n", ret);
}

SEC("xdp")
int xdp_sample_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    int eth_type, ip_type, err, tcp_packet = 0;
    struct ethhdr *eth;
    struct iphdr *iphdr;
    struct ipv6hdr *ipv6hdr;
    struct udphdr *udphdr;
    struct tcphdr *tcphdr;
    struct hdr_cursor nh = { .pos = data };
    struct flow_key key = {0};
    struct flow_info *finfo, new_info;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0) {
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {

        ip_type = parse_iphdr(&nh, data_end, &iphdr);

        /* make bpf verifier happy, because we're
         * accessing packet data afterwards */
        if (ip_type < 0) goto out;

        key.dst_ip.ip = iphdr->daddr;
        key.src_ip.ip = iphdr->saddr;

    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {

        ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);

        /* make bpf verifier happy, because we're
         * accessing packet data afterwards */
        if (ip_type < 0) goto out;

        key.dst_ip.ip6 = ipv6hdr->daddr;
        key.src_ip.ip6 = ipv6hdr->saddr;

    } else {
        bpf_printk("unknown eth_type: %d", eth_type);
        goto out;
    }

    if (ip_type == IPPROTO_UDP) {
        if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
            goto out;
        }
        key.dst_port = bpf_ntohs(udphdr->dest);
        key.src_port = bpf_ntohs(udphdr->source);
    } else if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
            goto out;
        }
        tcp_packet = 1;
        key.dst_port = bpf_ntohs(tcphdr->dest);
        key.src_port = bpf_ntohs(tcphdr->source);
    }
    else {
        bpf_printk("skip ip_type: %d", ip_type);
        goto out;
    }

    if (data < data_end) {

        if (tcp_packet)
        {
            if (tcphdr->fin || tcphdr->rst)
            {
                finfo = bpf_map_lookup_elem(&flow_map, &key);
                if (!finfo) goto out; /* maybe gc due to timeout */
                err = bpf_map_delete_elem(&flow_map, &key);
                if (err) bpf_printk("bpf_map_delete_elem failed");
                goto out;
            }

            if (nh.pos == data_end) // no payload
            {
                /* we won't saving tcp meta info, such as fin/rst. */
                goto out;
            }
        }

        finfo = bpf_map_lookup_elem(&flow_map, &key);
        if (!finfo)
        {
            new_info.flow_pkts = 1;
            new_info.flow_bytes = (data_end - data);
            new_info.timestamp = bpf_ktime_get_ns(); /* bpf verifier.. */
            err = bpf_map_update_elem(&flow_map, &key, &new_info, BPF_ANY);
            if (err < 0)
            {
                bpf_printk("flow map is full.");
                goto out;
            }

            finfo = bpf_map_lookup_elem(&flow_map, &key);
            if (!finfo) goto out;
        }
        else {
            finfo->flow_bytes += (data_end - data);
            finfo->flow_pkts += 1;
            finfo->timestamp = bpf_ktime_get_ns();
        }

        if (finfo->flow_pkts <= SAMPLE_COUNT)
        {
            save_packet(ctx);
        }
    }

out:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
