#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define MAX_DEVICES 64

struct binding_key {
    unsigned char mac[6];
};

struct binding_val {
    __u32 ip;
    __u8 role;
};

// Map: Pre-enrolled MAC mathum current active DHCP IP
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEVICES);
    __type(key, struct binding_key);
    __type(value, struct binding_val);
} trusted_devices SEC(".maps");

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Bounds check: Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Bounds check: IPv4 Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Registry & DHCP binding check
    struct binding_key bkey;
    __builtin_memcpy(bkey.mac, eth->h_source, 6);

    struct binding_val *bval = bpf_map_lookup_elem(&trusted_devices, &bkey);
    if (!bval) {
        // Unknown MAC entry
        return XDP_DROP;
    }

    if (bval->ip != ip->saddr) {
        // Mismatched IP or Spoofed attempt
        return XDP_DROP;
    }

    // Inspect TCP Header
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((void *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
