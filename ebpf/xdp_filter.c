// Kernel-side packet filter for the Smart Office IoT gateway.
// Attached to the XDP hook of the IoT-facing NIC, so this code runs for
// every frame the NIC receives, before the kernel builds a socket buffer
// and before iptables ever sees the packet.
//
// Written for BCC (github.com/iovisor/bcc): the Python loader compiles
// this file at runtime with clang, so there is no separate build step
// and no vmlinux.h/CO-RE setup to manage. BPF_HASH / BPF_RINGBUF_OUTPUT
// below are BCC macros, not raw libbpf map definitions.
//
// NOTE: this has not been compiled/tested on real hardware yet (no
// eBPF-capable kernel available in the environment this was written in).
// If BPF_RINGBUF_OUTPUT / .ringbuf_output() isn't recognised by your
// installed bcc version, the older and near-universally-supported
// equivalent is BPF_PERF_OUTPUT / .perf_submit() - swap those two in and
// the Python side's open_ring_buffer()/ring_buffer_poll() calls become
// open_perf_buffer()/perf_buffer_poll() instead.

// Deliberately does NOT include <linux/bpf.h> here: BCC's own
// compilation pipeline already provides struct xdp_md, XDP_PASS/
// XDP_DROP, and every BPF helper/map macro this file uses, through its
// own internal preamble - this file never needed to include it directly.
// Removing it does NOT fix the CI/verifier-check failure some kernels
// hit, though: BCC's own preamble pulls in the real kernel's
// <linux/bpf.h> regardless, and that failure (incomplete types like
// struct bpf_wq, undeclared identifiers like BPF_LOAD_ACQ/BPF_F_CPU) is
// bcc 0.29.1's clang front-end being too old to parse very recent
// kernel BPF additions - a real upstream bcc/kernel-version gap, not
// something fixable from this source file. See the README for the full
// explanation and why the CI job stays best-effort (continue-on-error)
// rather than being "fixed" here.
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

// ---------------------------------------------------------------------
// Tunable constants
// ---------------------------------------------------------------------

#define MAX_DEVICES 64

// DHCP negotiation (a device asking for / renewing an IP) always uses
// these two ports. A brand-new ESP32 has no lease yet, so it cannot
// possibly be in the trusted_devices map below - if we didn't let its
// DHCP traffic through unconditionally, it could never obtain the lease
// that is supposed to get it admitted in the first place. This bypass
// is what makes "a new node is admitted automatically once it obtains a
// lease" (from the proposal) actually possible.
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

// The fire node must publish to this MQTT port so this filter can tell
// its traffic apart from routine traffic using only header fields (an
// XDP program cannot safely parse the MQTT payload to read the topic
// name). Must match a `listener 18830` line in mosquitto.conf.
#define HIGH_PRIORITY_PORT 18830

// Token-bucket rate-limit parameters. BURST = how many packets can be
// sent in a sudden spike before any are dropped; REFILL = tokens added
// back per second afterwards. High-priority (fire node) gets a budget
// large enough that it should never run dry even while the network is
// under attack; these are starting points to tune experimentally, per
// the proposal's "iterative refinement" step - not final numbers.
#define NORMAL_BURST      20
#define NORMAL_REFILL     10
#define HIGH_PRIO_BURST   500
#define HIGH_PRIO_REFILL  2000

// Verdict/reason codes, sent to user space in each ring-buffer event so
// the dashboard can show *why* a packet was dropped, not just that it
// was.
#define VERDICT_DROP 0
#define VERDICT_PASS 1

#define REASON_UNKNOWN_MAC  0
#define REASON_IP_MISMATCH  1
#define REASON_RATE_LIMITED 2
#define REASON_OK           3
#define REASON_DHCP_BYPASS  4

// ---------------------------------------------------------------------
// Map 1: the allowlist. Written only by the loader daemon from DHCP
// lease data - never from anything arriving over the network - which is
// what makes an MQTT-side "unauthorised configuration" attack unable to
// change who the gateway trusts.
// ---------------------------------------------------------------------

struct binding_key {
    unsigned char mac[6];
};

struct binding_val {
    u32 ip;   // ip->saddr, i.e. raw network-byte-order bytes - see the
              // Python loader's ip_str_to_bpf_u32() for why this matters
    u8  role; // 1=fire, 2=door, 3=env (informational only right now)
};

BPF_HASH(trusted_devices, struct binding_key, struct binding_val, MAX_DEVICES);

// ---------------------------------------------------------------------
// Map 2: per-device rate limit state (the token bucket).
// ---------------------------------------------------------------------

struct token_bucket {
    u64 tokens;
    u64 last_refill_ns;
};

BPF_HASH(rate_limit, struct binding_key, struct token_bucket, MAX_DEVICES);

// ---------------------------------------------------------------------
// Map 3: destination port -> priority class (0 = normal, 1 = high).
// Populated once at startup by the loader daemon.
// ---------------------------------------------------------------------

BPF_HASH(port_priority, u16, u8, 16);

// ---------------------------------------------------------------------
// Map 4: ring buffer - every verdict of interest is pushed through here
// so the Python side can log it and the Flask dashboard can show it.
// ---------------------------------------------------------------------

struct event {
    unsigned char mac[6];
    u32 ip;
    u8  verdict;
    u8  reason;
    u8  priority;
    u64 ts_ns;
};

BPF_RINGBUF_OUTPUT(events, 8); // 8 pages = 32KB of buffer space

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// Pushes one event to user space. If the ring buffer is momentarily
// full we just drop the *telemetry* event, never the packet itself -
// losing a log line is fine, losing a fire alert is not.
static inline void emit_event(struct binding_key *key, u32 ip, u8 verdict,
                               u8 reason, u8 priority) {
    struct event evt = {};
    __builtin_memcpy(evt.mac, key->mac, 6);
    evt.ip = ip;
    evt.verdict = verdict;
    evt.reason = reason;
    evt.priority = priority;
    evt.ts_ns = bpf_ktime_get_ns();
    events.ringbuf_output(&evt, sizeof(evt), 0);
}

// Classic token bucket: refill based on elapsed time, then spend one
// token per packet. Returns 1 = allow, 0 = drop.
//
// Known limitation, left as-is deliberately for a first working version:
// two packets from the same device arriving on different CPU cores at
// the same instant could both read the bucket before either writes it
// back, letting one extra packet through. Fixing this needs a
// bpf_spin_lock around the read-modify-write - worth mentioning as a
// "future work" line in the report rather than solving now.
static inline int allow_by_rate_limit(struct binding_key *key, u8 priority) {
    struct token_bucket *tb = rate_limit.lookup(key);
    u64 now = bpf_ktime_get_ns();

    if (!tb) {
        struct token_bucket init = {};
        // Already spent this packet's token, so start one below full.
        init.tokens = (priority ? HIGH_PRIO_BURST : NORMAL_BURST) - 1;
        init.last_refill_ns = now;
        rate_limit.update(key, &init);
        return 1;
    }

    u64 max_burst   = priority ? HIGH_PRIO_BURST  : NORMAL_BURST;
    u64 refill_rate = priority ? HIGH_PRIO_REFILL : NORMAL_REFILL;

    u64 elapsed_ns = now - tb->last_refill_ns;
    u64 new_tokens = (elapsed_ns * refill_rate) / 1000000000ULL;

    if (new_tokens > 0) {
        u64 total = tb->tokens + new_tokens;
        tb->tokens = total > max_burst ? max_burst : total;
        tb->last_refill_ns = now;
    }

    if (tb->tokens == 0)
        return 0;

    tb->tokens -= 1;
    return 1;
}

// ---------------------------------------------------------------------
// Entry point. BCC attaches this by name (xdp_firewall), not via a
// SEC() annotation - see sync_daemon.py's load_and_attach().
// ---------------------------------------------------------------------

int xdp_firewall(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    void *l4 = (void *)ip + (ip->ihl * 4);

    // --- DHCP bootstrap bypass -----------------------------------
    // Must happen before the allowlist check (see DHCP_SERVER_PORT
    // comment above) - a device with no lease yet cannot be trusted,
    // but it still has to be allowed to *ask* for one.
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS; // truncated packet - let the stack deal with it

        u16 dport = bpf_ntohs(udp->dest);
        if (dport == DHCP_SERVER_PORT || dport == DHCP_CLIENT_PORT) {
            struct binding_key bkey = {};
            __builtin_memcpy(bkey.mac, eth->h_source, 6);
            emit_event(&bkey, ip->saddr, VERDICT_PASS, REASON_DHCP_BYPASS, 0);
            return XDP_PASS;
        }
    }

    // --- Identity check --------------------------------------------
    struct binding_key bkey = {};
    __builtin_memcpy(bkey.mac, eth->h_source, 6);

    struct binding_val *bval = trusted_devices.lookup(&bkey);
    if (!bval) {
        emit_event(&bkey, ip->saddr, VERDICT_DROP, REASON_UNKNOWN_MAC, 0);
        return XDP_DROP;
    }

    if (bval->ip != ip->saddr) {
        emit_event(&bkey, ip->saddr, VERDICT_DROP, REASON_IP_MISMATCH, 0);
        return XDP_DROP;
    }

    // --- Priority + rate limit (TCP/UDP only - MQTT is normally TCP) ---
    u16 dport;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            emit_event(&bkey, ip->saddr, VERDICT_DROP, REASON_IP_MISMATCH, 0);
            return XDP_DROP; // truncated header from an already-trusted
                              // device is suspicious enough to drop
        }
        dport = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
        dport = bpf_ntohs(udp->dest);
    } else {
        // Not TCP/UDP (e.g. ICMP) from a trusted device - nothing else
        // to enforce here.
        return XDP_PASS;
    }

    u8 *prio_lookup = port_priority.lookup(&dport);
    u8 priority = prio_lookup ? *prio_lookup : 0;

    if (!allow_by_rate_limit(&bkey, priority)) {
        emit_event(&bkey, ip->saddr, VERDICT_DROP, REASON_RATE_LIMITED, priority);
        return XDP_DROP;
    }

    emit_event(&bkey, ip->saddr, VERDICT_PASS, REASON_OK, priority);
    return XDP_PASS;
}
