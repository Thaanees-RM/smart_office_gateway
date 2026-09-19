#!/usr/bin/env python3
# Loader daemon for the Smart Office IoT gateway.
#
# What this actually does now (unlike the old print()-only version):
#   1. Compiles ebpf/xdp_filter.c and attaches it to the IoT-facing NIC.
#   2. Tells the kernel which port counts as "high priority" (the fire
#      node's dedicated MQTT port).
#   3. Reads dnsmasq's DHCP lease file and WRITES matching devices into
#      the kernel's trusted_devices map (the old version only printed
#      this - nothing ever reached the kernel).
#   4. Reads the ring buffer of verdict events the kernel pushes out and
#      prints them, so there is something real for a dashboard to
#      consume later.
#
# Requires root (loading/attaching XDP programs needs elevated
# privileges) and the bcc package: on Ubuntu, `sudo apt install
# python3-bpfcc bpfcc-tools linux-headers-$(uname -r)`.
#
# Not yet run against a real kernel/bcc install in the environment this
# was written in - see the comments in xdp_filter.c about possible
# version differences in the ring-buffer API.

import ctypes as ct
import os
import signal
import socket
import sys
import time

from bcc import BPF

# --- Configuration ------------------------------------------------------

# The gateway's IoT-facing network interface. Find yours with `ip link
# show` and change this to match.
IFACE = "eth1"

# Every ESP32 allowed onto the network, keyed by its MAC address.
# "role" is a label for now (1=fire, 2=door, 3=env) - priority is
# actually decided by which PORT a device publishes to (see below), not
# by this role number.
ENROLLED_REGISTRY = {
    "cc:50:e3:12:34:56": {"role": 1, "name": "fire_node"},
    "cc:50:e3:12:34:57": {"role": 2, "name": "door_node"},
    "cc:50:e3:12:34:58": {"role": 3, "name": "env_node"},
}

# Must match HIGH_PRIORITY_PORT in xdp_filter.c, and the fire node's
# publish port / mosquitto.conf listener.
HIGH_PRIORITY_PORT = 18830

LEASE_FILE = "/var/lib/misc/dnsmasq.leases"
SYNC_INTERVAL_SEC = 5
XDP_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ebpf", "xdp_filter.c")

VERDICT_NAMES = {0: "DROP", 1: "PASS"}
REASON_NAMES = {
    0: "unknown MAC",
    1: "MAC/IP mismatch",
    2: "rate limited",
    3: "ok",
    4: "DHCP bootstrap bypass",
}


# --- Small conversion helpers --------------------------------------------

def mac_str_to_bytes(mac_str):
    """'cc:50:e3:12:34:56' -> bytes matching the kernel's u8 mac[6]."""
    return bytes(int(part, 16) for part in mac_str.split(":"))


def ip_str_to_bpf_u32(ip_str):
    """
    Convert '192.168.10.5' into the same 32-bit value the kernel sees as
    ip->saddr.

    IP headers store addresses in network byte order (big-endian).
    socket.inet_aton() gives us exactly those 4 bytes. This laptop's CPU
    (and ctypes' c_uint32) is little-endian, so reading those same 4
    bytes back as a little-endian integer produces a number that, when
    ctypes writes it into the BPF map, lands as the identical 4 raw
    bytes in the identical order the kernel already has. Using
    socket.ntohl() here instead would silently reverse the byte order
    and every IP comparison in the kernel would fail.
    """
    raw = socket.inet_aton(ip_str)
    return int.from_bytes(raw, byteorder="little")


# --- Kernel program loading -----------------------------------------------

def load_and_attach():
    """Compile xdp_filter.c and attach it to IFACE. Returns the BPF object."""
    b = BPF(src_file=XDP_SRC)
    fn = b.load_func("xdp_firewall", BPF.XDP)
    b.attach_xdp(IFACE, fn, 0)
    print(f"[+] xdp_firewall attached to {IFACE}")
    return b


def seed_priority_map(b):
    """
    Runs once at startup. Tells the kernel: 'packets whose destination
    port is HIGH_PRIORITY_PORT are priority class 1 (large rate-limit
    budget); everything else is left at the default, class 0.'
    """
    port_priority = b["port_priority"]
    key = ct.c_uint16(HIGH_PRIORITY_PORT)
    value = ct.c_uint8(1)
    port_priority[key] = value
    print(f"[+] port {HIGH_PRIORITY_PORT} marked as high priority")


def sync_leases_to_bpf(b):
    """
    Read dnsmasq's lease file and write any matching enrolled device's
    current MAC->IP binding into the kernel's trusted_devices map.

    This is the part the old version was missing entirely: it computed
    the same bindings but only printed them, so the kernel filter never
    actually learned who was trusted.

    Returns {mac: ip} for whichever enrolled devices currently hold a
    lease, so a caller (e.g. the dashboard) can show per-device IP and
    online status without re-reading the lease file itself.
    """
    trusted_devices = b["trusted_devices"]
    synced = {}

    try:
        with open(LEASE_FILE, "r") as f:
            lines = f.readlines()
    except OSError as err:
        print(f"[!] Could not read lease file: {err}")
        return synced

    for line in lines:
        parts = line.strip().split()
        if len(parts) < 3:
            continue

        mac, ip = parts[1].lower(), parts[2]
        if mac not in ENROLLED_REGISTRY:
            continue  # not one of our known devices

        device = ENROLLED_REGISTRY[mac]

        # trusted_devices.Key()/.Leaf() are ctypes structures that BCC
        # auto-generates from the C struct definitions in xdp_filter.c -
        # their field layout always matches the kernel side exactly, so
        # we don't have to hand-duplicate it here.
        key = trusted_devices.Key()
        for i, byte in enumerate(mac_str_to_bytes(mac)):
            key.mac[i] = byte

        leaf = trusted_devices.Leaf()
        leaf.ip = ip_str_to_bpf_u32(ip)
        leaf.role = device["role"]

        trusted_devices[key] = leaf
        synced[mac] = ip
        print(f"[Sync] {device['name']}: MAC {mac} -> IP {ip} written to kernel map")

    return synced


# --- Main loop --------------------------------------------------------

def main():
    b = load_and_attach()
    seed_priority_map(b)
    sync_leases_to_bpf(b)

    def handle_event(ctx, data, size):
        """Called once per verdict event the kernel pushes through the ring buffer."""
        event = b["events"].event(data)
        mac = ":".join(f"{byte:02x}" for byte in event.mac)
        verdict = VERDICT_NAMES.get(event.verdict, "?")
        reason = REASON_NAMES.get(event.reason, "?")
        print(f"[Kernel] {verdict:4s} mac={mac} reason={reason} priority={event.priority}")

    b["events"].open_ring_buffer(handle_event)

    def cleanup(signum, frame):
        print("\n[+] Detaching xdp_firewall and exiting")
        b.remove_xdp(IFACE, 0)
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    last_sync = time.time()
    print("[+] Control plane daemon running - Ctrl+C to stop")
    while True:
        # Waits up to 1 second for a kernel event, so we're never
        # blocked for long and still re-sync leases on schedule below.
        b.ring_buffer_poll(timeout=1000)

        now = time.time()
        if now - last_sync >= SYNC_INTERVAL_SEC:
            sync_leases_to_bpf(b)
            last_sync = now


if __name__ == "__main__":
    main()
