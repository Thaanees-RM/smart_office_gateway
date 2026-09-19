import subprocess
import time

ENROLLED_REGISTRY = {
    "cc:50:e3:12:34:56": {"role": 1, "name": "fire_node"},
    "cc:50:e3:12:34:57": {"role": 2, "name": "door_node"},
    "cc:50:e3:12:34:58": {"role": 3, "name": "env_node"}
}

LEASE_FILE = "/var/lib/misc/dnsmasq.leases"

def parse_leases():
    active_bindings = {}
    try:
        with open(LEASE_FILE, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    mac, ip = parts[1].lower(), parts[2]
                    if mac in ENROLLED_REGISTRY:
                        active_bindings[mac] = ip
    except Exception as err:
        print(f"[Error] Lease file read failed: {err}")
    return active_bindings

def update_bpf_map():
    bindings = parse_leases()
    for mac, ip in bindings.items():
        print(f"[Sync] Approved device: MAC {mac} -> IP {ip}")

if __name__ == "__main__":
    print("Control plane daemon running with Python 3.12...")
    while True:
        update_bpf_map()
        time.sleep(5)
