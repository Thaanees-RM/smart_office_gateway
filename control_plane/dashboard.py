#!/usr/bin/env python3
# Flask monitoring dashboard for the Smart Office IoT gateway.
#
# Reuses the kernel-loading and DHCP-sync logic from sync_daemon.py (so
# that logic exists in exactly one place) and adds:
#   - a background thread that keeps the loader running and maintains
#     three rolling time-series (drops/sec, gateway CPU%, an
#     event-pipeline latency placeholder) plus a capped log of recent
#     kernel events,
#   - an optional best-effort MQTT subscriber for the message log (the
#     dashboard still works with no broker running yet),
#   - the Flask routes that serve the page and the JSON it polls.
#
# Run this INSTEAD of sync_daemon.py when you want the web dashboard - it
# does everything sync_daemon.py does, plus the dashboard.
#
# Extra dependencies beyond sync_daemon.py's (bcc):
#   sudo apt install python3-flask python3-psutil python3-paho-mqtt
#
# Run as root (loading/attaching XDP needs it, same as sync_daemon.py):
#   sudo python3 dashboard.py
# Then open http://<gateway-ip>:5000 from a machine on the OFFICE
# network (not the isolated IoT subnet).
#
# The bcc calls this file relies on (via sync_daemon.py) were checked
# against a real installed bcc 0.29.1 on Ubuntu 24.04 - see the project
# README. Actually attaching to a live interface with real traffic, and
# a real Mosquitto broker, have NOT been tested yet.

import os
import threading
import time
from collections import deque

import psutil
from flask import Flask, jsonify, render_template

import sync_daemon as daemon  # reuses load_and_attach / sync_leases_to_bpf / etc.

try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False

# --- Configuration --------------------------------------------------------

# In Docker Compose, Mosquitto would be a separate service reachable by
# its service name (e.g. "mosquitto"), not "127.0.0.1" - overridable
# via environment variables for exactly that reason.
MQTT_BROKER_HOST = os.environ.get("MQTT_BROKER_HOST", "127.0.0.1")
MQTT_BROKER_PORT = int(os.environ.get("MQTT_BROKER_PORT", "1883"))
SERIES_LENGTH = 120   # ~2 minutes of history at 1 sample/sec, per chart
EVENT_LOG_LENGTH = 200
MQTT_LOG_LENGTH = 100

# --- Shared state, guarded by one lock -------------------------------------
# The background thread writes to these; Flask's request threads read
# them. One lock for all of it is simpler to reason about than one lock
# per structure, and at this data rate (a few small deques, touched a
# few times a second) it is nowhere near a bottleneck.

state_lock = threading.Lock()
events_log = deque(maxlen=EVENT_LOG_LENGTH)
mqtt_log = deque(maxlen=MQTT_LOG_LENGTH)

drop_timestamps = deque()  # raw drop times, trimmed to the trailing 1s window
drop_rate_series = deque(maxlen=SERIES_LENGTH)
cpu_series = deque(maxlen=SERIES_LENGTH)
latency_series = deque(maxlen=SERIES_LENGTH)

daemon_start_time = time.time()

# Running totals across the whole session (not windowed like the series
# above) - plain dicts rather than module-level ints so record_event()
# can mutate them without a `global` statement.
totals = {"pass": 0, "drop": 0}

# Only the three DROP reasons are meaningful here (REASON_OK and
# REASON_DHCP_BYPASS aren't drops) - see daemon.REASON_NAMES for the
# full code list this indexes into.
drop_reason_counts = {0: 0, 1: 0, 2: 0}

# One entry per enrolled device, seeded from ENROLLED_REGISTRY so the
# dashboard can show fire_node/door_node/env_node even before any
# traffic has been seen from them. "slot" is the fixed categorical
# colour slot for that device (1=blue, 2=orange, 3=aqua), taken straight
# from its role number so the mapping never changes at runtime.
device_stats = {
    mac: {
        "name": info["name"],
        "slot": info["role"],
        "ip": None,
        "leased": False,
        "pass_count": 0,
        "drop_count": 0,
        "last_seen": None,
    }
    for mac, info in daemon.ENROLLED_REGISTRY.items()
}


def record_event(mac, verdict, reason, priority):
    """Called for every kernel verdict event. Logs it and updates drop/latency series."""
    now = time.time()
    with state_lock:
        events_log.append({
            "time": now,
            "mac": mac,
            "verdict": daemon.VERDICT_NAMES.get(verdict, "?"),
            "reason": daemon.REASON_NAMES.get(reason, "?"),
            "priority": priority,
        })
        if verdict == 0:  # DROP
            drop_timestamps.append(now)
            totals["drop"] += 1
            if reason in drop_reason_counts:
                drop_reason_counts[reason] += 1
        else:
            totals["pass"] += 1

        # Only enrolled devices are tracked individually - traffic from
        # an unknown MAC (e.g. an attack node) still counts in the
        # totals above, but has nowhere per-device to go.
        if mac in device_stats:
            ds = device_stats[mac]
            ds["last_seen"] = now
            if verdict == 1:
                ds["pass_count"] += 1
            else:
                ds["drop_count"] += 1

        # PLACEHOLDER METRIC - not the proposal's real fire-alert latency.
        # The real metric is (dashboard display time) - (physical sensor
        # trigger time), and the trigger time can only come from the
        # ESP32 fire node embedding its own timestamp in the MQTT
        # payload it publishes. That firmware doesn't exist yet. Until
        # it does, this just marks "a high-priority packet passed the
        # filter just now" with value 0, so the chart has a real, honest
        # data point instead of a fabricated latency number. Once the
        # firmware sends a trigger timestamp, read it from mqtt_log
        # instead and compute (now - trigger_time) here.
        if priority == 1 and verdict == 1:
            latency_series.append({"time": now, "value": 0})


def sample_gateway_metrics():
    """Runs ~once/sec: turns the raw drop timestamps into a rate, and samples CPU%."""
    now = time.time()
    with state_lock:
        while drop_timestamps and now - drop_timestamps[0] > 1.0:
            drop_timestamps.popleft()
        drop_rate_series.append({"time": now, "value": len(drop_timestamps)})
        cpu_series.append({"time": now, "value": psutil.cpu_percent(interval=None)})


def mqtt_worker():
    """
    Best-effort MQTT subscriber for the dashboard's message log. Retries
    quietly if Mosquitto isn't running yet - everything else on the
    dashboard works without this thread succeeding.
    """
    if not MQTT_AVAILABLE:
        print("[!] paho-mqtt not installed - MQTT message log disabled")
        return

    def on_message(client, userdata, msg):
        with state_lock:
            mqtt_log.append({
                "time": time.time(),
                "topic": msg.topic,
                "payload": msg.payload.decode(errors="replace")[:200],
            })

    client = mqtt.Client()
    client.on_message = on_message

    while True:
        try:
            client.connect(MQTT_BROKER_HOST, MQTT_BROKER_PORT, keepalive=30)
            client.subscribe("#")
            print(f"[+] MQTT log connected to {MQTT_BROKER_HOST}:{MQTT_BROKER_PORT}")
            client.loop_forever()
        except OSError as err:
            print(f"[!] MQTT broker not reachable yet ({err}); retrying in 5s")
            time.sleep(5)


def apply_lease_sync(b):
    """
    Wraps sync_leases_to_bpf() so its {mac: ip} result also updates each
    enrolled device's IP and online status here, instead of the
    dashboard re-reading the lease file itself.
    """
    synced = daemon.sync_leases_to_bpf(b)
    with state_lock:
        for mac, ds in device_stats.items():
            ds["leased"] = mac in synced
            if mac in synced:
                ds["ip"] = synced[mac]


def kernel_worker():
    """
    Loads and attaches the XDP program, feeds its ring-buffer events into
    record_event(), and keeps DHCP-lease sync plus per-second metric
    sampling running - the web-dashboard equivalent of sync_daemon.py's
    own main() loop.
    """
    b = daemon.load_and_attach()
    daemon.seed_priority_map(b)
    apply_lease_sync(b)

    def handle_event(ctx, data, size):
        event = b["events"].event(data)
        mac = ":".join(f"{byte:02x}" for byte in event.mac)
        record_event(mac, event.verdict, event.reason, event.priority)

    b["events"].open_ring_buffer(handle_event)

    last_lease_sync = time.time()
    last_metric_sample = time.time()

    while True:
        # Short timeout so we come back around often enough to keep the
        # once-a-second metric sampling below on schedule even when no
        # kernel events are arriving.
        b.ring_buffer_poll(timeout=200)

        now = time.time()
        if now - last_lease_sync >= daemon.SYNC_INTERVAL_SEC:
            apply_lease_sync(b)
            last_lease_sync = now

        if now - last_metric_sample >= 1.0:
            sample_gateway_metrics()
            last_metric_sample = now


# --- Flask app --------------------------------------------------------

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/state")
def api_state():
    """
    Everything the page needs for one refresh: the three chart series,
    the live kernel-event log, and the MQTT message log. Polled from the
    browser every couple of seconds - see templates/dashboard.html.
    """
    with state_lock:
        return jsonify({
            "events": list(events_log)[-50:][::-1],     # most recent first
            "mqtt_log": list(mqtt_log)[-20:][::-1],
            "drop_rate_series": list(drop_rate_series),
            "cpu_series": list(cpu_series),
            "latency_series": list(latency_series),
            "totals": {
                "pass": totals["pass"],
                "drop": totals["drop"],
                "trusted_online": sum(1 for d in device_stats.values() if d["leased"]),
                "trusted_total": len(device_stats),
                "uptime_sec": time.time() - daemon_start_time,
            },
            "devices": [
                {"mac": mac, **ds} for mac, ds in device_stats.items()
            ],
            "drop_reasons": {
                "Unknown MAC": drop_reason_counts[0],
                "IP mismatch": drop_reason_counts[1],
                "Rate limited": drop_reason_counts[2],
            },
        })


if __name__ == "__main__":
    threading.Thread(target=kernel_worker, daemon=True).start()
    threading.Thread(target=mqtt_worker, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
