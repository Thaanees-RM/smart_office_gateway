Smart Office Gateway - Control Plane and Kernel Filter
=======================================================

This covers the part of the NTP proposal ("Securing Smart Office IoT Devices
Against Unauthorized Configuration/API Attacks and Buffer Overflow/Memory
Injection") that is actually implemented in this repo so far: the kernel-side
XDP filter and the loader daemon and dashboard that drive it.

What's here vs. what isn't (read this first)
----------------------------------------------

Implemented:

- ebpf/xdp_filter.c - the kernel packet filter: MAC+IP allowlist, a DHCP
  bootstrap bypass, per-device rate limiting, port-based priority, and a
  ring buffer of verdict events.
- control_plane/sync_daemon.py - headless loader daemon: attaches the
  filter, syncs DHCP leases into it, prints ring-buffer events.
- control_plane/dashboard.py and control_plane/templates/dashboard.html -
  the same daemon, plus a live web dashboard (event log, per-device cards,
  drop-reason breakdown, latency/CPU/drop charts).

Not implemented yet (other team members' sub-objectives - don't expect
these steps to cover them):

- Mosquitto broker configuration
- ESP32 fire/door/env node firmware
- The iptables/baseline comparison setup
- The two graded security pass/fail tests (both need the broker and
  firmware above)

The fire-alert latency chart in the dashboard is a labelled placeholder
until the ESP32 firmware exists - see the comment in dashboard.py's
record_event function.

Prerequisites
-------------

- Ubuntu 24.04 (or similar), kernel 5.8 or newer for ring-buffer maps -
  check with: uname -r
- Root/sudo access (loading and attaching an XDP program requires it).
- dnsmasq running on the gateway's IoT-facing interface, writing leases to
  /var/lib/misc/dnsmasq.leases.
- Ideally a second machine, VM, or network namespace to act as a "device" -
  several tests below need something to send traffic from.

1. Install dependencies
------------------------

Run:

  sudo apt update
  sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r) python3-flask python3-psutil python3-paho-mqtt linux-tools-common

Note: bpftool itself is a virtual package on Ubuntu - installing it
directly by that name fails. linux-tools-common is what actually
provides a working bpftool binary, confirmed on a real Ubuntu 24.04
machine.

2. Point the scripts at your real interface
--------------------------------------------

Find your IoT-facing NIC name:

  ip link show

Edit IFACE at the top of both control_plane/sync_daemon.py and
control_plane/dashboard.py to match (currently set to "eth1").

3. Smoke test - does it load and attach at all?
------------------------------------------------

  cd control_plane
  sudo python3 sync_daemon.py

Expect a line like "xdp_firewall attached to <iface>" and no traceback.
Press Ctrl+C, then confirm the program actually detached:

  ip link show <iface>

It should show no xdp entry now. If this step fails, stop here and fix it
before testing anything else - nothing downstream works without a clean
attach/detach cycle.

4. Inspect kernel state directly with bpftool
------------------------------------------------

Useful for showing a lecturer that state genuinely lives in the kernel,
not just in Python:

  sudo bpftool prog show
  sudo bpftool map dump name trusted_devices
  sudo bpftool map dump name rate_limit

The first command lists your xdp_firewall program with an id. The second
shows allowlist entries once synced. The third shows per-device token
buckets.

5. Dry-run the DHCP lease sync (no real device needed yet)
--------------------------------------------------------------

From the repo root, with sync_daemon.py's LEASE_FILE pointed at a scratch
file instead of the real one (edit the constant temporarily, or copy a
fake line into the real path in a test VM):

  echo "1700000000 cc:50:e3:12:34:56 192.168.10.50 fire_node *" | sudo tee -a /var/lib/misc/dnsmasq.leases
  sudo python3 control_plane/sync_daemon.py

Expect a line like: Sync fire_node MAC cc:50:e3:12:34:56 to IP
192.168.10.50 written to kernel map. Then confirm it really landed in the
kernel with the bpftool map dump command from step 4.

6. Test the allowlist drop path (unenrolled device)
--------------------------------------------------------

From a second machine, VM, or namespace on the IoT-facing network segment,
with its real (unenrolled) MAC:

  ping -c 3 <gateway-iot-ip>

Expect no replies. On the gateway, the running daemon should print a line
like DROP, reason unknown MAC (or show it in the dashboard's live event
log).

7. Test the allowlist pass path (spoofed-but-enrolled MAC)
---------------------------------------------------------------

On the second machine, temporarily take on one of the registry's MAC
addresses and get a real lease:

  sudo ip link set <iface> down
  sudo ip link set <iface> address cc:50:e3:12:34:56
  sudo ip link set <iface> up
  sudo dhclient <iface>
  ping -c 3 <gateway-iot-ip>

Wait up to SYNC_INTERVAL_SEC (5 seconds) for the daemon to pick up the new
lease. Expect the dashboard's fire_node card to show "leased" with the new
IP, and the ping to succeed with PASS, reason ok events logged.

Change the MAC back afterwards (sudo ip link set <iface> address
<original-mac>) so you don't leave the test machine impersonating a real
node.

8. Test the rate limiter
-----------------------------

From the same spoofed-and-leased device, generate a fast burst (needs root
for flood ping):

  sudo ping -f -c 100 <gateway-iot-ip>

NORMAL_BURST is 20 packets - expect the first roughly 20 to pass, then
DROP, reason rate limited events for the rest of the burst, until the
bucket refills.

9. Run the dashboard and repeat visually
---------------------------------------------

  sudo python3 control_plane/dashboard.py

Open http://<gateway-ip>:5000 from a machine on the office network (not
the IoT subnet). Re-run steps 6 to 8 while watching: the KPI row, the
device card's pass/drop counters and online status, the drop-reason bar
chart, and the drops per second and CPU percent charts should all update
live.

10. Cleanup
----------------

Ctrl+C on either script detaches the program via its signal handler. If a
script ever gets killed uncleanly (for example, kill -9), verify and
manually clean up:

  ip link show <iface>
  sudo ip link set <iface> xdp off

The second command force-detaches a program if one is still attached.

My recommended order
-------------------------

1. Do steps 3 and 4 first, in isolation, before touching leases or traffic
   at all - a clean attach and detach is the foundation everything else
   sits on.
2. Do the dry-run lease sync (step 5) before involving a second machine -
   it isolates whether the Python-to-kernel write works from whether a
   real packet exchange works.
3. Only then bring in a second machine for steps 6 to 8, in that order
   (drop, then pass, then rate limit) - each step assumes the previous one
   already works, so debugging is easier if you don't skip ahead.
4. Keep a terminal transcript while you test (script -a test_log.txt
   before you start) - it gives you evidence to cite directly in the
   report instead of having to redo a run later for a screenshot.
5. Don't attempt the two proposal security tests yet - they need Mosquitto
   and ESP32 firmware that aren't built. Coordinate with whoever owns
   those before trying to demo them.

Troubleshooting
-------------------

ImportError, no module named bcc - the python3-bpfcc package installs
into the system Python, not a venv; run with system python3, or don't use
a virtualenv for this script.

Attach fails or permission errors - you almost certainly forgot sudo.

No events ever appear - confirm IFACE is actually the interface carrying
the traffic: sudo tcpdump -i <iface> in another terminal should show
packets while you ping.

BPF_RINGBUF_OUTPUT, ringbuf_output, or open_ring_buffer errors - your
installed bcc version may not support ring buffers; see the fallback note
(switch to BPF_PERF_OUTPUT, perf_submit, open_perf_buffer) at the top of
ebpf/xdp_filter.c.

Docker
----------

A Dockerfile and docker-compose.yml are provided to package the dashboard
and its dependencies (bcc, flask, psutil, paho-mqtt) so they don't need to
be installed on the host by hand. Read the comments in both files before
using them - a few things are non-negotiable:

- bcc compiles xdp_filter.c against the HOST's running kernel, not the
  container's. Kernel headers are bind-mounted in from the host
  (/usr/src, /lib/modules) - there is no way to bake "the right" headers
  into the image at build time, since the image doesn't know in advance
  which host it will run on.
- Attaching XDP to a real interface needs the container to see host
  interfaces directly (network_mode: host) and elevated privileges
  (privileged: true, or a narrower capability set once that's confirmed
  to work).
- dnsmasq itself is expected to run on the host, not in this container -
  its lease file is bind-mounted in read-only.

Build and run:

  docker compose up --build

I could not verify the image actually builds on this development
machine - even a bare ubuntu:24.04 container gets a 403 Forbidden from
Ubuntu's package mirrors here, while the host's own apt works fine, which
points to a pre-existing Docker networking issue on that machine, not a
problem with the Dockerfile. Try the build on the actual gateway laptop,
or check the docker-build job in CI (below), before assuming it doesn't
work.

CI pipeline
----------------

.github/workflows/ci.yml runs three jobs on every push and pull request
to main:

1. python-syntax - compiles both control_plane scripts, catches typos
   and syntax errors in seconds.
2. docker-build - builds the Docker image, to confirm it still builds as
   the code changes.
3. ebpf-verifier-check - installs bcc on the CI runner and loads
   xdp_filter.c (compile plus eBPF verifier check only, no interface
   attach), so a change that breaks verification is caught automatically.
   This job is marked continue-on-error, since eBPF program loading on a
   shared CI runner is inherently less predictable than the two jobs
   above - treat a failure here as worth investigating, not as a hard
   block on merging.

Update: ebpf-verifier-check has been confirmed failing on GitHub's own
runner, and the cause has been diagnosed precisely (not guessed) by
reproducing the exact same compile-and-load step locally and reading the
real compiler output: bcc 0.29.1's bundled clang cannot parse the actual
running kernel's own linux/bpf.h once that kernel is new enough to
contain very recent additions (struct bpf_wq, BPF_LOAD_ACQ, BPF_F_CPU,
and similar). This is not a bug in xdp_filter.c - the errors occur
inside bcc's own compilation preamble, which pulls in the real kernel's
header regardless of what this file includes, before this file's own
code is even reached. It is a genuine version gap between the bcc
package Ubuntu 24.04 ships and however new a kernel GitHub's runner
happens to be on at build time - not something a source-code change can
fix, and not under this project's control. This is exactly the class of
instability the job was marked continue-on-error for. Treat a red
ebpf-verifier-check as expected until a newer bcc package closes that
gap, and rely on python-syntax and docker-build (both reliably green) as
the real safety net.

Known limitations to state plainly in the report
------------------------------------------------------

- Fire-alert latency is a placeholder metric, not the proposal's real
  sensor-trigger-to-dashboard measurement (needs ESP32 firmware support).
- The MQTT message log is best-effort and shows nothing until Mosquitto is
  configured and running.
- The token bucket has a small race window across CPU cores (documented
  in a comment in xdp_filter.c) - acceptable for a first working version,
  but worth naming as a known limitation rather than an oversight.
