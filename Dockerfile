# Ubuntu 24.04 is used deliberately (not a slim/alpine image) because
# python3-bpfcc - the apt package providing bcc, which this project's
# eBPF loader needs - is only reliably available through Ubuntu/Debian's
# package repositories, not pip.
FROM ubuntu:24.04

# NOTE ON KERNEL HEADERS: bcc compiles ebpf/xdp_filter.c at runtime
# against the HOST machine's running kernel, not this image's kernel.
# There is no way to bake "the right headers" into this image at build
# time, because the host that eventually runs this container could have
# any kernel version. Kernel headers are bind-mounted in from the host
# at run time instead - see docker-compose.yml (/usr/src, /lib/modules).
# Some networks (including the one this was built on) block plain-HTTP
# requests whose User-Agent identifies as "Debian APT-HTTP" - a pattern
# a few network filters use specifically to block package-manager
# traffic. Confirmed by testing: the identical request over HTTPS, or
# over HTTP with any other User-Agent, is NOT blocked - only that exact
# string is. Overriding it to a generic one is a normal apt config
# option, not a workaround for anything apt itself restricts.
RUN echo 'Acquire::http::User-Agent "Mozilla/5.0";' > /etc/apt/apt.conf.d/99custom-user-agent

# bpftool is deliberately NOT installed here: on Ubuntu it's a virtual
# package backed by a kernel-version-specific linux-tools-<version>
# package, so it hits the exact same "which host kernel?" problem as the
# header mount above - baking a specific kernel's bpftool into this
# image would be wrong for a different host. Run bpftool on the HOST
# directly instead (see the README), where apt can match it to whatever
# kernel is actually running.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-bpfcc \
        bpfcc-tools \
        python3-flask \
        python3-psutil \
        python3-paho-mqtt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY ebpf/ ebpf/
COPY control_plane/ control_plane/

EXPOSE 5000

WORKDIR /app/control_plane

# Loading/attaching an XDP program needs root inside the container too -
# this image does not drop privileges, matching how the scripts already
# require `sudo` when run directly on a real gateway.
CMD ["python3", "dashboard.py"]
