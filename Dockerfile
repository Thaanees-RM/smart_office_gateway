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
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3-bpfcc \
        bpfcc-tools \
        bpftool \
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
