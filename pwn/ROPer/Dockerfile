# ── Stage 1: compile ──────────────────────────────────────────────────────────
FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y gcc && \
    rm -rf /var/lib/apt/lists/*

COPY vuln.c /build/vuln.c

RUN gcc \
    -fno-stack-protector \
    -no-pie \
    -Wl,-z,relro,-z,now \
    -O0 \
    -w \
    -o /build/vuln /build/vuln.c

# ── Stage 2: nsjail ───────────────────────────────────────────────────────────
FROM pwn.red/jail

# Full Ubuntu 22.04 rootfs gives us glibc, /dev/urandom, etc.
COPY --from=ubuntu:22.04 / /srv
RUN mkdir -p /srv/app

# Binary and flag
COPY --from=builder /build/vuln /srv/app/run
COPY flag.txt /srv/app/flag.txt

# uid 1000 owns the binary (read+exec) and the flag (read-only)
# The flag is opened BEFORE seccomp is installed, so no open() is
# needed (or allowed) after the program starts.
RUN chown 1000:1000 /srv/app/run /srv/app/flag.txt && \
    chmod 750 /srv/app/run && \
    chmod 400 /srv/app/flag.txt
