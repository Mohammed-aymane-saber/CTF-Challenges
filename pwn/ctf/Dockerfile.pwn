# ---------- Stage 1: build the vulnerable binary ----------
FROM ubuntu:22.04 AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /build
COPY vuln.c /build/vuln.c

RUN gcc -fstack-protector-all -no-pie -Wl,-z,relro,-z,now -O0 -w -o /build/vuln /build/vuln.c

# ---------- Stage 2: pwn.red/jail wrapping ubuntu rootfs ----------
FROM pwn.red/jail

# Copy a clean ubuntu:22.04 rootfs as the chroot served by jail
COPY --from=ubuntu:22.04 / /srv

# Make `/srv/...` paths inside the chroot resolve to the chroot root,
# so the binary's hard-coded `/srv/app/data` matches the bind-mount that
# docker-compose places at `/srv/app/data` on the container.
# (Inside the chroot, `/srv` becomes a symlink to `/`.)
RUN rm -rf /srv/srv && ln -s / /srv/srv

# Drop in the compiled binary as the jail's run target, plus the flag,
# and the data directory the binary writes to.
COPY --from=builder /build/vuln /srv/app/run
COPY flag.txt /srv/app/flag.txt
RUN mkdir -p /srv/app/data && \
    chown -R 1000:1000 /srv/app/run /srv/app/flag.txt /srv/app/data && \
    chmod 0755 /srv/app/run && \
    chmod 0644 /srv/app/flag.txt && \
    chmod 0777 /srv/app/data
