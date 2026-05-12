FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*
COPY vuln.c /build/vuln.c
RUN gcc \
    -fno-stack-protector \
    -no-pie \
    -Wl,-z,relro,-z,now \
    -O0 \
    -w \
    -o /build/vuln /build/vuln.c

FROM pwn.red/jail

COPY --from=ubuntu:22.04 / /srv
RUN mkdir -p /srv/app

COPY --from=builder /build/vuln /srv/app/run
COPY flag.txt /srv/app/flag.txt

RUN chown 1000:1000 /srv/app/run /srv/app/flag.txt && \
    chmod 750 /srv/app/run && \
    chmod 400 /srv/app/flag.txt
