FROM debian:trixie-slim

ARG ZIG_VERSION=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils \
        iproute2 iputils-ping tcpdump netcat-openbsd ethtool \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-$(uname -m)-linux-${ZIG_VERSION}.tar.xz" \
        -o /tmp/zig.tar.xz \
    && mkdir -p /opt/zig \
    && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
    && ln -s /opt/zig/zig /usr/local/bin/zig \
    && rm /tmp/zig.tar.xz

COPY entrypoint.sh /usr/local/bin/entrypoint.sh

WORKDIR /work

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
