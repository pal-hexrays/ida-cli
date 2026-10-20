# Linux target for icli's debugger tests: gcc to build test programs; IDA's
# armlinux_server/linux_server is mounted from the local IDA installation.
FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc libc6-dev >/dev/null \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /w
