FROM rust:1.100.0
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iperf3 iputils-ping procps \
    && rm -rf /var/lib/apt/lists/*
