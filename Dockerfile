FROM ubuntu:22.04 AS build
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential libsctp-dev libssl-dev libyaml-dev pkg-config git && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /work
COPY . /work
RUN make -C /work clean && make -C /work

FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libsctp1 libssl3 libyaml-0-2 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN mkdir -p /config
COPY --from=build /work/build/s1n2-converter /usr/local/bin/s1n2-converter
ENV S1C_BIND_ADDR=0.0.0.0 \
    S1C_PORT=36412 \
    S1U_BIND_ADDR=0.0.0.0 \
    S1U_PORT=2152 \
    N2_REMOTE_ADDR=amf \
    N2_REMOTE_PORT=38412 \
    N3_REMOTE_ADDR=upf \
    N3_REMOTE_PORT=2152
ENTRYPOINT ["/usr/local/bin/s1n2-converter"]


