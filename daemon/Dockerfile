FROM ubuntu:22.04 AS base
RUN apt-get update && apt-get install -y \
    make \
    build-essential \
    libevent-dev \
    libnl-3-dev \
    libnl-genl-3-dev \
    pkg-config \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

FROM base AS ion-dtn
WORKDIR /build
ADD https://github.com/nasa-jpl/ION-DTN/archive/refs/tags/ion-open-source-4.1.3.tar.gz /build/ion-open-source-4.1.3.tar.gz
RUN tar -zxf ion-open-source-4.1.3.tar.gz
WORKDIR /build/ION-DTN-ion-open-source-4.1.3
RUN make clean && make
RUN make install

FROM base AS builder
WORKDIR /build
COPY . /build/
COPY --from=ion-dtn /usr/local/include/ /usr/local/include/
COPY --from=ion-dtn /usr/local/lib/ /usr/local/lib/
WORKDIR /build/daemon
RUN make clean && make

FROM ubuntu:22.04 AS runner
RUN apt-get update && apt-get install -y \
    libevent-2.1-7 \
    libnl-3-200 \
    libnl-genl-3-200 \
    linux-headers-generic \
    kmod \
    && rm -rf /var/lib/apt/lists/*
# RUN useradd -r -s /bin/false bpdaemon
COPY --from=builder /build/daemon/bp_daemon /usr/local/bin/
COPY --from=ion-dtn /usr/local/include/ /usr/local/include/
COPY --from=ion-dtn /usr/local/lib/ /usr/local/lib/
RUN chmod +x /usr/local/bin/bp_daemon

# USER bpdaemon

ENV LD_LIBRARY_PATH=/usr/local/lib

CMD ["/usr/local/bin/bp_daemon"]
