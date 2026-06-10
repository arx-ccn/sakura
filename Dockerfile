# syntax=docker/dockerfile:1
#
# Smallest-possible image for sakura: the server is dependency-free and links
# fully static, so the final stage is `FROM scratch` — no base OS, no libc, no
# shell. Just the ~1.3 MB stripped binary and an empty /data.
#
#   docker build -t sakura .
#   docker run --rm -p 3000:3000 -v sakura-data:/data sakura
#
# Override the toolchain version with --build-arg ODIN_VERSION=dev-2026-05.

# ---- build stage: fetch the Odin toolchain and produce a static binary ----
FROM debian:bookworm-slim AS build
ARG ODIN_VERSION=dev-2026-05
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl clang lld libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/odin
RUN curl -fsSL -o /tmp/odin.tar.gz \
        "https://github.com/odin-lang/Odin/releases/download/${ODIN_VERSION}/odin-linux-amd64-${ODIN_VERSION}.tar.gz" \
    && tar xzf /tmp/odin.tar.gz -C /opt/odin --strip-components=1 \
    && rm /tmp/odin.tar.gz
ENV PATH="/opt/odin:${PATH}"

WORKDIR /src
COPY . .
# Fully static link so the binary needs nothing at runtime.
RUN odin build . -out:/tmp/sakura -o:speed -extra-linker-flags:"-static" \
    && strip /tmp/sakura \
    && /tmp/sakura --selftest

# ---- prep stage: an empty, correctly-owned /data (scratch has no mkdir) ----
FROM busybox:latest AS prep
RUN mkdir -p /data

# ---- final stage: nothing but the binary ----
FROM scratch
COPY --from=prep --chown=65532:65532 /data /data
COPY --from=build /tmp/sakura /sakura

ENV SAKURA_HOST=0.0.0.0 \
    SAKURA_PORT=3000 \
    SAKURA_DATA=/data
EXPOSE 3000
VOLUME ["/data"]
USER 65532:65532
ENTRYPOINT ["/sakura"]
