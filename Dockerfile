# syntax=docker/dockerfile:1.7

FROM rust:1-bookworm AS builder

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends libclang-dev clang \
    && rm -rf /var/lib/apt/lists/*

COPY . .

ARG CARGO_PROFILE=prod
ARG CARGO_BIN_DIR=prod

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/target \
    cargo build --locked --package fastroll --profile "${CARGO_PROFILE}" --features "tiny,fuzz" \
    && cp "target/${CARGO_BIN_DIR}/fastroll" /usr/local/bin/fastroll-tiny \
    && cargo build --locked --package fastroll --profile "${CARGO_PROFILE}" --features "full,fuzz" \
    && cp "target/${CARGO_BIN_DIR}/fastroll" /usr/local/bin/fastroll-full

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/fastroll-tiny /usr/local/bin/fastroll-tiny
COPY --from=builder /usr/local/bin/fastroll-full /usr/local/bin/fastroll-full
COPY docker/entrypoint.sh /usr/local/bin/fastroll-entrypoint

RUN chmod 0755 /usr/local/bin/fastroll-tiny \
    /usr/local/bin/fastroll-full \
    /usr/local/bin/fastroll-entrypoint

ENTRYPOINT ["/usr/local/bin/fastroll-entrypoint"]
CMD ["--help"]
