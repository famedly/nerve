FROM rust:1.93-alpine AS builder
# pinned to 1.93 due to https://github.com/matrix-org/matrix-rust-sdk/issues/6254

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY . .

RUN cargo build --release --target $(uname -m)-unknown-linux-musl && \
    strip -o nerve target/$(uname -m)-unknown-linux-musl/release/nerve

RUN cargo build --release --target $(uname -m)-unknown-linux-musl -p datapoint && \
    strip -o datapoint target/$(uname -m)-unknown-linux-musl/release/datapoint

FROM scratch AS nerve

COPY --from=builder /build/nerve /nerve
COPY --from=builder /build/datapoint /datapoint

ENTRYPOINT ["/nerve"]
