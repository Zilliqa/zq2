FROM rust:1.69.0-slim-bullseye as builder

RUN apt update -y && \
    apt upgrade -y && \
    apt install -y protobuf-compiler

RUN apt autoremove

RUN mkdir build

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/target \
    cargo build --bin zilliqa && \
    mv /target/debug/zilliqa /build/


FROM gcr.io/distroless/cc-debian11

COPY --from=builder /build/zilliqa /zilliqa
