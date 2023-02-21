FROM rust:1.67.1-slim-buster as build-env

RUN apt update -y && \
    apt upgrade -y && \
    apt install -y protobuf-compiler

RUN apt autoremove

COPY . .

RUN cargo build --release --bin zilliqa


FROM rust:1.67.1-slim-buster

RUN apt update -y && \
    apt upgrade -y

RUN apt autoremove

COPY --from=build-env /target/release/zilliqa /zilliqa


