FROM rust:1.75.0-slim-bullseye as builder

RUN apt update -y && \
    apt upgrade -y && \
    apt install -y protobuf-compiler

RUN apt autoremove

WORKDIR /zilliqa

RUN mkdir build

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/target \
    cargo build --bin zilliqa && \
    mv ./target/debug/zilliqa ./build/


FROM ubuntu:22.04

RUN apt update -y && \
    apt install -y build-essential libev-dev libgmp-dev

COPY --chmod=777 ./infra/run.sh /run.sh
COPY --from=builder /zilliqa/build/zilliqa /zilliqa
COPY --from=asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/scilla:a5a81f72 /scilla/0 /scilla/0

ENTRYPOINT [ "/run.sh" ]
