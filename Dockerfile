FROM rust:1.86.0-slim-bullseye as builder

ARG is_release=false
RUN apt update -y && \
    apt upgrade -y && \
    apt install -y libclang-dev protobuf-compiler build-essential

RUN apt autoremove

WORKDIR /zilliqa

RUN mkdir build

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/target \
    if [ "${is_release}" != "true" ] ; then \
    cargo build --bin zilliqa && \
    mv ./target/debug/zilliqa ./build/ ;\
    else \
    cargo build --release --bin zilliqa && \
    mv ./target/release/zilliqa ./build/ ;\
    fi


FROM ubuntu:22.04

RUN apt update -y && \
    apt install -y build-essential libev-dev libgmp-dev curl

COPY --chmod=777 ./infra/run.sh /run.sh
COPY --from=builder /zilliqa/build/zilliqa /zilliqa
COPY --from=asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/scilla:abdb24b1 /scilla/0 /scilla/0

ENTRYPOINT [ "/run.sh" ]
