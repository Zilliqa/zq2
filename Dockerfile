FROM rust:1.78.0-slim-bullseye as builder

ARG is_ci=false
RUN apt update -y && \
    apt upgrade -y && \
    apt install -y protobuf-compiler

RUN apt autoremove

WORKDIR /zilliqa

RUN mkdir build

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/target \
    if [ "${is_ci}" != "true " ] ; then \
    cargo build --bin zilliqa && \
    mv ./target/debug/zilliqa ./build/ ;\
    fi

RUN if [ "${is_ci}" == "true " ]; then \
    cargo test --release --all-targets --all-features ;\
    fi

RUN if [ "${is_ci}" == "true " ]; then \
    cargo build --release --bin zilliqa && \
    mv ./target/release/zilliqa ./build/ ;\
    fi

FROM ubuntu:22.04

RUN apt update -y && \
    apt install -y build-essential libev-dev libgmp-dev

COPY --chmod=777 ./infra/run.sh /run.sh
COPY --from=builder /zilliqa/build/zilliqa /zilliqa
COPY --from=asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa-public/scilla:a5a81f72 /scilla/0 /scilla/0

ENTRYPOINT [ "/run.sh" ]
