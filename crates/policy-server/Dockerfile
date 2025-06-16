FROM --platform=${BUILDPLATFORM} ghcr.io/cross-rs/aarch64-unknown-linux-musl:0.2.5 AS build-arm64
ARG BUILDPLATFORM
ARG TARGETPLATFORM

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --target aarch64-unknown-linux-musl  --default-toolchain stable

ENV PATH=/root/.cargo/bin:$PATH 
RUN cargo --version

WORKDIR /usr/src

RUN mkdir /usr/src/policy-server
WORKDIR /usr/src/policy-server
COPY ./ ./

RUN cargo install cargo-auditable
RUN cargo auditable install --locked --target aarch64-unknown-linux-musl --path .

FROM --platform=${BUILDPLATFORM} ghcr.io/cross-rs/x86_64-unknown-linux-musl:0.2.5 AS build-amd64
ARG BUILDPLATFORM
ARG TARGETPLATFORM

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --target x86_64-unknown-linux-musl  --default-toolchain stable

ENV PATH=/root/.cargo/bin:$PATH 
RUN cargo --version

WORKDIR /usr/src

RUN mkdir /usr/src/policy-server
WORKDIR /usr/src/policy-server
COPY ./ ./

RUN cargo install cargo-auditable
RUN cargo auditable install --locked --target x86_64-unknown-linux-musl --path .

FROM --platform=$BUILDPLATFORM alpine:3.22.0 AS cfg
RUN echo "policy-server:x:65533:65533::/tmp:/sbin/nologin" >> /etc/passwd
RUN echo "policy-server:x:65533:policy-server" >> /etc/group

FROM scratch AS copy-amd64
COPY --from=build-amd64 --chmod=0755 /root/.cargo/bin/policy-server /policy-server

FROM scratch AS copy-arm64
COPY --from=build-arm64 --chmod=0755 /root/.cargo/bin/policy-server /policy-server

# Copy the statically-linked binary into a scratch container.
FROM copy-${TARGETARCH}
COPY --from=cfg /etc/passwd /etc/passwd
COPY --from=cfg /etc/group /etc/group
COPY ./Cargo.lock /Cargo.lock
USER 65533:65533
# Default port, should be used when tls is not enabled
EXPOSE 3000
# Readiness probe port, always http
EXPOSE 8081
# To be used when tls is enabled
EXPOSE 8443
ENTRYPOINT ["/policy-server"]
