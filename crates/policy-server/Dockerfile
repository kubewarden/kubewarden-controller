FROM rust:1.70 AS build
WORKDIR /usr/src

# Download the target for static linking.
RUN rustup target add $(arch)-unknown-linux-musl

# Fix ring building using musl - see https://github.com/briansmith/ring/issues/1414#issuecomment-1055177218
RUN apt-get update && apt-get install musl-tools clang llvm -y
ENV CC="clang"

RUN mkdir /usr/src/policy-server
WORKDIR /usr/src/policy-server
COPY ./ ./
RUN cargo install --target $(arch)-unknown-linux-musl --path .

FROM alpine AS cfg
RUN echo "policy-server:x:65533:65533::/tmp:/sbin/nologin" >> /etc/passwd
RUN echo "policy-server:x:65533:policy-server" >> /etc/group

# Copy the statically-linked binary into a scratch container.
FROM scratch
COPY --from=cfg /etc/passwd /etc/passwd
COPY --from=cfg /etc/group /etc/group
COPY --from=build --chmod=0755 /usr/local/cargo/bin/policy-server /policy-server
USER 65533:65533
EXPOSE 3000
ENTRYPOINT ["/policy-server"]
