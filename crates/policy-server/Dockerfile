FROM rust:1.80-alpine AS build
WORKDIR /usr/src

RUN apk add --no-cache musl-dev make 

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
ADD Cargo.lock /Cargo.lock
USER 65533:65533
EXPOSE 3000
ENTRYPOINT ["/policy-server"]
