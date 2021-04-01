# build image
FROM rust:1.50-buster as builder

WORKDIR /usr/src/policy-server
COPY . .
RUN cargo install --path .

# final image
FROM debian:buster-slim
COPY --from=builder /usr/local/cargo/bin/policy-server /usr/local/bin/policy-server

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN adduser \
  --disabled-password \
  --gecos "" \
  --no-create-home \
  --home "/none" \
  --shell "/sbin/nologin" \
  --uid 2000 \
  kubewarden
USER kubewarden

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/policy-server"]
