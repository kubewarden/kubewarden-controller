# build image
FROM rust:1.49 as builder

WORKDIR /usr/src/policy-server
COPY . .
RUN cargo install --path .

# final image
FROM rust:1.49-slim
COPY --from=builder /usr/local/cargo/bin/policy-server /usr/local/bin/policy-server

RUN adduser \
  --disabled-password \
  --gecos "" \
  --no-create-home \
  --home "/none" \
  --shell "/sbin/nologin" \
  --uid 2000 \
  chimera
USER chimera

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/policy-server"]
