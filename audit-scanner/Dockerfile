# Build the audit-scanner binary
FROM golang:1.25 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY *.go ./
COPY cmd/ cmd/
COPY internal/ internal/

# Build
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -o audit-scanner .

FROM alpine AS cfg
RUN echo "audit-scanner:x:65533:65533::/tmp:/sbin/nologin" >> /etc/passwd
RUN echo "audit-scanner:x:65533:audit-scanner" >> /etc/group

# Copy the statically-linked binary into a scratch container.
FROM scratch
COPY --from=cfg /etc/passwd /etc/passwd
COPY --from=cfg /etc/group /etc/group
COPY --from=builder --chmod=0755 /workspace/audit-scanner /audit-scanner
USER 65532:65532
ENTRYPOINT ["/audit-scanner"]
