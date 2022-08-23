FROM alpine AS common
RUN echo "policy-server:x:65533:65533::/tmp:/sbin/nologin" >> /etc/passwd
RUN echo "policy-server:x:65533:policy-server" >> /etc/group

# amd64-specific
FROM scratch AS build-amd64
COPY --from=common /etc/passwd /etc/passwd
COPY --from=common /etc/group /etc/group
COPY --chmod=0755 policy-server-x86_64 /policy-server

# arm64-specific
FROM scratch AS build-arm64
COPY --from=common /etc/passwd /etc/passwd
COPY --from=common /etc/group /etc/group
COPY --chmod=0755 policy-server-aarch64 /policy-server

# common final steps
FROM build-${TARGETARCH}
USER 65533:65533
EXPOSE 3000
ENTRYPOINT ["/policy-server"]
