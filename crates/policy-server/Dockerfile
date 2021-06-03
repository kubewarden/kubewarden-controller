# build image
FROM registry.opensuse.org/opensuse/leap:15.3 as builder

RUN zypper in -y curl && \
    sh -c 'curl https://download.opensuse.org/repositories/devel:/languages:/rust/openSUSE_Leap_15.3/repodata/repomd.xml.key > gpg.key' && \
    gpg --import gpg.key && \
    rpm --import gpg.key && \
    # Now add the repository and install cargo
    zypper ar -f obs://devel:languages:rust/openSUSE_Leap_15.3 devel:languages:rust && \
    zypper ref && \
    zypper in -y cargo gcc libopenssl-devel

WORKDIR /usr/src/policy-server
COPY . .
RUN cargo install --root /usr/local/cargo --path .

# final image
FROM registry.opensuse.org/opensuse/leap:15.3
LABEL org.opencontainers.image.source https://github.com/kubewarden/policy-server

COPY --from=builder /usr/local/cargo/bin/policy-server /usr/local/bin/policy-server

RUN useradd \
  --system \
  --shell "/sbin/nologin" \
  --uid 2000 \
  kubewarden
USER kubewarden

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/policy-server"]
