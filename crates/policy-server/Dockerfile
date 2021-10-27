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

FROM registry.suse.com/suse/sle15:latest as sle

RUN zypper download libopenssl1_1
# move rpm packages to / to strip arch from path:
RUN find /var/cache/zypp/packages/ -iname '*.rpm' -exec mv '{}' / \;

RUN useradd \
  --system \
  --shell "/sbin/nologin" \
  --uid 2000 \
  kubewarden

# final image
FROM registry.suse.com/bci/minimal
LABEL org.opencontainers.image.source https://github.com/kubewarden/policy-server

USER root

COPY --from=sle /etc/passwd /etc/passwd
COPY --from=sle /*.rpm /
COPY --from=builder /usr/local/cargo/bin/policy-server /usr/local/bin/policy-server

RUN rpm --install /*.rpm; rm -f /*.rpm

USER kubewarden

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/policy-server"]
