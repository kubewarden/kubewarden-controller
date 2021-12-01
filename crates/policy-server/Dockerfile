# build image
FROM registry.opensuse.org/opensuse/leap:15.3 as builder

RUN zypper in -y curl && \
    sh -c 'curl https://download.opensuse.org/repositories/devel:/languages:/rust/openSUSE_Leap_15.3/repodata/repomd.xml.key > gpg.key' && \
    gpg --import gpg.key && \
    rpm --import gpg.key && \
    # Now add the repository and install cargo
    zypper ar -f obs://devel:languages:rust/openSUSE_Leap_15.3 devel:languages:rust && \
    zypper ref && \
    zypper in -y gcc cargo

WORKDIR /usr/src/policy-server
COPY . .
RUN cargo install --root /usr/local/cargo --path .

# final image
FROM registry.suse.com/bci/minimal
LABEL org.opencontainers.image.source https://github.com/kubewarden/policy-server

# By default we will run as this user...
RUN echo "policy-server:x:65533:65533::/tmp:/sbin/nologin" >> /etc/passwd
# Add the default GID to /etc/group for completeness.
RUN echo "policy-server:x:65533:policy-server" >> /etc/group

COPY --from=builder /usr/local/cargo/bin/policy-server /usr/local/bin/policy-server

USER 65533:65533

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/policy-server"]
