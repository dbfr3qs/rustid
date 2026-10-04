# rustid-server as one static binary on scratch. Configure it with RUSTID_*
# variables, or mount a configuration file and set RUSTID_CONFIG to its path.
# Keys made by key management and the generated data protection key live in
# /var/lib/rustid; mount a volume there to keep them.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev cmake perl clang make ca-certificates
WORKDIR /src
COPY . .
# The image's toolchain builds; rust-toolchain.toml would download another.
RUN rm -f rust-toolchain.toml
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p rustid-server \
 && cp target/release/rustid-server /rustid-server
RUN mkdir -p /out/var/lib/rustid

# The bare executable, for release archives:
#   docker buildx build --target binary --output type=local,dest=out .
FROM scratch AS binary
COPY --from=build /rustid-server /rustid-server

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/ /
COPY --from=build /rustid-server /rustid-server
USER 65532:65532
WORKDIR /var/lib/rustid
ENV RUSTID_LISTEN=0.0.0.0:8080 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=6s --start-period=10s --retries=3 \
  CMD ["/rustid-server", "--probe", "http://127.0.0.1:8080/ready"]
ENTRYPOINT ["/rustid-server"]
