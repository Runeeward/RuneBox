# runebox control plane, MCP server, and Kubernetes controller (one binary).

# runebox from the Rust workspace. Built natively for the target platform
# (no --platform=$BUILDPLATFORM: the Alpine/musl toolchain links a static
# binary for the distroless runtime below without a cross linker; the
# release workflow builds each architecture on a native runner). TLS is
# rustls with ring; no OpenSSL or aws-lc.
FROM rust:1.99-alpine@sha256:b1d5dd5a22a09404d3e798c0cf051b689077360374eb505fa5bb93c479693d87 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Embedded at compile time: the web dashboard. (The Kubernetes manifests
# live in crates/runebox-k8s/manifests.)
COPY web ./web
# Stamped into `runebox version` by crates/runebox-cli/build.rs.
ARG VERSION=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    RUNEBOX_VERSION="${VERSION#v}" \
    cargo build --release --locked -p runebox-cli --bin runebox \
    && install -D -m 0755 target/release/runebox /out/runebox

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
LABEL org.opencontainers.image.source="https://github.com/Runeeward/RuneBox"
LABEL org.opencontainers.image.description="Rune Box: an environment where your agent can roam freely but with receipts"
# MCP registry OCI ownership check: the value MUST equal the server.json "name".
LABEL io.modelcontextprotocol.server.name="io.github.Runeeward/runebox"
COPY --from=build /out/runebox /usr/local/bin/runebox
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/runebox"]
CMD ["serve", "--port", "8080"]
