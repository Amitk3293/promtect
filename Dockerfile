# ---- builder ----
FROM rust:1.96.0-slim-bookworm@sha256:4732ca96fd086cb9be682050c3f0176288eebaac2b80aa2bcefccfaf198e1950 AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
# Pre-build dependencies against stub sources so they cache independently of src.
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && touch src/lib.rs \
 && cargo build --release --bin promtect \
 && rm -rf src
COPY src ./src
COPY assets ./assets
# Bust the stub artifacts so our real code recompiles (deps stay cached).
RUN touch src/main.rs src/lib.rs && cargo build --release --bin promtect

# ---- runtime (distroless, non-root, has CA roots + glibc) ----
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:ce0d66bc0f64aae46e6a03add867b07f42cc7b8799c949c2e898057b7f75a151
COPY --from=builder /build/target/release/promtect /usr/local/bin/promtect
ENV PROMTECT_BIND=0.0.0.0 \
    PROMTECT_ALLOW_PUBLIC_BIND=1 \
    PROMTECT_PORT=8790 \
    PROMTECT_UPSTREAM=https://api.anthropic.com \
    PROMTECT_AUDIT=/home/nonroot/promtect-audit.jsonl
EXPOSE 8790
USER nonroot
ENTRYPOINT ["/usr/local/bin/promtect"]
