# ---- builder ----
FROM rust:1-slim-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
# Pre-build dependencies against stub sources so they cache independently of src.
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && touch src/lib.rs \
 && cargo build --release --bin airlock \
 && rm -rf src
COPY src ./src
# Bust the stub artifacts so our real code recompiles (deps stay cached).
RUN touch src/main.rs src/lib.rs && cargo build --release --bin airlock

# ---- runtime (distroless, non-root, has CA roots + glibc) ----
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /build/target/release/airlock /usr/local/bin/airlock
ENV AIRLOCK_BIND=0.0.0.0 \
    AIRLOCK_PORT=8787 \
    AIRLOCK_UPSTREAM=https://api.anthropic.com \
    AIRLOCK_AUDIT=/home/nonroot/airlock-audit.jsonl
EXPOSE 8787
USER nonroot
ENTRYPOINT ["/usr/local/bin/airlock"]
