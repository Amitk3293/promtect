PORT ?= 8790

.PHONY: build test lint fmt run selftest smoke coverage coverage-html docker-build docker-run docker-test provider-harness up down clean

build:
	cargo build --release

test:
	cargo test

lint:
	cargo fmt --check && cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

run:
	cargo run

selftest:
	cargo run -- selftest

smoke:
	bash scripts/smoke.sh

# Coverage targets — require `cargo install cargo-llvm-cov` on the local machine.
# CI runs these in a report-only job (never gates the build).
coverage:        ## Text coverage summary (needs: cargo install cargo-llvm-cov)
	cargo llvm-cov --summary-only

coverage-html:   ## Full HTML coverage report under target/llvm-cov/html
	cargo llvm-cov --html

docker-build:
	docker build -t promtect .

docker-run:
	docker run --rm -p 127.0.0.1:$(PORT):8790 promtect

# Docker-only test gate (fmt + clippy + cargo test). Used while GH Actions CI is capped.
docker-test:
	docker-compose -f docker-compose.test.yml run --rm test

# Credential-free provider protocol validation. Every component (Promtect,
# mock providers, and assertions) runs inside an internal Docker network.
provider-harness:
	sh tests/provider-harness/run.sh

up:
	docker-compose up -d || docker compose up -d

down:
	docker-compose down || docker compose down

clean:
	cargo clean
