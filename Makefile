PORT ?= 8787

.PHONY: build test lint fmt run selftest smoke docker-build docker-run up down clean

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

docker-build:
	docker build -t airlock-ai .

docker-run:
	docker run --rm -p 127.0.0.1:$(PORT):8787 airlock-ai

up:
	docker-compose up -d || docker compose up -d

down:
	docker-compose down || docker compose down

clean:
	cargo clean
