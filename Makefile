VERSION := $(shell git describe --tags --always --dirty)

.PHONY: build test fmt clippy clean install

build:
	cargo build --release

test:
	cargo test --all

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all -- -D warnings

clean:
	cargo clean

install:
	cargo install --path cli
