# Sealed Exploit — every judged command is a make target. See DEMO.md for expected output.
SHELL := /bin/bash
CARGO_HOME ?= $(HOME)/.cargo
# Absolute build paths end up in panic-location strings; remap them so any clone rebuilds the same bytes.
REMAP := --remap-path-prefix=$(CARGO_HOME)=/cargo --remap-path-prefix=$(CURDIR)=/sealed
WASM := target/wasm32-wasip1/release/verifier.wasm

.PHONY: verifier-wasm verifier-check test test-verifier test-contracts contracts-wasm

## Rebuild verifier.wasm from source and write its sha256 (the hash every bounty pins).
verifier-wasm:
	RUSTFLAGS="$(REMAP)" cargo build --locked --release --target wasm32-wasip1 -p verifier
	cp $(WASM) verifier.wasm
	shasum -a 256 verifier.wasm > verifier.wasm.sha256
	@cat verifier.wasm.sha256

## Rebuild from source and fail unless the bytes equal the committed verifier.wasm.
verifier-check:
	RUSTFLAGS="$(REMAP)" cargo build --locked --release --target wasm32-wasip1 -p verifier
	@shasum -a 256 -c <(sed 's#verifier.wasm#$(WASM)#' verifier.wasm.sha256)

test: test-verifier test-contracts

## Golden verdicts (native) + the committed verifier.wasm under wasmtime must print the same verdict bytes.
test-verifier:
	cargo test --locked --release -p verifier

# ----- contracts (bounty / test token) -----
## Build the contract wasms (Rust 1.85.0, near-sys 0.2.4 pinned) and wasm-opt -Oz the bounty.
contracts-wasm:
	cd contracts && cargo +1.85.0 build --locked --target wasm32-unknown-unknown --release
	wasm-opt -Oz contracts/target/wasm32-unknown-unknown/release/bounty.wasm -o contracts/bounty.wasm
	shasum -a 256 contracts/bounty.wasm

## near-workspaces sandbox tests for the bounty (I1–I8). Needs the wasms built first.
test-contracts: contracts-wasm
	cd contracts/itests && cargo test --test bounty -- --test-threads=4
