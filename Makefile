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
## Build the contract wasms (Rust 1.85.0, near-sys 0.2.4 pinned) and wasm-opt -Oz the bounty. Paths are
## remapped so the public wasm carries no build-machine fingerprints and any clone rebuilds the same bytes.
contracts-wasm:
	cd contracts && RUSTFLAGS="--remap-path-prefix=$(CARGO_HOME)=/cargo --remap-path-prefix=$(CURDIR)/contracts=/sealed-contracts" cargo +1.85.0 build --locked --target wasm32-unknown-unknown --release
	wasm-opt -Oz contracts/target/wasm32-unknown-unknown/release/bounty.wasm -o contracts/bounty.wasm
	wasm-opt -Oz contracts/target/wasm32-unknown-unknown/release/test_token.wasm -o contracts/test-token.wasm
	@echo -n "paths leaked: "; cat contracts/bounty.wasm contracts/test-token.wasm | strings | grep -c '/Users/' || true
	shasum -a 256 contracts/bounty.wasm contracts/test-token.wasm

## Contract unit tests (native host) + near-workspaces sandbox tests for the bounty (I1–I8). The wasm the
## worker/judge runs is built on 1.85.0 (near-sys 0.2.4); the native unit tests use a newer toolchain only
## because near-sdk's `unit-testing` feature pulls deps that require rustc ≥ 1.88 — it never touches the wasm.
test-contracts: contracts-wasm
	cd contracts && cargo +1.97.1 test -p bounty
	cd contracts/itests && cargo test --test bounty -- --test-threads=4

# ----- replay / verify (judge-facing; see DEMO.md) -----
# Archival RPC for `make verify` CHAIN-CHECKED lines. Both the NEAR Foundation and FastNEAR archival nodes
# serve testnet history; the Foundation node rate-limits shared IPs, so FastNEAR is the default. Override:
#   make verify RPC=https://archival-rpc.testnet.near.org
RPC ?= https://archival-rpc.testnet.fastnear.com

## Re-run every published commit (corpus/published/) under wasmtime from the committed verifier.wasm — no
## NEAR credentials, no network, no Rust. `make replay INPUT=<file>` runs a judge's own tx list instead.
## Preconditions: wasmtime + python3 only (the sha256 of verifier.wasm is checked against each pinned hash).
replay:
	@python3 scripts/verify_offline.py $(INPUT)

## Prove every payout from chain data: each commit's request pinned the verifier hash, an attested OutLayer
## worker key answered, the logged verdict matches, and (paid) sha256(enc)=h_enc and PAID fired. Re-fetches
## every bundled tx from the archival RPC → CHAIN-CHECKED; unreachable network → bundle only (RECORDED, exit 2).
verify:
	@python3 scripts/verify.py --rpc $(RPC)

## The D5 production bounties only (demo = 5 levels paid, corpus = fakes + expiry), and FAIL unless each is keyless
## on the global-contract hash (0 access keys for life). `make verify` above also covers the keyed D3 throwaway.
D5_BOUNTIES := demo.sealed-dev-11010702.testnet corpus.sealed-dev-11010702.testnet
verify-d5:
	@python3 scripts/verify.py --rpc $(RPC) --require-keyless $(addprefix --bounty ,$(D5_BOUNTIES))

## Every corpus item (real, near-miss, wrong snapshot, malformed, abuse, LLM-written) under wasmtime from the
## committed verifier.wasm, against its golden + designed verdict. No credentials, no network, no Rust.
corpus:
	@python3 scripts/corpus_check.py

## The 6 on-chain refusal kinds with their testnet tx hash and the bounty's log line (corpus/refusals.json).
refusals:
	@python3 scripts/refusals.py

## Rebuild corpus/results.json (every testnet tx hash + summary counts) from the committed evidence; no network.
results:
	@python3 scripts/results.py

.PHONY: replay verify verify-d5 corpus refusals results
