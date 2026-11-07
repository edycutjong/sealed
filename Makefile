# Sealed Exploit — every judged command is a make target. See DEMO.md for expected output.
SHELL := /bin/bash
CARGO_HOME ?= $(HOME)/.cargo
# Absolute build paths end up in panic-location strings; remap them so any clone on the same host OS rebuilds the same bytes.
REMAP := --remap-path-prefix=$(CARGO_HOME)=/cargo --remap-path-prefix=$(CURDIR)=/sealed
WASM := target/wasm32-wasip1/release/verifier.wasm

.PHONY: verifier-wasm verifier-check test test-py test-py-cov test-verifier test-contracts contracts-build contracts-wasm cov

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

test: test-py test-verifier test-contracts

## Python unit tests for every script (no network: tests/python/conftest.py blocks sockets).
test-py:
	python3 -m pytest

## The same with CI's 100% line-coverage gate (pip install pytest pytest-cov pynacl base58).
test-py-cov:
	python3 -m pytest --cov=scripts --cov=near --cov-report=term-missing --cov-fail-under=100

## Line coverage: Python (pytest-cov, gate 100%), verifier and contracts (cargo-llvm-cov: `cargo install cargo-llvm-cov`).
cov:
	python3 -m pytest --cov=scripts --cov=near --cov-report=term-missing --cov-fail-under=100
	cargo llvm-cov --package verifier --summary-only
	cd contracts && cargo +1.97.1 llvm-cov --locked -p bounty -p test-token -p mock-outlayer -p mock-token --summary-only

## Golden verdicts (native) + the committed verifier.wasm under wasmtime must print the same verdict bytes.
test-verifier:
	cargo test --locked --release -p verifier

# ----- contracts (bounty / test token) -----
## Compile the contract wasms (Rust 1.85.0, near-sys 0.2.4 pinned) into contracts/target/: what the sandbox tests deploy.
## Paths are remapped so the public wasm carries no build-machine fingerprints and any clone on the same host OS rebuilds the same bytes.
contracts-build:
	cd contracts && RUSTFLAGS="--remap-path-prefix=$(CARGO_HOME)=/cargo --remap-path-prefix=$(CURDIR)/contracts=/sealed-contracts" cargo +1.85.0 build --locked --target wasm32-unknown-unknown --release

## contracts-build, then wasm-opt -Oz into the committed contracts/bounty.wasm / test-token.wasm (the deployed bytes, which
## `make verify-demo` hashes). They rebuild byte-identically only on the pin host OS (a Linux build differs), so `make test`
## depends on contracts-build and never rewrites them; run this target only to re-derive the deployed wasm.
contracts-wasm: contracts-build
	wasm-opt -Oz contracts/target/wasm32-unknown-unknown/release/bounty.wasm -o contracts/bounty.wasm
	wasm-opt -Oz contracts/target/wasm32-unknown-unknown/release/test_token.wasm -o contracts/test-token.wasm
	@echo -n "paths leaked: "; cat contracts/bounty.wasm contracts/test-token.wasm | strings | grep -c '/Users/' || true
	shasum -a 256 contracts/bounty.wasm contracts/test-token.wasm

## Contract unit tests (native host) + near-workspaces sandbox tests for the bounty (I1–I8). The wasm the
## worker/judge runs is built on 1.85.0 (near-sys 0.2.4); the native unit tests use a newer toolchain only
## because near-sdk's `unit-testing` feature pulls deps that require rustc ≥ 1.88 — it never touches the wasm.
test-contracts: contracts-build
	cd contracts && cargo +1.97.1 test --locked -p bounty -p test-token -p mock-outlayer -p mock-token
	cd contracts/itests && cargo test --test bounty -- --test-threads=4

# ----- replay / verify (judge-facing; see DEMO.md) -----
## Fresh-clone preflight: python3 + wasmtime + the committed verifier.wasm hash + archival RPC reachability.
doctor:
	@python3 scripts/doctor.py $(RPC)

# Archival RPC for `make verify` CHAIN-CHECKED lines. Both the NEAR Foundation and FastNEAR archival nodes
# serve testnet history; the Foundation node rate-limits shared IPs, so FastNEAR is the default. Override:
#   make verify RPC=https://archival-rpc.testnet.near.org
RPC ?= https://archival-rpc.testnet.fastnear.com

## Re-run every published commit (corpus/published/) under wasmtime from the committed verifier.wasm — no
## NEAR credentials, no network, no Rust. `make replay INPUT=<file>` runs a judge's own tx list instead.
## Preconditions: wasmtime + python3 only (the sha256 of verifier.wasm is checked against each pinned hash).
replay:
	@python3 scripts/verify_offline.py $(INPUT)

## Open every paid delivery offline (exactly the Paid runs in corpus/results.json): verdict broken for this commit,
## AWARDED/DELIVERED/PAID logged for it, sha256(enc) = h_enc, the box opens (published EPH_SK, the same shared key the
## protocol's own key gives) to the exact exploit `make replay` re-runs, and it hashes to the commit.
## Needs PyNaCl (pip install pynacl); no network, no NEAR credentials.
open:
	@python3 scripts/open_deliveries.py

## Prove every payout from chain data: each commit's request pinned the verifier hash, the operator's scoped
## OutLayer worker key answered, the logged verdict matches, and (paid) sha256(enc)=h_enc and PAID fired. Re-fetches
## every bundled tx from the archival RPC → CHAIN-CHECKED; unreachable network → bundle only (RECORDED).
## verify.py exits 1 on a failed check and 2 on RECORDED; through make both stop with "Error 1" / "Error 2"
## (make's own status is 2 either way), so run `python3 scripts/verify.py` when a script needs the raw code.
verify:
	@python3 scripts/verify.py --rpc $(RPC)

## Quick path (~25 RPC calls instead of ~80): the 5 paid lines of the D5 demo bounty, with the same checks, its
## completeness and its ledger, and FAIL unless it is keyless on the committed bounty.wasm's global code hash and its
## create tx added no key (I6).
## Use it when a full `make verify` would outlast a command timeout.
verify-demo:
	@python3 scripts/verify.py --rpc $(RPC) --require-keyless --bounty demo.sealed-dev-11010702.testnet

## The D5 production bounties only (demo = 5 levels paid, corpus = fakes + expiry), and FAIL unless each is keyless
## on the global code hash of the committed contracts/bounty.wasm, created with no key (0 access keys for life). `make verify` above also covers the keyed D3 throwaway.
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

## Latency p50/p95 + verifier instructions/time/memory vs the enforced limits, recomputed from the evidence bundles
## (OutLayer's on-chain event timestamps + resolve args) and checked against corpus/bench.json. No network.
bench:
	@python3 scripts/bench.py

## Same, plus re-read every resolve_execution tx and block header from the archival RPC (block-time commit→verdict,
## commit→PAID, deliver→PAID). Paced for the public nodes' rate limit (~3–4 min); exit 2 if the RPC is unreachable.
bench-chain:
	@python3 scripts/bench.py --chain --rpc $(RPC)

.PHONY: doctor replay open verify verify-demo verify-d5 corpus refusals results bench bench-chain

# ----- baseline / hunter agent (D6) -----
## The mirror image of `make replay`: the same corpus judged by an LLM that cannot execute anything. Prints, per recorded
## model, how many fakes it would pay (baseline/run.json, raw replies in baseline/transcripts/). `make baseline MODEL=<id>`
## re-runs it live on NEAR AI Cloud when ~/.config/near-ai-cloud/api.key exists and adds that model to the record
## (the record holds one NEAR AI Cloud model and three other providers, see baseline/README.md).
MODEL ?=
baseline:
ifeq ($(MODEL),)
	@python3 scripts/baseline.py show
else
	python3 scripts/baseline.py record --provider nearai --model $(MODEL)
endif

.PHONY: baseline

# ----- CI stages, runnable locally (mirrors .github/workflows/ci.yml; its advisory Lighthouse step is `make lighthouse`) -----
lint:
	cargo clippy --locked -p verifier --all-targets -- -A clippy::all -D clippy::correctness -D clippy::suspicious
	cd contracts && cargo +1.97.1 clippy --locked -p bounty -- -A clippy::all -D clippy::correctness -D clippy::suspicious
	ruff check .

security-scan:
	gitleaks detect --source . --config .gitleaks.toml --log-opts="--all" --redact
	python3 scripts/check_submission_readiness.py
	-for d in . contracts contracts/itests; do (cd $$d && cargo audit); done

e2e-site:
	python3 scripts/site_check.py --live https://sealed.edycu.dev

perf:
	python3 scripts/perf_gate.py

lighthouse:
	npx --yes @lhci/cli@0.14.0 autorun

ci: lint security-scan test-py-cov test-verifier verifier-check test-contracts replay corpus refusals open verify-demo e2e-site bench perf

.PHONY: lint security-scan e2e-site perf lighthouse ci
