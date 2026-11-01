# Sealed

Bug bounties that pay for an executed break of a committed invariant on a committed snapshot — verified inside
NEAR OutLayer, paid on NEAR. Built at the NEAR Hackathon 2026 (1–14 Nov).

Work in progress. Day-0 feasibility checks live in `day0/`; how the pieces fit: [ARCHITECTURE.md](ARCHITECTURE.md).

## Reproduce from a fresh clone (no NEAR account, no keys)

Needs `python3` ≥ 3.8 and `wasmtime` (`brew install wasmtime` or `curl https://wasmtime.dev/install.sh -sSf | bash`).
Rust is only needed to rebuild the verifier from source (`make verifier-check`).

| Command | What it shows | Network |
|---|---|---|
| `make doctor` | prerequisites present, `verifier.wasm` hash matches its pin | archival RPC ping |
| `make replay` | every published commit re-run under wasmtime from the committed wasm its bounty pinned (sha256-checked) = its on-chain verdict | none |
| `make replay INPUT=corpus/vectors/real-fallback.json` | the verdict for one tx list (yours: `{"target":0,"invariant_id":"…","txs":[…]}`) | none |
| `make verify` | each payout proven from chain data: pinned hash, attested worker key, verdict, `h_enc`, PAID | archival RPC (exit 2 = unreachable, not a failed check) |
| `make corpus` | all 52 corpus items vs their golden verdicts | none |
| `make refusals` | the 6 on-chain refusal kinds with tx hashes | none |
| `make bench` | request→verdict p50/p95, instructions / time / memory vs the enforced limits | none (`make bench-chain` re-reads the chain) |
