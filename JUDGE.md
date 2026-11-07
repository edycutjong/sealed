# JUDGE.md — Sealed, for the judges

Machine-readable companion for the NEAR Hackathon 2026 AI judges (Claude Code + Codex) and the
human jury. It is a short index to the evidence; the authority is [README.md](README.md),
[DEMO.md](DEMO.md) and [ARCHITECTURE.md](ARCHITECTURE.md), and every number below is reproducible
from a fresh clone of this repo with no NEAR account or key. Testnet only. A styled web version
(source `docs/judge/index.html`) is live at https://sealed.edycu.dev/judge/.

## 1. One-sentence claim

Sealed is a bug bounty that pays for an *executed* break of a committed invariant on a committed
snapshot — the exploit is run by the pinned verifier in a NEAR OutLayer TEE worker (Intel TDX per OutLayer's
docs; this repo checks the worker key, not the quote) and paid on NEAR — and on testnet the
executing verifier paid **5 of 5** real Ethernaut exploits and **0 of 21** submitted fakes.

## 2. Two-command path (do X → see Y)

From a fresh clone with `python3` and `wasmtime`, no account or key:

```bash
make replay        # offline: re-runs 29 published commits under wasmtime → "replay: 29 OK · 0 FAIL", printing validateInstance = 1 (real break) or 0 (fake); the 4 malformed inputs print "no validateInstance call"
make verify-demo   # from chain data, about 25 archival RPC calls (about 1.5 min): the 5 paid demo-bounty runs → "checks: 5 PASS · 5 CHAIN-CHECKED · 0 RECORDED"
```

`make replay` is offline and deterministic; `make verify-demo` reads the public chain. Through `make`, `Error 2` means
the archival RPC was unreachable or rate-limited (re-run it, or pass `RPC=https://archival-rpc.testnet.near.org`),
never a pass; `Error 1` is a failed check. Then `make open` (offline, needs PyNaCl) opens the 6 paid deliveries →
"open: 6 of 6 paid runs (corpus/results.json) open to the exploit their verdict and payout name", and `make verify`
re-checks all 29 runs from chain data (about 80 calls, a few minutes on a rate-limited node).

One edit flips a verdict: `make replay INPUT=corpus/vectors/real-fallback.json` prints `validateInstance … → 1`
(`"broken": true`); `make replay INPUT=corpus/vectors/nearmiss-fallback-no-receive.json`, the same exploit minus its
1-wei send to `receive()`, prints `→ 0`. Your own tx list works the same way (README § Reproduce). Full script in
[DEMO.md](DEMO.md).

## 3. Receipt block (on-chain, testnet)

| Item | Value |
|---|---|
| Real exploits paid / submitted | **5 of 5** (demo bounty) — `corpus/results.json` |
| Non-breaking submissions paid | **0 of 21** (21 of 21 refused) — `corpus/results.json` |
| Testnet runs | 29 = 5 paid (demo bounty) + 22 on the corpus bounty (the 21 refused + 1 real break awarded, never delivered, expired) + 2 on the earlier keyed D3 bounty (1 paid, 1 refused); 6 paid deliveries = 5 demo + 1 D3 — `corpus/results.json` |
| Demo bounty (keyless) | `demo.sealed-dev-11010702.testnet` |
| Corpus bounty (fakes) | `corpus.sealed-dev-11010702.testnet` |
| Global code hash | `7HtmeswBuR9JLCcU31QCioUGEmudjyYrNcbAr1jghRUv` |
| A real exploit, PAID | commit `FNbCUc53YNayqd6NBqaaxnZTeGAVGABHfPsoHz7Gkc2s` → verdict `2vdtrvQmZmpt4NGfAD2FyBQy9d5PjLR4dEJuQCF8MXTX` → deliver `AodmFQ6tq4pBcxLreRDSCanKkZQY7m6nhM459NfPAg3s` |
| A fake, REFUSED | `DUtubHScU3udGH58UxdTHWjwvDBjsHCsrupmBMxVYZiy` — "no invariant broken", bond slashed |
| Refusal kinds on chain | 6 of 6 demonstrated kinds — `make refusals` lists each tx; every refusal the contract can log: [ARCHITECTURE.md § Refusals](ARCHITECTURE.md#refusals) |

Explorer links for each: [README.md § Live Deployment](README.md). The payout is the verifier's
award-then-pay: `on_verdict` awards escrow to the earliest verifying commit; `deliver` pays only
once `sha256(enc) == h_enc`.

## 4. Real reproduce commands (copy-paste, creds-free)

```bash
make replay        # offline re-run, 29 OK
make verify-demo   # 5 paid demo-bounty runs proven from chain (about 1.5 min)
make verify        # all 29 runs proven from chain (about 80 calls; Error 2 = RPC unreachable, Error 1 = a failed check)
make open          # offline: all 6 paid deliveries open to the exploit make replay re-runs (needs PyNaCl)
make corpus        # 52 items vs golden verdicts → "corpus: 52 OK · 0 FAIL"
make bench         # request→verdict p50 7.27 s · p95 10.85 s (29 runs)
```

The full test suite needs a developer toolchain, not credentials: `pip install pytest pytest-cov pynacl base58`, Rust
1.97.1 and 1.85.0 (`wasm32-unknown-unknown` target), then `make test` → 413 tests: 307 Python unit, 39 verifier, 47
contract unit, 20 near-workspaces sandbox (it downloads the sandbox node the first time).

What each check covers, line by line, is in [DEMO.md](DEMO.md) and
[README.md § Engineering Rigor](README.md).

## 5. Honest limits (7)

1. **Testnet only** — the mainnet leg is prepared (`scripts/mainnet_leg.py`), not run.
2. **Worker attestation** — `make verify` checks the OutLayer worker *key*, not its TDX quote; it
   does not prove the worker ran exactly the pinned bytes. `make replay` re-runs those bytes locally.
3. **RPC trust** — `make verify` trusts the archival RPC; an RPC error is RECORDED, never a pass.
4. **Baseline models** are third-party, not NEAR AI Cloud, one run each.
5. **Stuck commits** — the dangling-`Pending` refund and yield-timeout paths are code-review-only.
6. **Storage and griefing** — commits are stored for good; fresh accounts can keep one invariant busy.
7. **No outside users yet** — the measured demo is our own hunter client (`scripts/hunter.py`) committing the
   corpus' real exploits and fakes; the LLM hunter agent ran only locally (`hunter-agent/`).

Full detail: [README.md § Honest limits](README.md) and [ARCHITECTURE.md § Limits](ARCHITECTURE.md#limits).

## 6. Links

- Live site: https://sealed.edycu.dev · styled judge page: https://sealed.edycu.dev/judge
- Pitch deck: https://sealed.edycu.dev/pitch/
- Demo video (1:34, captioned): https://youtu.be/sEMg3q7gG5k · X demo post: https://x.com/edycutjong/status/2117725204403364028
- Architecture (every claim with `file:line`): [ARCHITECTURE.md](ARCHITECTURE.md)
- Demo walk-through: [DEMO.md](DEMO.md)
- OutLayer integration (4 OutLayer methods plus NEAR global contracts, with code refs): [README.md § NEAR OutLayer Integration](README.md)
