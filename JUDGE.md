# JUDGE.md — Sealed, for the judges

Machine-readable companion for the NEAR Hackathon 2026 AI judges (Claude Code + Codex) and the
human jury. It is a short index to the evidence; the authority is [README.md](README.md),
[DEMO.md](DEMO.md) and [ARCHITECTURE.md](ARCHITECTURE.md), and every number below is reproducible
from `build/` with no NEAR account or key. Testnet only. A styled web version is at
`docs/judge/index.html`, served at `/judge` once the site is deployed.

## 1. One-sentence claim

Sealed is a bug bounty that pays for an *executed* break of a committed invariant on a committed
snapshot — the exploit is verified inside a NEAR OutLayer TEE and paid on NEAR — and on testnet the
executing verifier paid **5 of 5** real Ethernaut exploits and **0 of 21** submitted fakes.

## 2. 30-second make path (do X → see Y)

From a fresh clone with `python3` and `wasmtime`, no account or key:

```bash
make replay   # offline: re-runs 29 published commits under wasmtime → 29 OK, each printing validateInstance = 1 (real break) or 0 (fake)
make verify   # from chain data: re-checks all 29 runs against testnet (about 80 archival RPC calls)
```

`make replay` is offline and deterministic; `make verify` reads the public chain. Full script in
[DEMO.md](DEMO.md).

## 3. Receipt block (on-chain, testnet)

| Item | Value |
|---|---|
| Real exploits paid / submitted | **5 of 5** (demo bounty) — `corpus/results.json` |
| Non-breaking submissions paid | **0 of 21** (21 of 21 refused) — `corpus/results.json` |
| Demo bounty (keyless) | `demo.sealed-dev-11010702.testnet` |
| Corpus bounty (fakes) | `corpus.sealed-dev-11010702.testnet` |
| Global code hash | `7HtmeswBuR9JLCcU31QCioUGEmudjyYrNcbAr1jghRUv` |
| A real exploit, PAID | commit `FNbCUc53YNayqd6NBqaaxnZTeGAVGABHfPsoHz7Gkc2s` → verdict `2vdtrvQmZmpt4NGfAD2FyBQy9d5PjLR4dEJuQCF8MXTX` → deliver `AodmFQ6tq4pBcxLreRDSCanKkZQY7m6nhM459NfPAg3s` |
| A fake, REFUSED | `DUtubHScU3udGH58UxdTHWjwvDBjsHCsrupmBMxVYZiy` — "no invariant broken", bond slashed |
| Refusal kinds on chain | 6 of 6 — `make refusals` lists each tx |

Explorer links for each: [README.md § Live Deployment](README.md). The payout is the verifier's
award-then-pay: `on_verdict` awards escrow to the earliest verifying commit; `deliver` pays only
once `sha256(enc) == h_enc`.

## 4. Real reproduce commands (copy-paste, creds-free)

```bash
make replay        # offline re-run, 29 OK
make verify-demo   # 5 paid demo-bounty runs proven from chain (about 1.5 min)
make open          # offline: all 6 paid deliveries open to the exploit make replay re-runs (needs PyNaCl)
make corpus        # 52 items vs golden verdicts → "corpus: 52 OK · 0 FAIL"
make bench         # request→verdict p50 7.27 s · p95 10.85 s (29 runs)
make test          # 411 tests: 305 Python unit, 39 verifier, 47 contract unit, 20 near-workspaces sandbox
```

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
7. **No outside users yet** — the measured demo is our own hunter agent plus the fakes corpus.

Full detail: [README.md § Honest limits](README.md) and [ARCHITECTURE.md § Limits](ARCHITECTURE.md#limits).

## 6. Links

- Live site: https://sealed.edycu.dev · styled judge page: https://sealed.edycu.dev/judge
- Pitch deck: https://sealed.edycu.dev/pitch/
- Architecture (every claim with `file:line`): [ARCHITECTURE.md](ARCHITECTURE.md)
- Demo walk-through: [DEMO.md](DEMO.md)
- OutLayer integration (5 methods, with code refs): [README.md § NEAR OutLayer Integration](README.md)
