<div align="center">
  <img src="docs/assets/icon-animated.svg" alt="Sealed icon: a sealed evidence bag stamped PAID" width="144">
  <h1>Sealed Exploit 🔒</h1>
  <p><em>Bug bounties that pay for an executed break of a committed invariant on a committed snapshot — before the protocol ever sees the exploit.</em></p>
  <img src="docs/assets/readme-hero-animated.svg" alt="Sealed — verified inside NEAR OutLayer, paid on NEAR" width="100%">

  **Proof, not a pitch:** on NEAR testnet the verifier paid **5 of 5** real Ethernaut exploits and **0 of 21** submitted fakes. Re-check it yourself, no NEAR account or key: `make replay` (offline) and `make verify` (from chain data).

  <br/>

  [![Live Demo](https://img.shields.io/badge/🚀_Live-Demo-06b6d4?style=for-the-badge)](https://sealed.edycu.dev)
  [![Pitch Deck](https://img.shields.io/badge/📊_Pitch-Deck-f59e0b?style=for-the-badge)](https://sealed.edycu.dev/pitch/)
  [![Judge Page](https://img.shields.io/badge/⚖️_Judge-Page-10b981?style=for-the-badge)](https://sealed.edycu.dev/judge/)
  [![Demo Video](https://img.shields.io/badge/▶_Demo-Video-ef4444?style=for-the-badge)](https://youtu.be/sEMg3q7gG5k)
  [![X Post](https://img.shields.io/badge/Demo-Post-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/edycutjong/status/2117725204403364028)
  [![dev.to Article](https://img.shields.io/badge/dev.to-Article-0a0a0a?style=for-the-badge&logo=devdotto&logoColor=white)](https://dev.to/edycutjong/i-asked-3-llms-to-triage-bug-bounty-exploits-so-i-built-a-contract-that-runs-them-instead-38i6)
  [![Built for NEAR Hackathon](https://img.shields.io/badge/NEAR-Hackathon_2026-8b5cf6?style=for-the-badge)](https://nearhackathon.com)

  <br/>

  ![Rust](https://img.shields.io/badge/Rust-000000?style=flat&logo=rust)
  ![WebAssembly](https://img.shields.io/badge/WASI-654FF0?style=flat&logo=webassembly&logoColor=white)
  ![NEAR](https://img.shields.io/badge/NEAR_testnet-000000?style=flat&logo=near&logoColor=white)
  ![Python](https://img.shields.io/badge/Python_3-3776AB?style=flat&logo=python&logoColor=white)
  [![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
  [![CI](https://github.com/edycutjong/sealed/actions/workflows/ci.yml/badge.svg)](https://github.com/edycutjong/sealed/actions/workflows/ci.yml)
  [![Release](https://img.shields.io/github/v/release/edycutjong/sealed?sort=semver)](https://github.com/edycutjong/sealed/releases/latest)

</div>

---

## 📸 See it in Action

<p align="center"><img src="docs/assets/broll.gif" alt="Silent 17-second loop from the demo: BUG BOUNTIES RUN ON TRUST over a pile of AI-written reports; the red SEALED EXPLOIT tape, PAYS ONLY FOR AN EXECUTED BREAK; the custody form committed at funding with 0 access keys; a green PAID 1 000 tUSDC stamp on the real exploit's deliver tx; a red REFUSED bond slashed stamp on the near-miss; and the numbers 5/5 real exploits paid, 0/21 fakes paid, LLM-only 1 · 3 · 3 of 21." width="100%"></p>

**[▶ Watch the 1:34 demo on YouTube](https://youtu.be/sEMg3q7gG5k)**: a real exploit is paid and a fake is refused on chain, with captions.

The hero above is the artwork; the product is the command line and the chain. Start with the five-minute path in
[DEMO.md](DEMO.md): one real exploit pays out, one fake is refused with a reason, both with explorer links.

## 💡 The Problem & Solution

### The Problem

Bug bounties are trust-first: the hunter reveals the bug, then a human triager decides whether and how much to pay. The
protocol can patch it, call it "known" and pay nothing, and AI-written "exploit reports" bury the triage queue.

### The Solution

A bounty account that nobody holds a key to commits three things at funding: the snapshot hash, the invariants, and the
hash of the verifier WASM. Then:

1. The hunter stores the exploit as an OutLayer encrypted secret, then **commits** `H(exploit ‖ hunter ‖ salt)` with a bond.
2. The contract asks **NEAR OutLayer** to run the pinned verifier in a TEE worker. The verifier replays the exploit in
   revm on the snapshot and calls the level's own `validateInstance`.
3. The callback **awards** the first commit that verifies, once per invariant. Everything else is **refused on chain with
   a reason**, and a hunter-caused failure slashes the bond.
4. The hunter **delivers** the exploit sealed to the protocol's key. The contract checks it hashes to what the worker
   attested, and only then is the escrow owed and **paid**. The protocol gets exactly the exploit that was verified
   (`make open` opens all 6 paid deliveries, the 5 demo-bounty payouts plus one on the earlier D3 bounty, offline to
   the exploit `make replay` re-runs).

The protocol still decides what counts as a break, but up front, before any claim, and in public.

## 🏗️ Architecture & Tech Stack

![Sealed architecture in ten steps across three phases. COMMIT: the protocol funds the keyless global bounty and pins snapshots, invariants and the verifier wasm hash; the hunter stores the exploit as an OutLayer encrypted secret, then commits H(exploit, hunter, salt) with a bond. VERIFY: the bounty calls request_execution pinned by hash; an OutLayer TEE worker replays the exploit in revm on the committed snapshot and returns the verdict to on_verdict; the first break per invariant is awarded into escrow. DELIVER and PAY: deliver(enc) must hash to the attested h_enc, then ft_transfer pays 1 000 tUSDC. Six refusal kinds branch off the failing check (pool pull, invariant busy, duplicate, fake, delivery mismatch, expired award). A trust strip says what is checked from chain, what replays offline, and what is not checked (the TDX quote).](docs/assets/architecture.png)

<details>
<summary><b>Text-equivalent diagram (Mermaid)</b> — click to expand</summary>

```mermaid
flowchart LR
  H[Hunter client] -- commit + bond --> B[Bounty contract<br/>keyless, global code]
  H -- sealed exploit --> S[(OutLayer secrets)]
  B -- request_execution<br/>pinned wasm hash --> O[OutLayer TEE worker]
  S --> O
  O -- resolve_execution<br/>verdict --> B
  B -- AWARDED / REFUSED --> H
  H -- deliver sealed to protocol --> B
  B -- ft_transfer --> H
```

</details>

| Layer | Choice |
|---|---|
| Verifier | Rust → WASI (`verifier.wasm`), revm, 5 Ethernaut snapshots at commit `d05643a4` |
| Contract | near-sdk 5.9.0, NEP-141 escrow, NEAR global contract, zero access keys |
| Execution | NEAR OutLayer TEE workers (documented as Intel TDX; this repo checks the worker key, not the quote), pinned by wasm hash |
| Tooling | Python 3 scripts, `wasmtime`, archival RPC (FastNEAR) |

Full walk-through with `file:line` for every claim: [ARCHITECTURE.md](ARCHITECTURE.md).

## 🏆 NEAR OutLayer Integration (Security track; Privacy, Agents and Open fits)

| OutLayer method | Used for | Code |
|---|---|---|
| `request_execution` | the bounty requests the verifier, pinned by hash, with the hunter's secrets profile | `contracts/bounty/src/lib.rs:334` (call), `:657` (hash pin) |
| `resolve_execution` | called by the OutLayer worker (not by the bounty): it resumes OutLayer's yield, and the verdict returns to the bounty's `on_verdict` callback, which decides AWARDED or REFUSED; `make verify` checks that resolve tx and its signing key | `contracts/bounty/src/lib.rs:335` (`.then(on_verdict)`), `:343`; `scripts/verify.py:33` |
| `store_secrets` | the hunter stores the exploit as an OutLayer encrypted secret bound to the pinned wasm hash | `scripts/hunter.py:63-76` |
| `get_config` | `make verify` anchors the worker to OutLayer's operator at the resolve block | `scripts/verify.py:111` |
| Global contracts | the bounty runs on a code hash with no access key (I6); the earlier D3 throwaway bounty (2 of the 29 runs) is keyed | `scripts/deploy_bounty_testnet.py:115` |

## ⛓️ Live Deployment

Testnet only; no wallet is needed to check any of it. Every hash is in `corpus/results.json`.

| Item | Value |
|---|---|
| Demo bounty (5 levels, keyless) | `demo.sealed-dev-11010702.testnet` · create tx `9FrSN6h6gnuTaqHnzy4AjGoYCfzJkhHeDKpG4wcdDpTU` |
| Corpus bounty (fakes) | `corpus.sealed-dev-11010702.testnet` · create tx `GWgM5NCLY75JQyUhnRXXaP1Uhs49aUYM3hxLocpuoRou` |
| Global code hash | `7HtmeswBuR9JLCcU31QCioUGEmudjyYrNcbAr1jghRUv` |
| A real exploit, PAID | [commit](https://testnet.nearblocks.io/txns/FNbCUc53YNayqd6NBqaaxnZTeGAVGABHfPsoHz7Gkc2s) · [worker verdict](https://testnet.nearblocks.io/txns/2vdtrvQmZmpt4NGfAD2FyBQy9d5PjLR4dEJuQCF8MXTX) · [deliver](https://testnet.nearblocks.io/txns/AodmFQ6tq4pBcxLreRDSCanKkZQY7m6nhM459NfPAg3s) |
| A fake, REFUSED | [`fake`](https://testnet.nearblocks.io/txns/DUtubHScU3udGH58UxdTHWjwvDBjsHCsrupmBMxVYZiy): "no invariant broken", bond slashed |
| Refusal kinds on chain | 6 of 6: `make refusals` lists each tx |

## 📊 Engineering Rigor

| Metric | Value | Where |
|---|---|---|
| Real exploits paid / submitted | 5 of 5 (demo bounty) | `corpus/results.json` |
| Non-breaking submissions paid | 0 of 21 (21 of 21 refused; all 21 ran on the corpus bounty) | `corpus/results.json` |
| Testnet runs | 29 = the 5 paid on the demo bounty + 22 on the corpus bounty (the 21 refused, plus 1 real break awarded but never delivered, expired back to the pool) + 2 on the earlier keyed D3 bounty (1 paid, 1 refused). Paid deliveries: 6 = the 5 demo payouts + the D3 one | `corpus/results.json` |
| Corpus | 52 items vs golden verdicts | `make corpus` |
| Tests | 411: 305 Python unit (all 19 scripts), 39 verifier (11 golden · 12 unit · 9 CLI · 4 seal · 3 snapgen), 47 contract unit, 20 near-workspaces sandbox | `make test` |
| Line coverage | Python 100% (1 771 statements, 19 files) · verifier 99.5% (380 lines) · contracts 99.1% (680 lines); the 8 uncovered Rust lines are error arms that cannot fire (e.g. an `Infallible` map_err) or a dead helper, left in rather than change pinned code | `make cov` |
| Request → verdict | p50 7.27 s · p95 10.85 s (29 runs) | `corpus/bench.json`, `make bench` |
| Heaviest real run | 7 371 260 instructions (0.37% of the 2e9 limit) | `corpus/results.json` |
| Heaviest fake | 479 555 711 instructions (23.98% of the limit) | `corpus/bench.json` |
| LLM-only triage on the same corpus (fakes it would pay, of 21) | muse-wonder-1.0 1 · nemotron-3-ultra 3 · qwen3.8-omni-flash 3; the same models would pay 12, 12 and 11 of the 15 submissions that really break a level (offline golden verdicts) | `make baseline` |

The baseline models could not run code and are **not** NEAR AI Cloud; read its limits in
[baseline/README.md](baseline/README.md) before quoting it.

### Attacks defeated

| Control | Why it is load-bearing | Test |
|---|---|---|
| I1 conservation | pool + escrow + paid = funded − withdrawn after every call | `contracts/itests/tests/bounty.rs:165` |
| I2 one payout per invariant | a duplicate commit cannot be paid twice | `bounty.rs:574`, `:486` |
| I2b reservation released | a refused fake frees its reservation and reopens the invariant | `bounty.rs:257` |
| I3 one verdict in flight | no race for the same invariant | `bounty.rs:363` |
| I4 withdraw guard | the protocol cannot pull reserved or awarded USDC | `bounty.rs:383` |
| I7 award matches the commit | a verdict for another exploit, invariant or snapshot is refused | `bounty.rs:279`, `:298`, `:318` |
| I8 delivery hash | the protocol gets the exploit only when `sha256(enc) == h_enc` | `bounty.rs:209` |
| Failed payout | a failed `ft_transfer` leaves the escrow owed and `retry_payout` pays it | `bounty.rs:436` |
| Fake exploits | a no-op, near-miss, wrong snapshot or abuse input is refused | `make corpus`, `verifier/tests/golden.rs` |

The sandbox tests run the contract against a mock OutLayer and a mock token; the live worker is shown by the testnet runs
(`make verify`).

### Honest limits (7)

1. **Testnet only.** The mainnet leg is prepared (`scripts/mainnet_leg.py`) and has not run.
2. **Worker attestation.** `make verify` shows the request pinned the verifier hash and the operator's OutLayer worker
   key answered (a FunctionCall key limited to OutLayer's contract, its method list including `resolve_execution`). It
   checks the key, not its TDX quote, and does not show the worker ran exactly those bytes. `make replay` re-runs the
   same bytes locally.
3. **RPC trust.** `make verify` believes the archival RPC it queries; an RPC error becomes RECORDED (`verify.py` exit 2, `make` prints `Error 2`), never a pass.
4. **Baseline models** are third-party, not NEAR AI Cloud, one run each, with a hunter claim on only 5 of the 21 fakes.
5. **Stuck commits.** The dangling-`Pending` refund branch is covered by code review only, and the yield-timeout path was
   not observed on a live testnet run.
6. **Storage and griefing.** Commits are stored for good and paid from the bounty's NEAR balance; fresh accounts can keep
   one invariant busy for the cost of gas and the OutLayer fee.
7. **No outside users yet.** The measured demo is our own hunter agent plus the fakes corpus.

Detail for each, plus memory and seal-key reuse: [ARCHITECTURE.md § Limits](ARCHITECTURE.md#limits).

## 🚀 Getting Started

### Prerequisites

`python3` ≥ 3.8 and `wasmtime` (`brew install wasmtime`, `cargo install wasmtime-cli`, or `curl https://wasmtime.dev/install.sh -sSf | bash`) run
every target in the table below; `make open` also needs PyNaCl (`pip install pynacl`). Rust is only for rebuilding
from source (`make verifier-check`) and for the full test suite: `make test` needs `pip install pytest pytest-cov pynacl base58`
plus Rust 1.97.1 (from `rust-toolchain.toml`) and 1.85.0 with the `wasm32-unknown-unknown` target, and near-workspaces
downloads its sandbox node the first time.

### Reproduce from a fresh clone (no NEAR account, no keys)

| Do this | See this | Network |
|---|---|---|
| `make doctor` | prerequisites present, `verifier.wasm` hash matches its pin | archival RPC ping |
| `make replay` | every published commit re-run under wasmtime from the committed wasm its bounty pinned (sha256-checked) = its on-chain verdict | none |
| `make replay INPUT=corpus/vectors/real-fallback.json` | the verdict for one tx list (yours: `{"target":0,"invariant_id":"…","txs":[…]}`) | none |
| `make open` | each of the 6 paid runs in `corpus/results.json` (FAIL if one is missing): verdict `broken` with `h_exploit` = the commit, AWARDED / DELIVERED / PAID for that commit id, `sha256(enc)` = `h_enc`, and the box opens to the published exploit `make replay` re-runs, which hashes to the commit (needs PyNaCl) | none |
| `make verify` | each of the 29 runs proven from chain data: pinned hash, the operator's scoped worker key, verdict, and for the 6 paid runs `h_enc` and PAID; every commit on chain bundled; paid totals match | archival RPC, about 80 calls (a few minutes on a rate-limited node; `Error 2` = unreachable, `Error 1` = a failed check) |
| `make verify-demo` | the same checks on the 5 paid demo-bounty runs, and FAIL unless that bounty has 0 access keys, runs the committed `contracts/bounty.wasm` (global hash `7Htmes…`) and was created with no key (its create tx) | about 25 calls (about 1.5 min) |
| `make corpus` | all 52 corpus items vs their golden verdicts | none |
| `make refusals` | the 6 on-chain refusal kinds with tx hashes | none |
| `make bench` | request→verdict p50/p95, instructions / time / memory vs the enforced limits | none (`make bench-chain` re-reads the chain) |
| `make baseline` | what LLM-only triage would pay on the same corpus | none |

## 🧪 Testing & CI

```bash
make test          # 411 tests: 305 Python unit + 39 verifier + 47 contract unit + 20 near-workspaces sandbox (Prerequisites above)
make corpus        # 52 items vs golden verdicts, wasmtime only
```

**6-stage pipeline** (`.github/workflows/ci.yml`): Quality ∥ Security → Build → E2E → Performance → Deploy gate.

| Stage | Gate | Blocking |
|---|---|---|
| 1 · Quality | clippy (correctness + suspicious) on verifier and bounty · ruff · verifier golden/unit/CLI tests | ✅ |
| 2 · Security | gitleaks over the full history · `scripts/check_submission_readiness.py` · `cargo audit` (advisories reviewed in [SECURITY.md](SECURITY.md)) | ✅ / audit reported |
| 3 · Build | `verifier.wasm` rebuilds byte-for-byte on macOS/arm64 (the pinned build host) · contracts wasm + unit tests | ✅ |
| 4 · E2E | near-workspaces sandbox I1–I8 · `make replay` / `corpus` / `refusals` / `open` · `make verify-demo` against NEAR testnet · `/judge` live with no credentials (`scripts/site_check.py`) | ✅ |
| 5 · Performance | `make bench` · every recorded run ≤ 50% of each OutLayer limit and p95 verdict ≤ 30 s (`scripts/perf_gate.py`) · Lighthouse CI on `docs/` | ✅ / Lighthouse advisory |
| 6 · Deploy gate | all of the above, `main` only; Vercel's Git integration deploys `docs/` to https://sealed.edycu.dev on every push to `main` | ✅ |

```bash
python3 scripts/perf_gate.py              # instructions 23.98% · time 2.31% · memory 0.34% of the limits; p95 10.85 s
python3 scripts/site_check.py --live https://sealed.edycu.dev
```

Rust sources are not auto-formatted in CI: moving a line shifts panic-location strings and would change the pinned
`verifier.wasm` / `bounty.wasm` bytes the on-chain evidence names. Releases are automatic: `.github/workflows/release.yml`
tags `vX.Y.Z` from conventional commits (`feat` → minor, `fix`/`perf` → patch, `!` → major) and never edits files.
CodeQL (Python, Rust), Dependabot, secret scanning and push protection are on. Developer-experience notes on OutLayer
and global contracts: [docs/DX-REPORT.md](docs/DX-REPORT.md).

## 📁 Project Structure

```
verifier/       WASI verifier (revm) + 5 Ethernaut snapshots      contracts/   bounty + test token + sandbox tests
levels/         pinned Ethernaut sources                           scripts/     hunter, verify, replay, bench, baseline
corpus/         52-item corpus, evidence bundles, results, bench   baseline/    LLM-only triage record
hunter-agent/   LLM-hunter transcripts and proposed exploits       day0/        feasibility checks
```

## 🗺️ Roadmap

- [x] Keyless bounty on a NEAR global contract, verifier pinned by hash
- [x] 5 Ethernaut levels, 52-item corpus, 6 refusal kinds on chain
- [x] `make replay` and `make verify` from a fresh clone
- [ ] Mainnet leg (script prepared, a human signs)
- [ ] LLM baseline and hunter on NEAR AI Cloud (needs the key)

## 📽️ Demo Materials

Walk-through with explorer links: [DEMO.md](DEMO.md). Landing page: [sealed.edycu.dev](https://sealed.edycu.dev)
(source `docs/index.html`; it replays two recorded testnet runs). Pitch deck: [/pitch/](https://sealed.edycu.dev/pitch/)
(`docs/pitch/index.html`). Demo video (1:34, captioned): [YouTube](https://youtu.be/sEMg3q7gG5k), also attached to the
[X demo post](https://x.com/edycutjong/status/2117725204403364028).

## 📄 License

MIT — see [LICENSE](LICENSE).

## 🙏 Acknowledgments

Levels from [OpenZeppelin Ethernaut](https://github.com/OpenZeppelin/ethernaut) · execution on [NEAR OutLayer](https://app.outlayer.ai) · EVM by [revm](https://github.com/bluealloy/revm).

**Built with (hackathon rules Q-001/Q-005).** All code in this repo was written during the hackathon window
(first commit 2026-11-01); there is no pre-hackathon baseline. Libraries: near-sdk 5.9.0, revm 43,
crypto_box 0.9 (libsodium sealed-box layout), sha2 / blake2, serde_json; the `wasmtime` CLI for `make replay`;
Ethernaut level sources (SPDX-MIT files only, see [levels/README.md](levels/README.md)) with OpenZeppelin 4.9.6
`Ownable`/`Context`, compiled with solc 0.8.24. The code was written with AI coding agents (Claude Code) under
human direction.
