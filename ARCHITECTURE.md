# Architecture

Written from the code at this commit; every claim points at the line that implements it. Testnet only so far (see
[Limits](#limits)).

Sealed pays for one thing: **an executed break of a committed invariant on a committed snapshot**. The invariant is an
Ethernaut level's own `validateInstance`, the snapshot is a frozen EVM state, and the break is run by a pinned WASI
verifier inside a NEAR OutLayer TEE worker. The exploit stays sealed until the money is already owed.

## Components

| Part | Code | Role |
|---|---|---|
| Verifier | `verifier/src/lib.rs`, `main.rs`, `seal.rs` → `verifier.wasm` (sha256 in `verifier.wasm.sha256`) | Runs ≤ 4 exploit txs on an embedded snapshot in revm, then calls the level's `validateInstance(instance, player)`; prints one verdict JSON line (≤ 900 B) |
| Snapshots | `verifier/snapshots/*.json`, index in `targets/hashes.json` | 5 Ethernaut levels (fallback, telephone, delegation, force, king) at commit `d05643a4`, built by `verifier/src/bin/snapgen.rs` |
| Bounty contract | `contracts/bounty/src/lib.rs` → `contracts/bounty.wasm` | Keyless NEP-141 escrow: commit, request the verifier on OutLayer, award, deliver, pay |
| Test token | `contracts/test-token/src/lib.rs` | Fixed-supply NEP-141 standing in for USDC on testnet |
| Deploy | `scripts/deploy_bounty_testnet.py` | One batch: create account, `UseGlobalContract(hash)`, `new` — no `AddKey` |
| Hunter client | `scripts/hunter.py`, `scripts/hunter_agent.py` | Commit, store the sealed secrets on OutLayer, wait for the verdict, deliver |
| Evidence | `corpus/evidence/*.json` (full tx bundles), `corpus/published/*.json`, `corpus/results.json`, `corpus/bench.json` | Everything the judge targets re-check |

## Commit to payout

```
hunter                bounty (keyless)            token            OutLayer (TEE worker)
  │ commit(h, inv, to) + bond + deposit │                     │                     │
  ├──────────────────────────►│ checks: bond, claim pending,   │                     │
  │                           │ invariant paid, pool short     │                     │
  │                           ├── storage_balance_of(to) ─────►│                     │
  │                           │◄── on_payout_checked ──────────┤                     │
  │                           │ PENDING; reserve amount        │                     │
  │                           ├── request_execution(WasmUrl+hash, input, secrets_ref c-<h[..8]>, limits) ──►│
  │                           │                                │   verifier.wasm: EXPLOIT/SALT/EPH_SK from │
  │                           │                                │   the hunter's secrets → verdict JSON     │
  │                           │◄── resolve_execution (worker key) → yield resumes → on_verdict ───────────┤
  │                           │ AWARDED (escrow, deliver_by) or REFUSED (bond slashed)                     │
  │ deliver(enc)              │                                │                     │
  ├──────────────────────────►│ sha256(enc) == h_enc → DELIVERED                     │
  │                           ├── ft_transfer(to, amount) ────►│                     │
  │                           │◄── on_paid → PAID              │                     │
```

- `commit` takes the commit hash, the invariant and a payout account; it refuses for a short bond, a claim pending, an
  invariant already paid, or a pool short (`contracts/bounty/src/lib.rs:241`, reasons at `:254-261`). Every refusal is a
  successful tx with a `REFUSED` log, never a panic.
- The payout account's token registration is checked before the slot is taken (`storage_balance_of`, `:301`;
  callback `on_payout_checked`, `:310`), so the first transfer normally succeeds.
- The OutLayer request pins the verifier by hash (`WasmUrl.hash = verifier_wasm_hash`, `:657`) and names the hunter's
  secrets profile `c-<commit_hash[..8]>` (`:647-668`). The contract builds `input_data` itself; it never sees the
  exploit.
- `on_verdict` (`:343`) awards only if the verdict says `broken`, its `h_exploit` equals the commit hash, its
  `invariant_id` equals the commit's, and its `h_snapshot` equals the bounty's pinned snapshot (`:365-385`); anything
  else is `REFUSED <reason>` and the bond is slashed. A verifier that never answered refunds the bond once, and slashes a
  repeat within 24 h (`:417-437`).
- `deliver(enc)` (`:478`) pays only when `sha256(enc)` equals the awarded `h_enc` and the award is not past
  `deliver_by`; `on_paid` (`:501`) logs `PAID`, or keeps the escrow owed for `retry_payout` (`:520`). An award never
  delivered can be `expire`d back to the pool (`:536`).

## What the verifier computes

`run` (`verifier/src/lib.rs:336`):

- `h_snapshot = sha256(snapshot bytes)` for `target` — the snapshots are compiled into the wasm (`:36`), so a bounty
  pinning the wasm hash also pins every snapshot.
- `h_exploit = sha256(EXPLOIT ‖ hunter ‖ SALT)` — must equal the on-chain commit hash.
- `execute` (`:289`): the exploit txs run from the snapshot's `player`, then the snapshot's `validator` calls
  `validateInstance(instance, player)` on the level factory; `broken` is that call's boolean. No Rust-side predicate.
- `enc = crypto_box_seal({"exploit": base64(EXPLOIT), "salt", "hunter"}, protocol_enc_pk)` (`seal.rs:12`) with the
  ephemeral key taken from `EPH_SK`, so
  native, wasmtime and the worker produce identical bytes (`verifier/src/seal.rs:1-5`); `h_enc = sha256(enc)`.
- Bounds (`:20-32`): 600 000 gas for all exploit txs, 500 000 for `validateInstance`, ≤ 4 txs, ≤ 24 KiB calldata, no
  precompiles (`:220`), `err` capped at 64 bytes.
- `main.rs` reads the worker's enforced limits (`NEAR_MAX_*`) and reports them plus its own peak linear memory in the
  verdict's `lim` field.

## Protocol invariants

| Id | Rule | Where it is tested |
|---|---|---|
| I1 | USDC conservation: pool + escrow + paid = funded − withdrawn | `contracts/itests/tests/bounty.rs:165`, asserted after every transition |
| I2 / I2b | One payout per invariant; a refused commit releases its reservation | `bounty.rs:574`, `:257`, `:486` |
| I3 | At most one pending verdict per invariant | `bounty.rs:363` |
| I4 | `withdraw_pool` never moves reserved or escrowed USDC, and only after the timelock | `bounty.rs:383`; `lib.rs:552` |
| I5 | Every request pins `verifier_wasm_hash`; only `new` sets it | `lib.rs:657`, `:192` |
| I6 | The bounty account has zero access keys for life | `scripts/deploy_bounty_testnet.py:115`; `make verify-d5` checks it on chain |
| I7 | Awarded ⇒ `h_exploit`, `invariant_id`, `h_snapshot` all match the commit | `bounty.rs:279`, `:298`, `:318` |
| I8 | The exploit becomes public, and the escrow owed, only in a `deliver` with `sha256(enc) == h_enc` | `bounty.rs:209`, `:436` |

## Judge targets → what they re-check

| Target | Script | Re-checks |
|---|---|---|
| `make replay` | `scripts/verify_offline.py` | each published commit under wasmtime from the committed wasm (hash-checked) = the on-chain verdict |
| `make verify` / `verify-d5` | `scripts/verify.py` | per commit, from the archival RPC: pinned hash (bounty's live state), the resolve tx went to the bounty's OutLayer contract from the operator OutLayer's config named at that block, with a key scoped to it; the bundle equals the chain; verdict, `h_enc`, `PAID` for this commit id; `view_commit` status matches the line; the bundle set equals `corpus/results.json` runs, each commit once; `verify-d5` adds I6 |
| `make corpus` | `scripts/corpus_check.py` | all 52 corpus items against their golden verdicts |
| `make refusals` | `scripts/refusals.py` | the 6 refusal kinds seen on chain, with tx hashes |
| `make bench` / `bench-chain` | `scripts/bench.py` | latency p50/p95 and resources vs limits, recomputed from the bundles (`bench-chain` re-reads the chain) |
| `make test` | `verifier/tests/golden.rs`, `contracts/itests/tests/bounty.rs` | golden verdicts native = wasmtime; the contract in a near-workspaces sandbox |

## Limits

- **Worker attestation.** On chain, `make verify` shows the request pinned the verifier hash and a key registered for
  the OutLayer worker answered (`scripts/verify.py` docstring, `worker`); it does not show the worker ran exactly those
  bytes. `make replay` re-runs the same bytes locally and must reproduce the verdict. Replay reads only the bundle;
  `make verify`'s `bundle` check is what ties that bundle to the chain.
- **RPC trust.** `make verify` believes the archival RPC it queries (no light-client proof). Run it against a second
  provider to cross-check: `make verify RPC=https://archival-rpc.testnet.near.org`. An RPC that errors or rate-limits
  turns lines into RECORDED (exit 2), never into a pass.
- **Memory** is the verifier's own peak linear memory; OutLayer reports no worker memory figure.
- **Stuck commits.** `release_stale` (`lib.rs:454`) unsticks a commit stuck in `AwaitingRegistration` (bond and
  deposit back: the deposit was never sent) or a dangling `Pending` (bond back; the OutLayer deposit already left with
  the request, so the `RELEASE_STALE … (full refund, uncounted)` log means the bond). Neither state can be produced in
  the near-workspaces sandbox (the registration callback's gas is reserved up front; the yield times out into a `null`
  verdict long before the 30-minute floor). The `AwaitingRegistration` branch has a unit test with a mocked context
  (`lib.rs:792`); the dangling-`Pending` branch is covered by code review only (`bounty.rs:545-549`, `:595-599`). The
  yield-timeout `null` path itself was not observed on a live testnet run. The 30-minute clock starts at `commit`,
  which is one or two blocks before the request.
- **Griefing.** A commit holds its invariant for one verdict (p95 12.15 s commit→verdict, `corpus/bench.json`), and
  other invariants are untouched (I4). A non-verdict refunds the bond once per `(hunter, invariant)` per 24 h
  (`lib.rs:415-443`), so a set of fresh accounts can keep one invariant busy at the cost of the OutLayer fee and gas per
  cycle rather than a bond. A commit whose payout account is unregistered reserves the amount for the one or two blocks
  before its registration callback refunds it in full.
- **Storage.** Every commit that passes the guards is stored for good (`commits` is append-only, `lib.rs:151`), and
  each `(hunter, invariant)` that gets an infra refund keeps one timestamp; the bounty account pays that storage from
  its own NEAR balance (4 NEAR on the demo bounty, ~0.004 NEAR per stored commit). A spammer who commits with an
  unregistered payout account is refunded in full and pays only gas, so a bounty can be run out of storage balance;
  anyone can top a keyless bounty up with a plain NEAR transfer. Charging storage to the hunter needs a contract change
  (not made: it would replace the global code hash the testnet evidence pins).
- **Seal key reuse.** The seal's nonce is derived from `EPH_SK` (`seal.rs:5`), so a hunter client must draw a fresh
  `EPH_SK` per commit; `scripts/hunter.py` draws 32 random bytes each time.
- **Testnet only.** The mainnet leg (`scripts/mainnet_leg.py`) prints the commands; it never signs and has not run.
- **Baseline models.** `make baseline` used third-party models, not NEAR AI Cloud (`baseline/README.md`).
