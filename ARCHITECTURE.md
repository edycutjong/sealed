# Architecture

Written from the code at this commit; every claim points at the line that implements it. Testnet only so far (see
[Limits](#limits)).

Sealed pays for one thing: **an executed break of a committed invariant on a committed snapshot**. The invariant is an
Ethernaut level's own `validateInstance`, the snapshot is a frozen EVM state, and the break is run by a pinned WASI
verifier inside a NEAR OutLayer TEE worker. The exploit stays sealed until the verifier has already awarded the payout.

## Components

| Part | Code | Role |
|---|---|---|
| Verifier | `verifier/src/lib.rs`, `main.rs`, `seal.rs` → `verifier.wasm` (sha256 in `verifier.wasm.sha256`) | Runs ≤ 4 exploit txs on an embedded snapshot in revm, then calls the level's `validateInstance(instance, player)`; prints one verdict JSON line (≤ 900 B) |
| Snapshots | `verifier/snapshots/*.json`, index in `targets/hashes.json` | 5 Ethernaut levels (fallback, telephone, delegation, force, king) at commit `d05643a4`, built by `verifier/src/bin/snapgen.rs` |
| Bounty contract | `contracts/bounty/src/lib.rs` → `contracts/bounty.wasm` | Keyless NEP-141 escrow: commit, request the verifier on OutLayer, award, deliver, pay |
| Test token | `contracts/test-token/src/lib.rs` | Fixed-supply NEP-141 standing in for USDC on testnet |
| Deploy | `scripts/deploy_bounty_testnet.py` | One batch: create account, `UseGlobalContract(hash)`, `new` — no `AddKey` |
| Hunter client | `scripts/hunter.py` · `scripts/hunter_agent.py` | `hunter.py`: store the sealed secrets on OutLayer, commit, wait for the verdict, deliver · `hunter_agent.py`: an LLM proposes exploits and checks each locally against the same `verifier.wasm` |
| Evidence | `corpus/evidence/*.json` (full tx bundles), `corpus/published/*.json`, `corpus/results.json`, `corpus/bench.json` | Everything the judge targets re-check |

## Commit to payout

```
hunter                bounty (keyless)            token            OutLayer (TEE worker)
  │ commit(h, inv, to) + bond + deposit │                     │                     │
  ├──────────────────────────►│ checks: bond, claim pending,   │                     │
  │                           │ invariant paid, pool short;    │                     │
  │                           │ reserve amount                 │                     │
  │                           ├── storage_balance_of(to) ─────►│                     │
  │                           │◄── on_payout_checked ──────────┤                     │
  │                           │ PENDING (slot taken)           │                     │
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
  invariant already paid, or a pool short (`contracts/bounty/src/lib.rs:241`, reasons at `:254-261`). Every guard refusal
  is a successful tx with a `REFUSED` log; malformed input (an unknown invariant, a non-hex hash) panics.
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
- `enc = crypto_box_seal({"exploit": base64(EXPLOIT), "salt", "hunter"}, protocol_enc_pk)` (`seal.rs:23`; plaintext layout `:12`) with the
  ephemeral key taken from `EPH_SK`, so
  native, wasmtime and the worker produce identical bytes (`verifier/src/seal.rs:1-5`); `h_enc = sha256(enc)`.
- Bounds (`:20-32`): 600 000 gas for all exploit txs, 500 000 for `validateInstance`, ≤ 4 txs, ≤ 24 KiB calldata, no
  precompiles (`:220`), `err` capped at 64 bytes.
- `main.rs` reads the worker's enforced limits (`NEAR_MAX_*`) and reports them plus its own peak linear memory in the
  verdict's `lim` field.

## Protocol invariants

| Id | Rule | Where it is tested |
|---|---|---|
| I1 | USDC conservation: pool + escrow + paid = funded − withdrawn | `contracts/itests/tests/bounty.rs:165` (`assert_conservation`, called throughout the sandbox tests) |
| I2 / I2b | One payout per invariant; a refused commit releases its reservation | `bounty.rs:574`, `:257`, `:486` |
| I3 | At most one pending verdict per invariant | `bounty.rs:363` |
| I4 | `withdraw_pool` never moves reserved or escrowed USDC, and only after the timelock | `bounty.rs:383`; `lib.rs:552` |
| I5 | Every request pins `verifier_wasm_hash`; only `new` sets it | `lib.rs:657`, `:192` |
| I6 | The bounty account has zero access keys for life | `scripts/deploy_bounty_testnet.py:115`; `make verify-demo` / `verify-d5` check it on chain: 0 keys now, global code = the committed `contracts/bounty.wasm`, and a create tx with no AddKey; the contract has no call that adds a key or deploys code |
| I7 | Awarded ⇒ `h_exploit`, `invariant_id`, `h_snapshot` all match the commit | `bounty.rs:279`, `:298`, `:318` |
| I8 | The sealed exploit (encrypted to the protocol's key) is published, and the escrow paid, only in a `deliver` with `sha256(enc) == h_enc` | `lib.rs:487`; `bounty.rs:209`, `:436` |

## Judge targets → what they re-check

| Target | Script | Re-checks |
|---|---|---|
| `make replay` | `scripts/verify_offline.py` | each published commit under wasmtime from the committed wasm whose sha256 is the hash its bounty pinned (`verifier.wasm`, or `verifiers/<sha>.wasm` for the earlier D3 build) = the on-chain verdict |
| `make verify` / `verify-demo` / `verify-d5` | `scripts/verify.py` | per commit, from the archival RPC: pinned hash (bounty's live state), the resolve tx went to the bounty's OutLayer contract from the operator OutLayer's config named at that block, with a key scoped to it; the bundle equals the chain (verdict, request input, deliver args incl. `commit_id`, bounty and deliver logs); verdict, `h_enc`, `PAID` for this commit id; the bounty's `paid_total` / `escrow` equal the bundled PAID / AWARDED amounts; the bundle set equals `corpus/results.json` runs, each commit once, and covers every commit id the bounty holds on chain (`view_state.commits`); `verify-demo` and `verify-d5` add I6: FAIL unless each bounty has 0 access keys, its global code hash is base58(sha256(`contracts/bounty.wasm`)), and its create tx (`corpus/results.json`) was CreateAccount · Transfer · UseGlobalContract(that hash) · FunctionCall `new` with no AddKey |
| `make open` | `scripts/open_deliveries.py` | offline, exactly the Paid runs in `corpus/results.json`, each: published commit id = the bundle's COMMIT log, published input = the bundled request input; verdict `broken`, same invariant, `h_exploit` = the commit; AWARDED / DELIVERED (`h_enc`) / PAID logged for that commit id; `sha256(enc)` = the verdict's `h_enc`; the box (`verifier/src/seal.rs`) opens with the hunter's ephemeral key, published after payment (the same shared key the protocol's own key gives), to the exploit `make replay` re-runs; it hashes to the commit |
| `make corpus` | `scripts/corpus_check.py` | all 52 corpus items against their golden verdicts |
| `make refusals` | `scripts/refusals.py` | the 6 refusal kinds seen on chain, with tx hashes |
| `make bench` / `bench-chain` | `scripts/bench.py` | latency p50/p95 and resources vs limits, recomputed from the bundles (`bench-chain` re-reads the chain) |
| `make test` | `tests/python/`, `verifier/tests/*.rs`, the contract crates' unit tests, `contracts/itests/tests/bounty.rs` | every script with the network blocked (`tests/python/conftest.py`); golden verdicts native = wasmtime; contract unit tests (mocked context); the contract in a near-workspaces sandbox |

## Limits

- **Worker attestation.** On chain, `make verify` shows the request pinned the verifier hash and the operator's worker
  key answered: a FunctionCall key limited to the OutLayer contract, its method list including `resolve_execution` (`scripts/verify.py` docstring, `worker`). It checks that key,
  not its TDX quote (OutLayer documents the quote check at key registration), and it does not show the worker ran
  exactly those bytes. `make replay` re-runs the same bytes locally and must reproduce the verdict. Replay and `make open` read only the bundle;
  `make verify`'s `bundle` check is what ties that bundle to the chain.
- **RPC trust.** `make verify` believes the archival RPC it queries (no light-client proof). Run it against a second
  provider to cross-check: `make verify RPC=https://archival-rpc.testnet.near.org`. An RPC that errors or rate-limits
  turns lines into RECORDED (`verify.py` exit 2; through `make`, a FAIL and a RECORDED both stop the target, printed
  as `Error 1` / `Error 2`), never into a pass. To stay under the public node's rate limit, the OutLayer
  operator and the worker key's scope are read at the first and last resolve block of the run and pinned in between
  when both reads agree (a rotation away and back would need OutLayer's owner key); otherwise each row reads its own.
- **Memory** is the verifier's own peak linear memory; OutLayer reports no worker memory figure.
- **Stuck commits.** `release_stale` (`lib.rs:454`) unsticks a commit stuck in `AwaitingRegistration` (bond and
  deposit back: the deposit was never sent) or a dangling `Pending` (bond back; the OutLayer deposit already left with
  the request, so the `RELEASE_STALE … (full refund, uncounted)` log means the bond). Neither state can be produced in
  the near-workspaces sandbox (the registration callback's gas is reserved up front; the yield times out into a `null`
  verdict long before the 30-minute floor). The `AwaitingRegistration` branch has a unit test with a mocked context
  (`lib.rs:792`); the dangling-`Pending` branch is covered by code review only (`bounty.rs:545-549`, `:595-599`). The
  yield-timeout `null` path itself was not observed on a live testnet run. The 30-minute clock starts at `commit`,
  about a second before the request (`corpus/bench.json`: commit→verdict p50 8.48 s vs request→verdict p50 7.27 s).
- **Griefing.** A commit holds its invariant for one verdict (p95 12.15 s commit→verdict, `corpus/bench.json`), and
  other invariants are untouched (I4). A non-verdict refunds the bond once per `(hunter, invariant)` per 24 h
  (`lib.rs:415-443`), so a set of fresh accounts can keep one invariant busy at the cost of the OutLayer fee and gas per
  cycle rather than a bond. A commit whose payout account is unregistered reserves the amount for the one or two blocks
  before its registration callback refunds it in full.
- **Storage.** Every commit that passes the guards is stored for good (`commits` is append-only, `lib.rs:151`), and
  each `(hunter, invariant)` that gets an infra refund keeps one timestamp; the bounty account pays that storage from
  its own NEAR balance (4 NEAR on the demo bounty on 1 Nov; a stored commit is roughly 350 B ≈ 0.0035 NEAR, an estimate). A spammer who commits with an
  unregistered payout account is refunded in full and pays only gas, so a bounty can be run out of storage balance;
  anyone can top a keyless bounty up with a plain NEAR transfer. Charging storage to the hunter needs a contract change
  (not made: it would replace the global code hash the testnet evidence pins).
- **Commit hash case.** `commit` accepts any 64 hex digits (`lib.rs:248`), but the award compares that string with the
  verifier's lowercase `h_exploit` (`lib.rs:379`), so an uppercase commit can never be awarded and is refused as
  `commit mismatch` (bond slashed). `scripts/hunter.py` commits Python's lowercase `hexdigest()` (`hunter.py:122`).
  Normalizing in the contract is a code change (not made: it would replace the global code hash).
- **Verdict parsing.** `find_verdict` (`lib.rs:720`) takes the first JSON object carrying `h_enc`, parsing any string
  OutLayer wraps it in. Every verifier verdict serializes `h_enc` at its top level, error verdicts included
  (`verifier/src/lib.rs:118`), so the search stops at the verdict and never parses its `err` text (≤ 64 B, `MAX_ERR`).
- **Seal key reuse.** The seal's nonce is derived from `EPH_SK` (`seal.rs:5`), so a hunter client must draw a fresh
  `EPH_SK` per commit; `scripts/hunter.py` draws 32 random bytes each time.
- **No outside users yet.** The measured demo is our own hunter agent plus the fakes corpus.
- **Testnet only.** The mainnet leg (`scripts/mainnet_leg.py`) prints the commands; it never signs and has not run.
- **Baseline models.** `make baseline` used third-party models, not NEAR AI Cloud (`baseline/README.md`).
