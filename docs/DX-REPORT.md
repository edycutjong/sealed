# Developer-experience report: building on OutLayer and NEAR global contracts

What it was like to build Sealed Exploit on OutLayer (verifier in an Intel TDX worker, called from a keyless NEAR
contract) and on NEAR global contracts, in the order we hit it. Each item says what we observed, how we got past it,
and what would have saved the time. Raw results are in `day0/results/`; the OutLayer source we read is
`github.com/out-layer/outlayer` at commit `aaf60a26` (2026-10-20 UTC). Everything ran on testnet.

## What worked well

- **The product path is real.** A pinned verifier was fetched by the worker, hash-checked, run, and its verdict came
  back through the contract's callback on chain. Worker-side execution of the same bytes gave the same verdict hash
  as native and wasmtime (`day0/results/day0.json`, check G3).
- **Verdict latency is predictable.** `make bench` reads OutLayer events: request to verdict p50 7.27 s, p95 10.85 s
  (`corpus/bench.json`).
- **Encrypted secrets fit the sealed-exploit shape.** A hunter's exploit is stored as a secret that only the pinned
  verifier run can read, and delivery to the protocol is a separate sealed box.
- **Global contracts make a keyless account practical.** An account created on a global code hash has zero access
  keys (check G9), which is what lets "no human can move the pool" be checked rather than promised.

## Friction, ordered by cost

| # | Where | What happened | What we did | What would have helped |
|---|---|---|---|---|
| 1 | Code source | Docs describe a `code_source` argument and a hash-only source. `request_execution` actually takes `source`, and there is no hash-only variant; pinned bytes are `{"WasmUrl": {url, hash, build_target}}`. | Read the OutLayer source and built the bounty around `WasmUrl` (url + hash fixed at init). | Docs matching the contract ABI; an example of a pinned-hash call. |
| 2 | Secret access control | Access rules are judged against the transaction signer. A keyless contract never signs, so a plain whitelist of the contract never admits it. | `And[Whitelist[hunter], Predecessor{Whitelist[bounty]}]` (`day0/secret.py`: `--access whitelist:<hunter> --via <bounty>`), plus the bounty setting `secrets_ref.account_id` to its predecessor so one bounty cannot run another's row. | A table of which access leaf checks signer vs predecessor. |
| 3 | Hosting the wasm | The pin is an https URL, sha256-checked by the worker. On day 0 we saw the FastFS testnet gateway return 502 for well over an hour (our probe log is not kept) and our NEARFS upload was never indexed by its gateway. | Used a public Vercel Blob URL. The hash makes the host untrusted. | A documented, supported host for testnet wasm; an uptime note for the gateway. |
| 4 | Failure shape | Every non-verdict (URL down, undecryptable secret, yield timeout, stale run) reaches the callback as a *successful* promise with bytes `null`; only the event log carries the reason. A contract cannot tell an infrastructure fault from a hunter fault. | One rule for all non-verdicts: refund the hunter once per invariant per 24 h, then slash. Hunter-caused cases (missing or oversized secret) are normal verdicts. | A distinct error arm or an error code in the callback payload. |
| 5 | Resource limits | Our first abuse run (JUMPDEST/PUSH0 loops under a 30 M gas cap) hit the worker's 2e9 instruction limit; that failing run was overwritten. Instructions per EVM gas differ by roughly 20x between opcodes (day-0 estimate: JUMPDEST loop ~42, KECCAK256 ~790 at `opt-level = 3`, ~2 700 at `opt-level = "s"`). | Fixed the verifier at `opt-level = 3`, no precompiles, a 600k-gas exploit budget plus 500k for `validateInstance`; worst abuse shape on chain is 23.98% of the instruction limit (`corpus/results.json`, `day0/results/g5b-fuel.json`). | A published instructions-per-opcode guide for revm-style workloads. |
| 6 | Storage deposits | A large input needs a refundable storage hold (day-0 estimates: about 0.18 NEAR at 49.7 KB vs 0.013 NEAR at 0.7 KB); an under-sized deposit failed with a bare `Err`. | `day0/callback.py` sizes the deposit from `estimate_execution_cost`. | The error naming the missing deposit. |
| 7 | CLI | `outlayer` CLI 0.2.1 attaches a fixed 0.1 NEAR deposit to `secrets set`, so large exploit rows fail. | A local patched CLI build reads `SEALED_SECRETS_DEPOSIT_YOCTO` (`day0/outlayer-cli-deposit.patch`); the stock CLI cannot store rows above a few KB. | A `--deposit` flag. |
| 8 | Trial key | In our day-0 test the trial key reached only curated connectors (`project_not_allowed` otherwise), so it could not run a custom wasm. | Used the NEAR-mode product path for all measurements. | State this on the trial-key page. |
| 9 | Global contract cost | Global code costs about 1e-4 NEAR per byte: a 166 KB probe was about 16.6 NEAR. A raw 373 KB build would be about 37 NEAR. | `wasm-opt -Oz` brought the bounty to 223 KB (222 745 B); the verifier is hosted off chain by hash. | A cost line in the global-contract docs. |
| 10 | near-sdk 5.9.0 | No `UseGlobalContract` promise action, so a factory *contract* cannot create keyless accounts. | The factory is a deploy script using a near-cli batch. | The action exposed in the SDK. |
| 11 | Toolchains | The contract wasm needs rustc 1.85.0 (near-sys 0.2.4 pin) while near-sdk's `unit-testing` feature needs 1.88 or newer. | Two pinned toolchains: wasm on 1.85.0, native contract tests on 1.97.1; the verifier on 1.97.1 with `--remap-path-prefix` so any clone rebuilds identical bytes. | One supported toolchain for sdk, tests and wasm. |
| 12 | Public RPC | `rpc.testnet.near.org` returned HTTP 429 to a shared IP during a full verification run; we saw archival requests throttled after a short burst. | FastNEAR archival endpoints by default, back-off on 429, `make verify` budgeted to about 80 calls, `make verify-demo` about 25 calls; an unreachable RPC exits 2 (RECORDED), never as a pass. | Documented archival rate limits. |

## Suggestions, ranked

1. Make the callback distinguish worker-answered failures from verdicts. Everything that pays out on a verdict has to
   handle this, and today it needs a convention per project.
2. Publish the `request_execution` ABI next to the docs, with the pinned-hash example.
3. Document the signer-vs-predecessor semantics of secret access rules.
4. Give testnet a supported place to host the pinned wasm.

## Method

Day-0 gate checks, scripts and raw JSON are in `day0/`; the fresh-clone checks that need no credentials are
`make doctor`, `make replay`, `make corpus` and `make refusals`.
