# Security policy

Sealed Exploit is a hackathon project on NEAR **testnet**. Nothing here holds mainnet funds.

**Report a vulnerability** with a private GitHub security advisory on this repository
(Security tab → Report a vulnerability). Please do not open a public issue for a suspected flaw in the bounty
contract (`contracts/bounty`) or the verifier (`verifier/`).

In scope: a way to be paid without a verified break, to move a reserved payout, to make the contract pay twice, or to
make the verifier give a different verdict than the pinned `verifier.wasm`. The invariants are tested as I1–I8 in
`contracts/itests`; `ARCHITECTURE.md` lists the known limits.

Secrets never live in this repository: credentials are read from `~/.config/`, and CI runs gitleaks over the full
history with `.gitleaks.toml`.

## Known dependency advisories (reviewed 2026-11-03)

| Advisory | Where | Decision |
|---|---|---|
| `wee_alloc` unmaintained (RUSTSEC-2022-0054), no patched version | near-sdk 5.9.0's default allocator inside `contracts/bounty.wasm` | Kept. That wasm (sha256 `5d79f36d…`) is the deployed testnet global code every PAID/REFUSED receipt verifies against; swapping the allocator changes those bytes. Informational advisory, no CVE; each NEAR call runs in a fresh wasm instance. |
| `wee_alloc`, same advisory | `day0/probe` (day-0 feasibility probe, not the product) | Kept, same reason. |
| `lru` `IterMut` Stacked Borrows (fixed in 0.16) | pulled only by `near-vm-runner`, near-sdk's host-side unit-test VM | Not in the wasm32 dependency graph (`cargo tree -i lru --target wasm32-unknown-unknown` is empty); 0.16 is a major bump near-sdk 5.9.0 cannot take. |

`cargo audit` runs in CI (Stage 2) and reports these; it does not block, because fixing them means moving the pinned
`verifier.wasm` / `bounty.wasm` bytes that the on-chain evidence names.
