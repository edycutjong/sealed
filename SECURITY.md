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
