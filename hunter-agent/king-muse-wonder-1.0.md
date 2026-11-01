# Hunter agent run — king — muse-wonder-1.0 (cmd) — 2026-11-01

## Turn 1 — model reply (verbatim)

The bug is that `King.receive()` pushes the prize to the previous king with `.transfer()` before updating `king`, so if the current king is a contract that always reverts on receiving Ether, every subsequent attempt to claim the throne reverts. My transaction deploys such a reverting contract whose constructor claims kingship with 0.1 ether, making that contract king and permanently blocking the level's reclaim transfer.

```json
[{"to": null, "data": "0x60006000600060003473d3264fed42a0dc00663d0aa2b0abb90a19b347f25af1156030576005603660003960056000f35b60006000fd60006000fd", "value": "100000000000000000"}]
```

### Turn 1 — local verifier (committed verifier.wasm, wasmtime)

```
tx 1: success data 0x60006000fd
validateInstance → 1
broken: True
```

**Result: invariant broken on turn 1.**

Next step on testnet (needs a funded hunter account and an open bounty on this invariant):
`python3 scripts/hunter.py --bounty <bounty> --hunter <account> --exploit hunter-agent/king-muse-wonder-1.0-exploit.json --label agent-king --invariant king-throne-locked`
