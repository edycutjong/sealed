# Hunter agent run — force — muse-wonder-1.0 (cmd) — 2026-11-01

## Turn 1 — model reply (verbatim)

The bug is that the empty `Force` contract assumes it cannot receive ether because it has no payable or fallback function, but `SELFDESTRUCT` can force-send ether to any address. The creation transaction deploys minimal initcode that immediately self-destructs to the `Force` instance, forcibly transferring its creation value and making the instance balance greater than zero.

```json
[{"to": null, "data": "0x73d3264fed42a0dc00663d0aa2b0abb90a19b347f2ff", "value": "1000000000000000"}]
```

### Turn 1 — local verifier (committed verifier.wasm, wasmtime)

```
tx 1: success
validateInstance → 1
broken: True
```

**Result: invariant broken on turn 1.**

Next step on testnet (needs a funded hunter account and an open bounty on this invariant):
`python3 scripts/hunter.py --bounty <bounty> --hunter <account> --exploit hunter-agent/force-muse-wonder-1.0-exploit.json --label agent-force --invariant force-balance-nonzero`
