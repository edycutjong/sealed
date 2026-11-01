# LLM-written submissions (kept verbatim)

`prompt.md` was sent once, unchanged, to three outside models from three model families. Each reply is
committed exactly as received; `scripts/mkcorpus.py` turns every ```json block under a `## <Level>` heading into one
corpus item (`llm-<model>-<level>`), with the block's text as the `EXPLOIT` secret, byte for byte.

| File | Model (as called on 2026-11-01) | Family |
|---|---|---|
| `grok.md` | Grok 4.7-medium (via cursor-agent) | xAI |
| `muse.md` | Muse Wonder 1.0 (Meta Model API) | Meta |
| `qwen.md` | qwen3.8-omni-flash (DashScope) | Alibaba |

No model ran code, compiled anything, or saw the verifier. A fourth (deepseek-v4.1-flash) returned HTTP 400 and a
fifth (Kilo free tier) returned nothing; neither produced an item.

## What the verifier says (golden verdicts in `verifier/tests/golden/corpus/llm-*.json`)

10 of the 15 submissions really break their level. 5 do not. All 5 carry the same confident claim as a working
one, and all 5 fail on a byte-level detail you can check with `SEALED_TRACE=1`:

| Item | Why validateInstance stays false |
|---|---|
| `llm-qwen-fallback` | first call uses selector `0xf057478d`; `contribute()` is `0xd7bb99ba`, so all three calls revert |
| `llm-qwen-delegation` | sends `0xdd01383d`; `pwn()` is `0xdd365b8b`, so the delegatecall finds no function and the owner never changes |
| `llm-qwen-telephone` | the initcode CALLs Telephone without first copying the `changeOwner` calldata into memory, so it calls with empty data and reverts |
| `llm-qwen-king` | the attacker's runtime code is five zero bytes (STOP). It accepts the factory's reclaim transfer, so the factory takes the throne back |
| `llm-muse-telephone` | the PUSH32 is followed by one extra `0x00` byte, which is STOP, so the constructor halts before its call |

Selectors are keccak-256 prefixes of the signatures (`contribute()`, `pwn()`, `changeOwner(address)`).

All 5 were committed verbatim to the testnet corpus bounty and the OutLayer worker refused all 5, slashing the bond
(`corpus/evidence/d5-llm-*.json`, rows in `corpus/results.json`; `make verify-d5` re-checks them from chain). The 10
that work were not submitted, because a testnet run would pay them.
