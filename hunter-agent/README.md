# Hunter agent runs

`scripts/hunter_agent.py` asks a model for an exploit, runs it through the committed `verifier.wasm` locally (the wasm the
TEE worker runs), and feeds back what a local EVM run prints (each transaction's outcome, what `validateInstance`
returned). It revises up to 4 turns. The model only proposes; the bounty still pays only what the verifier executes. A
winning submission can be committed with `scripts/hunter.py --exploit hunter-agent/<file>.json` (needs an open bounty).

| Level | muse-wonder-1.0 (reasoning medium) | muse-wonder-1.0-low (reasoning low) | qwen3.8-omni-flash (thinking off) |
|---|---|---|---|
| fallback | broken, turn 1 | broken, turn 1 | not broken, 4 turns |
| telephone | broken, turn 1 | not broken, 4 turns | not broken, 4 turns |
| delegation | broken, turn 1 | broken, turn 1 | not broken, 4 turns |
| force | broken, turn 1 | broken, turn 1 | not broken, 4 turns |
| king | broken, turn 1 | not broken, 4 turns | not broken, 4 turns |
| **found** | **5 of 5** | **3 of 5** | **0 of 5** |

Every transcript is `<level>-<model>.md` (replies verbatim, local verifier output after each). Each winning submission is
`<level>-<model>-exploit.json`; all 8 re-ran as `broken:true` through the committed verifier after extraction (2026-11-01).

**Not NEAR AI Cloud.** These runs used other providers because no NEAR AI Cloud key exists on this machine
(`submission/HUMAN-TODO.md` is the owner's list; run `--provider nearai --model <id>` with a key to add that row). They are
not private-inference runs and must not be described as such.

**Honest history.** One run per cell, kept as it came out, with two exceptions: the first `fallback` run with muse ran before
the trace feedback worked and was re-run; the first `king` run with muse failed because the 4000-token output cap truncated its
replies before the JSON block, so it was re-run with a 12000-token cap (`MUSE_MAX_TOKENS`) and broke the level on turn 1.
Neither discarded run is kept. In the failed cells the model did revise ("I was wrong because …") and still missed, which is
what the verifier gate is for: a wrong agent costs the hunter a bond, never the protocol.
