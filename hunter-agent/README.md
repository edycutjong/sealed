# Hunter agent runs

`scripts/hunter_agent.py` asks a model for an exploit, runs it through the committed `verifier.wasm` locally (the wasm the
TEE worker runs), and feeds back what a local EVM run prints (each transaction's outcome, what `validateInstance`
returned). The whole conversation (task, each earlier answer, each local-run output) goes into every later prompt, up to 4
turns. The model only proposes; the bounty still pays only what the verifier executes. A winning submission can be
committed with `scripts/hunter.py --exploit hunter-agent/<file>.json` (needs an open bounty and a funded hunter account).

| Level | muse-wonder-1.0, reasoning medium | muse-wonder-1.0, reasoning low |
|---|---|---|
| fallback | broken, turn 1 | broken, turn 1 |
| telephone | broken, turn 1 | broken, **turn 2** (turn 1 transacted but `validateInstance` returned 0) |
| delegation | broken, turn 1 | broken, turn 1 |
| force | broken, turn 1 | broken, turn 1 |
| king | broken, turn 1 | broken, turn 1 (second sample) |
| **found** | **5 of 5** | **5 of 5** |

Every transcript is `<level>-<model>.md` (replies verbatim, local verifier output after each turn); each winning
submission is `<level>-<model>-exploit.json`, and all 10 re-ran as `broken:true` through the committed verifier after
extraction. `telephone-muse-wonder-1.0-low.md` shows the agent changing course for a stated reason: "I was wrong because the
local run shows the transaction succeeded but validateInstance returned 0 …", then a different submission that breaks it.

**Not NEAR AI Cloud.** These runs used Meta's Muse API because no NEAR AI Cloud key exists on this machine
(run `--provider nearai --model <id>` with a key to add that row). They are not
private-inference runs and must not be described as such.

**Honest history.**
- One kept run per cell. Muse is not deterministic, and two cells were resampled, so read the 10 cells as "a capable model usually
  finds these five textbook levels", not as a success rate. `king` with reasoning low is a second sample: its first sample failed
  all 4 turns, and the resample (listed) broke it on turn 1. `telephone` with reasoning low is also a second run (its first
  failed all 4 turns); the listed one broke it on turn 2.
- Why those two were rerun: an earlier version of the loop dropped the conversation after turn 1, so every run it produced was
  discarded. That bug could not have caused `king`'s failure on turn 1 (turn 1 has no history), so that resample is plain
  best-of-two. A qwen3.8-omni-flash set (thinking off) was discarded too and could not be redone, because DashScope's free quota
  ran out on 2026-11-01; qwen has no row here.
- Also discarded: a first `fallback` run made before the trace feedback worked, and a first `king` run (reasoning medium) whose
  replies the 4000-token output cap truncated; `king` was rerun with a 12000-token cap (`MUSE_MAX_TOKENS`).
- The levels are textbook Ethernaut; none of this says anything about live protocols.
