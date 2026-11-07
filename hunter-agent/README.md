# Hunter agent runs

`scripts/hunter_agent.py` asks a model for an exploit, runs it through the committed `verifier.wasm` locally (the wasm the
TEE worker runs), and feeds back what a local EVM run prints (each transaction's outcome, what `validateInstance`
returned). The whole conversation (task, each earlier answer, each local-run output) goes into every later prompt, up to 4
turns. The model only proposes; the bounty still pays only what the verifier executes. A winning submission can be
committed with `scripts/hunter.py --exploit hunter-agent/<file>.json` (needs an open bounty and a funded hunter account).

| Level | muse-wonder-1.0, reasoning medium | muse-wonder-1.0, reasoning low | DeepSeek-V4.1-Flash-1017 on NEAR AI Cloud |
|---|---|---|---|
| fallback | broken, turn 1 | broken, turn 1 | broken, turn 1 (re-run after a provider timeout) |
| telephone | broken, turn 1 | broken, **turn 2** (turn 1 transacted but `validateInstance` returned 0) | broken, turn 1 (re-run after a provider timeout) |
| delegation | broken, turn 1 | broken, turn 1 | broken, turn 1 |
| force | broken, turn 1 | broken, turn 1 | broken, turn 1 |
| king | broken, turn 1 | broken, turn 1 (second sample) | **provider error** on turn 1 (read timeout at 900 s, 3 tries; not a model result) |
| **found** | **5 of 5** | **5 of 5** | **4 of 4 answered** (king: no answer) |

Every transcript is `<level>-<model>.md` (replies verbatim, local verifier output after each turn); each winning
submission is `<level>-<model>-exploit.json`, and all 14 re-ran as `broken:true` through the committed verifier after
extraction (`make replay INPUT=<file>`, with the tx array wrapped as `{"target", "invariant_id", "txs"}` from
`targets/hashes.json`). `telephone-muse-wonder-1.0-low.md` shows the agent changing course for a stated reason: "I was wrong because the
local run shows the transaction succeeded but validateInstance returned 0 …", then a different submission that breaks it.

**Which runs are NEAR AI Cloud.** The two muse columns used Meta's Muse API; they are not private-inference runs and must not
be described as such. The DeepSeek column (2026-11-07) used `--provider nearai --model deepseek-ai/DeepSeek-V4.1-Flash-1017`,
a NEAR-AI-owned model that NEAR AI's model listing describes as "Served privately from NEAR AI's attested TEE
infrastructure." We did not verify any TEE attestation ourselves.

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
- DeepSeek on NEAR AI Cloud: `fallback` and `telephone` first ran with the default 300 s read timeout; each failed turn 1 and
  then hit a provider timeout on turn 2. Both were re-run with a 900 s timeout (`BASELINE_TIMEOUT=900`), which broke each on
  turn 1, and the re-run overwrote the first transcript, so those first attempts are not kept. `king` timed out on turn 1 at
  900 s three times: a provider error, not a model result.
- The levels are textbook Ethernaut; none of this says anything about live protocols.
