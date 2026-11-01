# LLM-only triage baseline

`make baseline` prints what an LLM that cannot run code would pay for, on the same 52-item corpus the verifier judged.
Ground truth is the verifier's golden verdict (it executes the submission and calls the level's `validateInstance`).

- **Prompt:** `python3 scripts/baseline.py prompt <item>` prints the exact text sent for one item: the level source, the
  bounty's goal, the submission bytes and, for the 15 LLM-written items only, the hunter's own claim. Answer: `VERDICT: PAY`
  or `VERDICT: REFUSE`. The same prompt went to every model; temperature is 0 on the qwen call, the muse and nemotron providers use their defaults.
- **Record:** `run.json` (one verdict per model per item), `transcripts/<model>/<item>.txt` (raw replies, verbatim).
  `make baseline` re-parses every transcript and prints `integrity: n/n` (that checks the record against the raw replies, not that
  the replies are genuine: re-run `record` to regenerate them).
- **Fakes:** `j of K` counts corpus items whose golden verdict is `broken:false`. K = 21 are the non-breaking submissions
  that also ran on testnet (the verifier paid 0 of them); the line below it covers all 37 non-breaking items.
- **Models (2026-11-01):** qwen3.8-omni-flash (Alibaba, default settings), muse-wonder-1.0 (Meta, reasoning medium; one item re-run
  with a larger output cap after the 4000-token cap truncated the reply), nemotron-3-ultra (NVIDIA, free tier via Kilo, tools
  denied). **None of these is NEAR AI Cloud**, so none of this is private inference. `make baseline MODEL=<id>` adds a NEAR AI
  Cloud model once `~/.config/near-ai-cloud/api.key` exists.

## Read the numbers with these limits

- Only the 15 LLM-written items carry a claim; 10 of them really break a level and 5 are fakes. So the K = 21 fakes include just 5
  with a confident explanation, and every fake a triager paid here is one of those 5 (`make baseline` prints the split). The other
  32 non-breaking corpus items arrive with no explanation, which is a harder case for an approver to say yes to. The comparison is
  "can a model be talked into paying", not a full triage workflow.
- The three triagers also judged submissions written by their own family (qwen read qwen's, muse read muse's).
- A reply that cannot be parsed (or an API failure) is recorded as `None` and counted as not paying; `make baseline` names each one. Two exist: nemotron's `abuse-input` (a 49 KB fake; no VERDICT line, which would help the baseline) and qwen's `real-king` (a real exploit; DashScope's free quota ran out, which hurts the baseline). The qwen row also cannot be re-run today for that reason.
- A triager that refuses everything would score 0 fakes; the line "of the 15 submissions that really break a level it would pay
  n" is the other half. The executing verifier pays 5 of 5 real exploits on the demo bounty.
- Prompts, replies and verdicts are one run each; no repeats, so there is no variance estimate.
