# LLM-only triage baseline

`make baseline` prints what an LLM that cannot run code would pay for, on the same 52-item corpus the verifier judged.
Ground truth is the verifier's golden verdict (it executes the submission and calls the level's `validateInstance`).

- **Prompt:** `python3 scripts/baseline.py prompt <item>` prints the exact text sent for one item: the level source, the
  bounty's goal, the submission bytes and, for the 15 LLM-written items only, the hunter's own claim. Answer: `VERDICT: PAY`
  or `VERDICT: REFUSE`. The same prompt went to every model; temperature is 0 on the qwen and DeepSeek calls, the muse and nemotron providers use their defaults.
- **Record:** `run.json` (one verdict per model per item), `transcripts/<model>/<item>.txt` (raw replies, verbatim).
  `make baseline` re-parses every transcript and prints `integrity: n/n` (that checks the record against the raw replies, not that
  the replies are genuine: re-run `record` to regenerate them).
- **Fakes:** `j of K` counts corpus items whose golden verdict is `broken:false`. K = 21 are the non-breaking submissions
  that also ran on testnet (the verifier paid 0 of them); the line below it covers all 37 non-breaking items.
- **Models (2026-11-01):** qwen3.8-omni-flash (Alibaba, default settings), muse-wonder-1.0 (Meta, reasoning medium; one item re-run
  with a larger output cap after the 4000-token cap truncated the reply), nemotron-3-ultra (NVIDIA, free tier via Kilo, tools
  denied). These three are third-party APIs, not private inference.
- **NEAR AI Cloud (2026-11-07):** `deepseek-ai/DeepSeek-V4.1-Flash-1017` (`--provider nearai`, temperature 0, `owned_by: nearai`).
  NEAR AI's model listing describes it as "Served privately from NEAR AI's attested TEE infrastructure." (the listing entry,
  as fetched on 2026-11-07, is saved in [nearai-model-listing.json](nearai-model-listing.json)). We did not verify
  any TEE attestation ourselves; that sentence is NEAR AI's claim, not something this repo checks. Long items that hit the
  default 300 s read timeout were re-run with `BASELINE_TIMEOUT=900`; `llm-muse-king` still got no reply after 3 tries at 900 s.
  `make baseline MODEL=<id>` adds another NEAR AI Cloud model (key in `~/.config/near-ai-cloud/api.key`).

## Read the numbers with these limits

- Only the 15 LLM-written items carry a claim; 10 of them really break a level and 5 are fakes. So the K = 21 fakes include just 5
  with a confident explanation, and every fake a triager paid here is one of those 5 (`make baseline` prints the split). The other
  32 non-breaking corpus items arrive with no explanation, which is a harder case for an approver to say yes to. The comparison is
  "can a model be talked into paying", not a full triage workflow.
- Two triagers also judged submissions written by their own family (qwen read qwen's, muse read muse's); no corpus item was
  written by nemotron or DeepSeek.
- A reply that cannot be parsed (or an API failure) is recorded as `None` and counted as not paying; `make baseline` names each one. Three exist: nemotron's `abuse-input` (a 49 KB fake; no VERDICT line, which would help the baseline), qwen's `real-king` (a real exploit; HTTP 403 on every try, and by the time it was retried DashScope reported the free quota exhausted, though the first failure's response body was not captured; this hurts the baseline), and DeepSeek's `llm-muse-king` (a real exploit; no reply after 3 tries with a 900 s read timeout; this hurts the baseline). The qwen row also cannot be re-run today for that reason.
- A triager that refuses everything would score 0 fakes; the line "of the 15 submissions that really break a level it would pay
  n" is the other half. The executing verifier pays 5 of 5 real exploits on the demo bounty.
- One retained reply per item and model (calls that timed out were retried; failed attempts are not kept); answered items were
  never re-asked, so there is no variance estimate.
