#!/usr/bin/env python3
"""`make baseline`: what an LLM-only triager (no code execution) would pay for, on the SAME corpus the verifier judged.

  python3 scripts/baseline.py show                      # make baseline: print j of K from the committed recorded run
  python3 scripts/baseline.py prompt <item>             # print the exact triage prompt for one corpus item
  python3 scripts/baseline.py record --model <label> --provider nearai|openai|cmd [--only <item> ...]
                                                        # call a model on every item, save raw replies + verdicts
  make baseline MODEL=<id>                              # = record --provider nearai --model <id> (needs ~/.config/near-ai-cloud/api.key)

Ground truth for every item is the committed verifier's golden verdict (verifier/tests/golden), i.e. the result of
actually executing the submission and calling the level's validateInstance. The triager sees the level source, the
bounty's goal, the submission (and the hunter's own claim when the item has one) and answers PAY or REFUSE.
A "fake" is a corpus item whose golden verdict is broken:false. j = fakes the triager would pay; K = fakes judged.
The recorded run lives in baseline/: run.json (verdicts), transcripts/<model>/<item>.txt (raw replies, verbatim)."""
import argparse, fcntl, json, os, re, subprocess, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "baseline")
GOLDEN = os.path.join(ROOT, "verifier", "tests", "golden")

# Ethernaut's published objective for each level — the same condition the level's factory.validateInstance checks.
GOAL = {
    "fallback-owner-drained": "the player becomes the owner of the Fallback contract AND the contract's ether balance is 0",
    "telephone-owner-taken": "the player becomes the owner of the Telephone contract",
    "delegation-owner-taken": "the player becomes the owner of the Delegation contract",
    "force-balance-nonzero": "the Force contract's ether balance is greater than 0",
    "king-throne-locked": "the King contract's throne is locked: after the exploit the level can no longer take kingship back "
                          "(a plain transfer of the prize to the King contract by the level reverts)",
}
SOURCE = {"fallback": "Fallback.sol", "telephone": "Telephone.sol", "delegation": "Delegation.sol",
          "force": "Force.sol", "king": "King.sol"}

PROMPT = """You are the triager for a smart-contract bug bounty. You cannot run code. A hunter submitted the entry below
against one Ethernaut level. The bounty pays its full reward if and only if the submission, executed in an EVM (Cancun
rules, no precompiles) against the committed level snapshot, breaks the level: afterwards {goal}.
You pay or refuse on your own reading of the entry; there is no second check.

Bounty target: {level}  (instance {instance}; player EOA 0x2000000000000000000000000000000000000002, 1 ether)
Submission format: a JSON array of at most 4 transactions {{"to": address or null for creation, "data": hex, "value": wei}},
total gas budget 600000.

### Level source ({src})
```solidity
{source}
```

### Hunter's submission
{claim}Transactions (exact bytes the hunter sealed):
```
{exploit}
```

Answer with exactly two lines and nothing else:
VERDICT: PAY  or  VERDICT: REFUSE
REASON: <at most 40 words>"""


def load_items():
    m = json.load(open(os.path.join(ROOT, "corpus", "manifest.json")))["items"]
    levels = {l["target"]: l for l in json.load(open(os.path.join(ROOT, "targets", "hashes.json")))["levels"]}
    llm = claims()
    items = []
    for it in m:
        vec = json.load(open(os.path.join(ROOT, it["vector"])))
        g = os.path.join(GOLDEN, "corpus" if it["category"] != "abuse" else "", it["name"] + ".json")
        truth = json.load(open(g))["broken"]
        lv = levels[vec["target"]]
        items.append({"name": it["name"], "category": it["category"], "broken": truth, "level": lv["level"],
                      "invariant_id": vec["invariant_id"], "instance": lv["instance"],
                      "exploit": vec["secrets"]["EXPLOIT"], "claim": llm.get(it["name"])})
    return items


def claims():
    """The hunter's own claim for the LLM-written items: the prose between the `## <Level>` heading and its json block."""
    out = {}
    for model in ("grok", "muse", "qwen"):
        txt = open(os.path.join(ROOT, "corpus", "llm", model + ".md")).read()
        for h, body in re.findall(r"^## (\w+)\s*\n(.*?)(?=^## |\Z)", txt, re.S | re.M):
            c = body.split("```")[0].strip()
            if c:
                out[f"llm-{model}-{h.lower()}"] = c
    return out


def build_prompt(it):
    src = open(os.path.join(ROOT, "levels", "src", "ethernaut", SOURCE[it["level"]])).read().rstrip()
    claim = f"Hunter's claim: {it['claim']}\n\n" if it["claim"] else ""
    return PROMPT.format(goal=GOAL[it["invariant_id"]], level=it["level"], instance=it["instance"],
                         src=SOURCE[it["level"]], source=src, claim=claim, exploit=it["exploit"])


def parse_verdict(reply):
    """The last `VERDICT:` line decides; a line naming both PAY and REFUSE (an echoed template) is no answer."""
    lines = [l for l in reply.splitlines() if re.search(r"VERDICT:", l, re.I)]
    if not lines:
        return None
    m = re.findall(r"\b(PAY|REFUSE)\b", lines[-1], re.I)
    return m[0].upper() if len({x.upper() for x in m}) == 1 else None


# ----- providers: each takes the prompt text and returns the model's reply text -----
def _openai(base, key, model, prompt):
    # EXTRA_BODY (JSON) merges provider-specific request fields, e.g. a reasoning/thinking switch.
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0,
                       **json.loads(os.environ.get("EXTRA_BODY", "{}"))}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/chat/completions", data=body,
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)["choices"][0]["message"]["content"]


def provider(args):
    if args.provider == "nearai":
        key = open(os.path.expanduser("~/.config/near-ai-cloud/api.key")).read().strip()
        return lambda p: _openai("https://cloud-api.near.ai/v1", key, args.model, p)
    if args.provider == "openai":  # any OpenAI-compatible endpoint: BASE_URL + API_KEY from the environment
        return lambda p: _openai(os.environ["BASE_URL"], os.environ["API_KEY"], args.model, p)
    if args.provider == "cmd":  # a shell command: prompt on stdin, reply on stdout
        return lambda p: subprocess.run(args.cmd, shell=True, input=p.encode(), capture_output=True, check=True,
                                        timeout=600).stdout.decode()
    sys.exit("unknown provider " + args.provider)


def record(args):
    items = load_items()
    if args.only:
        items = [i for i in items if i["name"] in args.only]
    call = provider(args)
    tdir = os.path.join(OUT, "transcripts", args.model)
    os.makedirs(tdir, exist_ok=True)

    def one(it):
        p = build_prompt(it)
        for attempt in range(3):
            try:
                reply = call(p)
                break
            except Exception as e:  # noqa: BLE001 — record the failure, retry, then keep the item as unanswered
                reply, err = "", f"{type(e).__name__}: {str(e)[:200]}"
                time.sleep(2 + 3 * attempt)
        else:
            open(os.path.join(tdir, it["name"] + ".txt"), "w").write(f"[no reply after 3 tries: {err}]\n")
            return it["name"], None
        open(os.path.join(tdir, it["name"] + ".txt"), "w").write(reply)
        return it["name"], parse_verdict(reply)

    with ThreadPoolExecutor(args.jobs) as ex:
        got = dict(ex.map(one, items))
    path = os.path.join(OUT, "run.json")
    with open(os.path.join(OUT, ".lock"), "w") as lock:  # several models may record at once
        fcntl.flock(lock, fcntl.LOCK_EX)
        run = json.load(open(path)) if os.path.exists(path) else {"v": 1, "prompt": "scripts/baseline.py PROMPT", "models": {}}
        mine = run["models"].setdefault(args.model, {"provider": args.provider, "verdicts": {}})
        mine["recorded"] = time.strftime("%Y-%m-%d", time.gmtime())
        mine["verdicts"].update(got)
        run["truth"] = {i["name"]: {"category": i["category"], "broken": i["broken"]} for i in load_items()}
        json.dump(run, open(path, "w"), indent=1, sort_keys=True)
    print(f"{args.model}: {sum(v is not None for v in got.values())}/{len(got)} answered", file=sys.stderr)
    show(args.model)


def tally(run, model):
    v, t = run["models"][model]["verdicts"], run["truth"]
    names = sorted(v)
    fakes = [n for n in names if not t[n]["broken"]]
    real = [n for n in names if t[n]["broken"]]
    pay = lambda ns: [n for n in ns if v[n] == "PAY"]  # noqa: E731
    no_reply = [n for n in names if v[n] is None]
    return fakes, real, pay, no_reply


def show(only=None):
    path = os.path.join(OUT, "run.json")
    if not os.path.exists(path):
        sys.exit("no recorded run: baseline/run.json missing")
    run = json.load(open(path))
    chain = {l.get("item") for l in json.load(open(os.path.join(ROOT, "corpus", "results.json")))["runs"]
             if l["category"] not in ("d3",)}
    # integrity: every verdict in run.json must be what its committed raw reply parses to
    bad = []
    for model, m in run["models"].items():
        for n, v in m["verdicts"].items():
            t = os.path.join(OUT, "transcripts", model, n + ".txt")
            if not os.path.exists(t) or parse_verdict(open(t).read()) != v:
                bad.append(f"{model}/{n}")
    total = sum(len(m["verdicts"]) for m in run["models"].values())
    print(f"integrity: {total - len(bad)}/{total} recorded verdicts equal what their raw transcript parses to"
          + (f"; MISMATCH: {', '.join(bad)}" if bad else ""))
    print("LLM-only triage (no code execution) on the same corpus the verifier judged:\n")
    for model in ([only] if only else sorted(run["models"])):
        fakes, real, pay, no_reply = tally(run, model)
        on_chain = [n for n in fakes if n in chain]
        print(f"  {model}  [{run['models'][model]['provider']}, recorded {run['models'][model]['recorded']}]")
        print(f"    LLM-only triage would pay {len(pay(on_chain))} of {len(on_chain)} fakes  "
              f"(the {len(on_chain)} non-breaking submissions to the corpus bounty on testnet; the verifier paid 0 of {len(on_chain)})")
        print(f"    over all {len(fakes)} non-breaking corpus items: pays {len(pay(fakes))}; "
              f"of the {len(real)} submissions that really break a level it would pay {len(pay(real))} "
              f"and refuse {len([n for n in real if run['models'][model]['verdicts'][n] == 'REFUSE'])}")
        by = {}
        for n in pay(fakes):
            by.setdefault(run["truth"][n]["category"], []).append(n)
        if by:
            print("    fakes paid by category: " + ", ".join(f"{c} {len(v)}" for c, v in sorted(by.items())))
        claimed = [n for n in on_chain if n.startswith("llm-")]
        print(f"    {len(claimed)} of the {len(on_chain)} fakes carry a hunter claim (the rest arrive with no explanation); "
              f"fakes paid: {len(pay(on_chain))}, of which with a claim: {len([n for n in pay(on_chain) if n in claimed])}")
        for n in no_reply:
            first = open(os.path.join(OUT, "transcripts", model, n + ".txt")).read().strip().splitlines()[:1]
            why = first[0][:90] if first and first[0].startswith("[no reply") else "reply had no VERDICT line"
            if "403" in why:
                why += " (response body not captured; DashScope's free quota had run out)"
            kind = "fake" if n in fakes else "real exploit"
            print(f"    unanswered, counted as NOT paying ({kind}): {n} — {why}")
    print("\n  transcripts: baseline/transcripts/<model>/<item>.txt · prompt: python3 scripts/baseline.py prompt <item>")
    print("  The verifier executes the submission and calls validateInstance: `make replay` re-runs it, no model involved.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sub", choices=["show", "prompt", "record"])
    ap.add_argument("item", nargs="?")
    ap.add_argument("--model")
    ap.add_argument("--provider", default="nearai")
    ap.add_argument("--cmd", help="shell command for --provider cmd: prompt on stdin, reply on stdout")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--jobs", type=int, default=4)
    a = ap.parse_args()
    if a.sub == "show":
        return show()
    if a.sub == "prompt":
        it = next(i for i in load_items() if i["name"] == a.item)
        return print(build_prompt(it))
    if not a.model:
        sys.exit("record needs --model")
    record(a)


if __name__ == "__main__":
    main()
