#!/usr/bin/env python3
"""Write corpus/results.json from what is already on disk — no network, no credentials:
corpus/published/*.json (runs) + corpus/evidence/*.json (chain data: commit, worker resolve, deliver) +
corpus/refusals.json + corpus/manifest.json (category, designed verdict) + contracts/results/d5-*.json.

Every number in the summary is counted from those files; `make verify` re-fetches each tx from an archival node.
usage: python3 scripts/results.py   (prints the summary; exit 1 if a chain verdict disagrees with its golden)"""
import glob, json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTNET = "https://testnet.nearblocks.io/txns/"


def load(p):
    return json.load(open(os.path.join(ROOT, p)))


def status(s):
    return s if isinstance(s, str) else next(iter(s))


def main():
    items = {i["name"]: i for i in load("corpus/manifest.json")["items"]}
    runs, bad = [], []
    for p in sorted(glob.glob(os.path.join(ROOT, "corpus", "published", "*.json"))):
        pub = json.load(open(p))
        ev = load(f"corpus/evidence/{pub['label']}.json")
        name = pub["exploit_name"].removeprefix("corpus:")
        item = items.get(name, {"category": "d3", "level": "fallback", "expect": None})
        chain = json.loads(ev["verdict_output"]) if isinstance(ev.get("verdict_output"), str) else ev.get("verdict_output")
        done = (ev.get("execution_completed") or [{}])[0].get("data", [{}])[0]
        res = done.get("resources_used", {})
        golden = None
        gpath = os.path.join(ROOT, "verifier", "tests", "golden", "corpus", f"{name}.json")
        if os.path.exists(gpath):
            golden = json.load(open(gpath))
        row = {
            "label": pub["label"], "bounty": pub["bounty"], "item": name, "category": item["category"],
            "level": item["level"], "invariant_id": pub["input"]["invariant_id"], "expect": item["expect"],
            "final_status": status(pub["final_status"]),
            "chain_verdict": {k: chain.get(k) for k in ("broken", "err", "gas_used")} if chain else None,
            "commit_tx": ev["commit_tx"], "request_id": ev.get("request_id"),
            "resolve_tx": (ev.get("resolve") or {}).get("tx"), "deliver_tx": ev.get("deliver_tx"),
            "instructions": res.get("instructions"), "time_ms": res.get("time_ms"), "timing_s": pub.get("timing_s"),
        }
        # The chain verdict must equal the committed golden (same verifier bytes, different SALT → compare the
        # verdict fields that do not depend on the secrets).
        if golden and chain and (golden["broken"], golden["err"], golden["gas_used"]) != \
                (chain["broken"], chain["err"], chain["gas_used"]):
            bad.append(pub["label"])
            row["golden_mismatch"] = True
        runs.append(row)

    refusals = load("corpus/refusals.json")["refusals"] if os.path.exists(
        os.path.join(ROOT, "corpus", "refusals.json")) else []
    kinds = sorted({r["kind"] for r in refusals if r["matched"]})
    fake_refusals = [r for r in runs if r["final_status"] == "Refused" and r["chain_verdict"]
                     and not r["chain_verdict"]["broken"]]
    for r in fake_refusals:  # the 'fake' kind: a worker verdict of no break, bond slashed
        if "fake" not in kinds:
            kinds.append("fake")
    bounties = {}
    for p in sorted(glob.glob(os.path.join(ROOT, "contracts", "results", "d5-*.json"))):
        d = json.load(open(p))
        bounties[d["bounty_account"]] = {"create_tx": d.get("create_tx"), "global_hash": d.get("global_hash"),
                                         "access_keys": len(d.get("access_keys", [])),
                                         "invariants": [i["id"] for i in d["config"]["invariants"]],
                                         "deliver_ttl_ns": d["config"]["deliver_ttl_ns"],
                                         "verifier_wasm_hash": d["config"]["verifier_wasm_hash"]}

    d5 = [r for r in runs if r["label"].startswith("d5-")]
    real = [r for r in d5 if r["category"] == "real" and r["bounty"].startswith("demo.")]
    fakes = [r for r in d5 if r["expect"] is not None and not r["expect"]["broken"]
             or r["category"] == "llm" and r["chain_verdict"] and not r["chain_verdict"]["broken"]]
    llm_paid = [r for r in d5 if r["category"] == "llm" and r["final_status"] == "Paid"]
    summary = {
        "real_paid_demo_bounty": f"{sum(r['final_status'] == 'Paid' for r in real)} of {len(real)}",
        "non_breaking_submissions_paid": f"{sum(r['final_status'] == 'Paid' for r in fakes)} of {len(fakes)}",
        "non_breaking_submissions_refused": f"{sum(r['final_status'] == 'Refused' for r in fakes)} of {len(fakes)}",
        "llm_written_paid": len(llm_paid),
        "refusal_kinds_on_chain": f"{len(set(kinds))} of 6",
        "runs": len(runs), "golden_mismatches": bad,
        "max_instructions": max((r["instructions"] or 0) for r in d5) if d5 else None,
    }
    out = {"v": 1, "network": "testnet", "explorer": TESTNET, "summary": summary, "bounties": bounties,
           "refusal_kinds": sorted(set(kinds)), "refusals": refusals, "runs": runs}
    json.dump(out, open(os.path.join(ROOT, "corpus", "results.json"), "w"), indent=1)
    print(json.dumps(summary, indent=1))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
