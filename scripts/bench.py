#!/usr/bin/env python3
"""`make bench`: latency p50/p95 and verifier resources vs the enforced limits, from the recorded testnet runs.

Every number comes from the evidence bundles (corpus/evidence/*.json), never from a local stopwatch:
  verdict_s     OutLayer's own on-chain events: execution_completed.timestamp − execution_requested.timestamp
                (ns, both emitted by outlayer.testnet; the request → resolve leg of a commit)
  instructions  resources_used.instructions from the worker's resolve_execution args, vs lim.i (the cap the
                verifier saw enforced — the same 2e9 the bounty requested)
  time_ms       resources_used.time_ms from the same resolve args, vs lim.s × 1000
  mem           the verifier's own peak linear memory (verdict lim.mem) vs lim.m MB — OutLayer reports no
                worker memory figure, so this is verifier-reported, not independently observed
`--chain` re-reads each resolve_execution tx and the block headers from an archival RPC: resources_used must
equal the bundle, and it adds block-time latencies commit tx block → resolve block (commit_to_verdict_s) and,
for paid runs, commit tx block → PAID receipt block (commit_to_paid_s; this includes the hunter's own delay
before `deliver`, scripted to fire right after the verdict) and deliver tx block → PAID block.
Percentiles are nearest-rank (p95 of 29 runs = the 28th smallest). Committed record: corpus/bench.json;
without `--write` the recomputed sections must equal it (exit 1 otherwise). Exit 2 = `--chain` with the RPC
unreachable (nothing checked)."""
import argparse, base64, glob, json, math, os, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "day0"))
import near  # noqa: E402

OUT = os.path.join(ROOT, "corpus", "bench.json")


def pct(xs, p):
    s = sorted(xs)
    return s[max(0, math.ceil(p / 100 * len(s)) - 1)]


def stats(xs, cap=None):
    out = {"n": len(xs), "p50": pct(xs, 50), "p95": pct(xs, 95), "max": max(xs)}
    if cap:
        out["max_pct_of_limit"] = round(100 * max(xs) / cap, 2)
    return out


def kind(ev):
    if any(l.startswith("PAID ") for l in ev.get("deliver_logs") or []):
        return "PAID"
    if ev.get("expire_tx"):
        return "EXPIRED"
    return "REFUSED"


def offline_row(ev):
    req = ev["execution_requested"]
    done = ev["execution_completed"][0]["data"][0]
    used = ev["resolve"]["args"]["response"]["resources_used"]
    lim = json.loads(ev["verdict_output"])["lim"]
    return {"label": ev["label"], "kind": kind(ev),
            "verdict_s": round((done["timestamp"] - req["timestamp"]) / 1e9, 2),
            "instructions": used["instructions"], "time_ms": used["time_ms"], "mem_bytes": lim["mem"],
            "lim": {"i": lim["i"], "m": lim["m"], "s": lim["s"]}}


PACE_S = 0.5  # public archival nodes rate-limit shared IPs (HTTP 429); ~90 calls stay under it at this pace


def block_ts(block, url):
    time.sleep(PACE_S)
    r = near.rpc("block", {"block_id": block}, url)
    if "result" not in r:
        raise RuntimeError(f"block {block}: {json.dumps(r)[:200]}")
    return r["result"]["header"]["timestamp"]


def chain_row(ev, row, url):
    """Re-read the resolve tx + block headers; returns (chain fields, list of mismatches)."""
    bad = []
    time.sleep(PACE_S)
    res = near.tx(ev["resolve"]["tx"], ev["resolve"]["signer"], url)
    if "result" not in res:
        return {}, [f"resolve tx {ev['resolve']['tx']} not found"]
    used = None
    for a in res["result"]["transaction"]["actions"]:
        fc = a.get("FunctionCall") or {}
        if fc.get("method_name") == ev["resolve"]["method"]:
            args = json.loads(base64.b64decode(fc["args"]))
            used = (args.get("response") or {}).get("resources_used")
    if not used or used.get("instructions") != row["instructions"] or used.get("time_ms") != row["time_ms"]:
        bad.append(f"resources_used on chain {used} != bundle {row['instructions']}/{row['time_ms']}")
    t_commit = block_ts(ev["commit_tx_status"]["transaction_outcome"]["block_hash"], url)
    t_resolve = block_ts(ev["resolve"]["block_height"], url)
    out = {"label": row["label"], "commit_to_verdict_s": round((t_resolve - t_commit) / 1e9, 2)}
    if row["kind"] == "PAID":
        st = ev["deliver_tx_status"]
        paid = [ro["block_hash"] for ro in st["receipts_outcome"]
                if any(l.startswith("PAID ") for l in ro["outcome"]["logs"])]
        t_paid = block_ts(paid[0], url)
        t_deliver = block_ts(st["transaction_outcome"]["block_hash"], url)
        out["commit_to_paid_s"] = round((t_paid - t_commit) / 1e9, 2)
        out["deliver_to_paid_s"] = round((t_paid - t_deliver) / 1e9, 2)
    return out, bad


def summarize(rows):
    lim = rows[0]["lim"]
    if any(r["lim"] != lim for r in rows):
        raise SystemExit("bench: runs saw different enforced limits — summarize per limit set first")
    return {"runs": len(rows), "enforced_limits": lim,
            "verdict_s": stats([r["verdict_s"] for r in rows]),
            "instructions": stats([r["instructions"] for r in rows], lim["i"]),
            "time_ms": stats([r["time_ms"] for r in rows], lim["s"] * 1000),
            "verifier_peak_mem_bytes": stats([r["mem_bytes"] for r in rows], lim["m"] << 20)}


def chain_summary(crows):
    out = {"runs": len(crows), "commit_to_verdict_s": stats([c["commit_to_verdict_s"] for c in crows])}
    paid = [c for c in crows if "commit_to_paid_s" in c]
    if paid:
        out["commit_to_paid_s"] = stats([c["commit_to_paid_s"] for c in paid])
        out["deliver_to_paid_s"] = stats([c["deliver_to_paid_s"] for c in paid])
    return out


def line(name, s, unit=""):
    tail = f" · max {s['max_pct_of_limit']}% of limit" if "max_pct_of_limit" in s else ""
    return f"{name:<26} n={s['n']:<3} p50 {s['p50']}{unit} · p95 {s['p95']}{unit} · max {s['max']}{unit}{tail}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chain", action="store_true", help="re-read resolve txs + block headers from the archival RPC")
    ap.add_argument("--rpc", default=near.ARCHIVAL)
    ap.add_argument("--write", action="store_true", help="rewrite corpus/bench.json instead of checking against it")
    a = ap.parse_args()
    bundles = sorted(glob.glob(os.path.join(ROOT, "corpus", "evidence", "*.json")))
    if not bundles:
        print("bench: empty bundle (no corpus/evidence/*.json)")
        return 1
    evs = [json.load(open(b)) for b in bundles]
    rows = [offline_row(ev) for ev in evs]
    rec = {"v": 1, "source": "corpus/evidence/*.json (OutLayer on-chain events + resolve_execution args)",
           "percentile": "nearest-rank", "summary": summarize(rows), "rows": rows}
    old = json.load(open(OUT)) if os.path.exists(OUT) else None
    if old and "chain" in old:
        rec["chain"] = old["chain"]
    s = rec["summary"]
    print(f"bench: {s['runs']} testnet runs · limits {s['enforced_limits']['i']:,} instructions / "
          f"{s['enforced_limits']['m']} MB / {s['enforced_limits']['s']} s (enforced, as the verifier saw them)")
    print(line("request→verdict (OutLayer)", s["verdict_s"], " s"))
    print(line("instructions", s["instructions"]))
    print(line("time_ms", s["time_ms"], " ms"))
    print(line("verifier peak memory", s["verifier_peak_mem_bytes"], " B"))
    bad = []
    if a.chain:
        try:
            near.rpc("status", [], a.rpc)["result"]
        except Exception:
            print(f"exit 2: archival RPC {a.rpc} unreachable — nothing re-read (offline numbers above are from the bundle)")
            return 2
        crows = []
        for ev, row in zip(evs, rows):
            try:
                c, b = chain_row(ev, row, a.rpc)
            except OSError as e:  # urllib HTTPError/URLError after near.rpc's retries (429, timeouts)
                print(f"exit 2: archival RPC failed at {row['label']} ({e}) — re-run later or pass --rpc <url>; "
                      "nothing written")
                return 2
            crows.append(c)
            bad += [f"{row['label']}: {x}" for x in b]
        rec["chain"] = {"rpc_note": "block header timestamps (ns) via `block`; resolve args re-decoded",
                        "summary": chain_summary(crows), "rows": crows}
        cs = rec["chain"]["summary"]
        print(f"chain: {len(crows)} resolve txs re-read · resources_used {'MISMATCH' if bad else 'match the bundle'}")
        for k in ("commit_to_verdict_s", "commit_to_paid_s", "deliver_to_paid_s"):
            if k in cs:
                print(line(k.replace("_s", "").replace("_to_", "→") + " (blocks)", cs[k], " s"))
    elif "chain" in rec:
        cs = rec["chain"]["summary"]
        print("recorded chain block-time (re-check: make bench-chain):")
        for k in ("commit_to_verdict_s", "commit_to_paid_s", "deliver_to_paid_s"):
            if k in cs:
                print(line(k.replace("_s", "").replace("_to_", "→") + " (blocks)", cs[k], " s"))
    for x in bad:
        print("FAIL " + x)
    if a.write:
        with open(OUT, "w") as f:
            json.dump(rec, f, indent=1)
            f.write("\n")
        print(f"wrote {os.path.relpath(OUT, ROOT)}")
    elif old is None:
        print("FAIL corpus/bench.json missing (run with --write)")
        return 1
    else:
        for k in ("summary", "rows") + (("chain",) if a.chain else ()):
            if rec.get(k) != old.get(k):
                bad.append(f"{k} differs from the committed corpus/bench.json")
                print(f"FAIL {k} differs from the committed corpus/bench.json")
        if not bad:
            print("bench: recomputed numbers = corpus/bench.json" + (" (incl. chain re-read)" if a.chain else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
