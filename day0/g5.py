#!/usr/bin/env python3
"""G5 + G5b summary: reads every results/g6-*.json of the CURRENT pin and reports, per run, the instructions and
time OutLayer reported in the resolve tx (`execution_completed.resources_used`) against the enforced limits the
verifier printed (`lim`), the verdict size against the 900 B NEAR-mode output limit, and the 3-runtime hash match.
Memory is the verifier-reported peak linear memory (OutLayer reports none). Writes results/g5.json."""
import glob, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
PIN = open(os.path.join(HERE, "artifacts", "verifier-day0.wasm.sha256")).read().split()[0]


def main():
    rows, worst = [], {"i": 0.0, "s": 0.0, "mem": 0.0}
    for p in sorted(glob.glob(os.path.join(HERE, "results", "g6-*.json"))):
        d = json.load(open(p))
        src = (d.get("request_source") or {}).get("WasmUrl") or {}
        if src.get("hash") != PIN or d["label"].startswith("g7"):  # G7/G7d runs are judged by secret.py, not here
            continue
        ev = d["execution_completed"][0]["data"][0] if d["execution_completed"] else {}
        used = ev.get("resources_used") or {}
        v, lim = d.get("chain_verdict") or {}, (d.get("chain_verdict") or {}).get("lim") or {}
        r = {
            "label": d["label"], "request_tx": d["request_tx"], "success": ev.get("success"),
            "broken": v.get("broken"), "err": v.get("err"), "three_of_three": d["three_of_three"],
            "instructions": used.get("instructions"), "time_ms": used.get("time_ms"), "peak_mem_b": lim.get("mem"),
            "verdict_bytes": len((d.get("record") or {}).get("raw") or ""),
        }
        if lim:
            r["pct"] = {"i": round(100 * used["instructions"] / lim["i"], 2),
                        "s": round(100 * used["time_ms"] / (lim["s"] * 1000), 2),
                        "mem": round(100 * lim["mem"] / (lim["m"] * 1024 * 1024), 2)}
            for k in worst:
                worst[k] = max(worst[k], r["pct"][k])
        rows.append(r)
    ok = bool(rows) and all(r["success"] and r["three_of_three"] and r["verdict_bytes"] <= 900 for r in rows)
    out = {"check": "G5+G5b", "pin_sha256": PIN, "runs": len(rows), "worst_pct_of_enforced": worst,
           "result": "PASS" if ok and max(worst.values()) <= 50 else "FAIL", "rows": rows}
    json.dump(out, open(os.path.join(HERE, "results", "g5.json"), "w"), indent=1)
    print(json.dumps({k: out[k] for k in ("check", "result", "runs", "worst_pct_of_enforced")}))
    for r in rows:
        print(f'{r["label"]:16} broken={r["broken"]!s:5} i={r["instructions"]:>11} ({r["pct"]["i"]}%) '
              f't={r["time_ms"]}ms out={r["verdict_bytes"]}B 3/3={r["three_of_three"]} err={r["err"]}')


if __name__ == "__main__":
    main()
