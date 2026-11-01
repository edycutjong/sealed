#!/usr/bin/env python3
"""`make corpus`: run every corpus item (corpus/manifest.json) through the committed verifier.wasm under wasmtime and
compare it with its golden verdict and, for hand-made items, with the DESIGNED verdict. No network, no credentials,
no Rust — wasmtime + python3 only. Exit 0 only if every item matches."""
import json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "verifier", "tests", "golden")


def main():
    items = json.load(open(os.path.join(ROOT, "corpus", "manifest.json")))["items"]
    wasm = os.path.join(ROOT, "verifier.wasm")
    ok = bad = 0
    for it in items:
        raw = open(os.path.join(ROOT, it["vector"]), "rb").read()
        p = subprocess.run(["wasmtime", "run", wasm], input=raw, capture_output=True)
        v = json.loads(p.stdout)
        v.pop("lim", None)
        g = os.path.join(GOLDEN, "corpus" if it["category"] != "abuse" else "", f"{it['name']}.json")
        want = json.load(open(g))
        fails = []
        if v != want:
            fails.append("verdict != golden")
        e = it["expect"]
        if e is not None and (v["broken"] != e["broken"] or ("err" in e and v["err"] != e["err"])):
            fails.append(f"designed {e}")
        tag = "OK  " if not fails else "FAIL"
        what = "BROKEN" if v["broken"] else f"refused ({v['err'] or 'no invariant broken'})"
        print(f"{tag} {it['category']:<14} {it['name']:<40} {what:<38} gas {v['gas_used']:>6}"
              + ("" if not fails else "  " + "; ".join(fails)))
        ok, bad = ok + (not fails), bad + bool(fails)
    print(f"corpus: {ok} OK · {bad} FAIL · {len(items)} items under wasmtime")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
