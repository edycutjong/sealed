"""Binary-search the minimal wasmtime fuel a verifier input needs. wasmtime fuel ~ OutLayer's `instructions` (the worker
meters with consume_fuel): Fallback 7.59 M local vs 7.39 M on chain at the current pin.
usage: fuel.py <verifier.wasm> <input.json> [...]  → one line per input; --json writes results/g5b-fuel.json"""
import json, os, subprocess, sys


def need(W, inp):
    def ok(f):
        p = subprocess.run(["wasmtime", "run", "-W", f"fuel={f}", W], input=inp, capture_output=True)
        return p.returncode == 0 and p.stdout.strip().startswith(b"{")
    lo, hi = 1, 1
    while not ok(hi):
        lo, hi = hi, hi * 2
        if hi > 1 << 40:
            return None
    while hi - lo > max(lo // 1000, 1):  # 0.1% resolution, rounded up
        m = (lo + hi) // 2
        lo, hi = (lo, m) if ok(m) else (m, hi)
    return hi


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--json"]
    W, out = args[0], {}
    for f in args[1:]:
        out[os.path.basename(f)] = need(W, open(f, "rb").read())
        print(os.path.basename(f), out[os.path.basename(f)], flush=True)
    if "--json" in sys.argv:
        here = os.path.dirname(os.path.abspath(__file__))
        json.dump({"wasm": os.path.basename(W), "fuel_limit_worker": 2_000_000_000, "fuel": out},
                  open(os.path.join(here, "results", "g5b-fuel.json"), "w"), indent=1)
