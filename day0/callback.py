#!/usr/bin/env python3
"""G6 + G5 (NEAR mode): the keyless probe contract asks OutLayer to run the PINNED verifier on one input and
records what its callback received. Prints and saves one JSON result with every tx hash.

usage: callback.py <input.json> <label> [--deliver] [--signer ACCOUNT] [--secrets-ref JSON] [--no-strip]

Default (G6): the input's `secrets` ride in input_data (day-0 test vectors only). `--secrets-ref` (G7) strips
them from input_data and lets OutLayer inject them from the keystore instead."""
import argparse, base64, json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import near  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROBE = os.environ.get("PROBE", "probe1.sealed-dev-11010702.testnet")
LIMITS = {"max_instructions": 2_000_000_000, "max_memory_mb": 512, "max_execution_seconds": 120}


def native(inp):
    """Native verdict + enc for the same input (the bytes the hunter rebuilds locally)."""
    exe = os.path.join(ROOT, "target", "release", "verifier")
    p = subprocess.run([exe], input=json.dumps(inp).encode(), capture_output=True,
                       env={**os.environ, "SEALED_DEBUG_ENC": "1"})
    v = json.loads(p.stdout)
    enc = next((l[4:] for l in p.stderr.decode().splitlines() if l.startswith("enc=")), None)
    return v, enc


def strip(v):
    return {k: x for k, x in v.items() if k != "lim"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("label")
    ap.add_argument("--deliver", action="store_true")
    ap.add_argument("--signer", default="sealed-hunter-a-11010702.testnet")
    ap.add_argument("--secrets-ref")
    ap.add_argument("--deposit", default="0.05 NEAR")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()

    inp = json.load(open(a.input))
    want, enc = native(inp)
    sent = dict(inp)
    secrets_ref = json.loads(a.secrets_ref) if a.secrets_ref else None
    if secrets_ref is not None:
        sent.pop("secrets", None)
    n0 = len(near.view(PROBE, "get_records"))
    t0 = time.time()
    txh = near.call(a.signer, PROBE, "request",
                    {"label": a.label, "input_data": json.dumps(sent, separators=(",", ":")),
                     "resource_limits": LIMITS, "secrets_ref": secrets_ref}, deposit=a.deposit)
    rec = None
    while time.time() - t0 < a.timeout:
        recs = near.view(PROBE, "get_records", {"from": n0})
        mine = [r for r in recs if r["label"] == a.label]
        if mine and mine[-1]["kind"] != "pending":
            rec = mine[-1]
            break
        time.sleep(3)
    txr = near.tx(txh, a.signer)
    req_args = near.request_execution_args(txr)
    completed = near.events(txr, "execution_completed")
    out = {
        "label": a.label, "input": os.path.relpath(a.input, ROOT), "probe": PROBE, "signer": a.signer,
        "request_tx": txh, "requested_limits": LIMITS,
        "request_source": (req_args or {}).get("source"), "secrets_ref": (req_args or {}).get("secrets_ref"),
        "record": rec, "wall_s_client": round(time.time() - t0, 1),
        "wall_s_chain": round((rec["resolved_ns"] - rec["requested_ns"]) / 1e9, 1) if rec else None,
        "blocks": (rec["resolved_height"] - rec["requested_height"]) if rec else None,
        "execution_completed": completed,
        "native_verdict": want,
    }
    chain_v = None
    if rec and rec.get("raw"):
        try:
            raw = json.loads(rec["raw"])
            chain_v = json.loads(raw) if isinstance(raw, str) else raw
        except Exception:
            chain_v = None
    out["chain_verdict"] = chain_v
    out["match_native"] = bool(chain_v) and isinstance(chain_v, dict) and strip(chain_v) == strip(want)
    if a.deliver and rec and rec.get("h_enc"):
        b64 = base64.b64encode(bytes.fromhex(enc)).decode()
        out["deliver_enc_bytes"] = len(enc) // 2
        out["deliver_tx"] = near.call(a.signer, PROBE, "deliver", {"id": rec["id"], "enc": b64}, gas="100 Tgas")
        out["delivered"] = near.view(PROBE, "get_records", {"from": rec["id"]})[0]["delivered"]
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    path = os.path.join(HERE, "results", f"g6-{a.label}.json")
    json.dump(out, open(path, "w"), indent=1)
    print(json.dumps({k: out[k] for k in ("label", "request_tx", "wall_s_chain", "match_native")}
                     | {"kind": rec and rec["kind"], "broken": rec and rec["broken"]}))


if __name__ == "__main__":
    main()
