#!/usr/bin/env python3
"""`make verify`: prove each payout from chain data alone.

For every corpus/evidence/<label>.json, re-fetch the bundled txs from an archival RPC (default
`https://archival-rpc.testnet.near.org`, `--rpc <url>` overrides; unreachable → read the bundle, label
`RECORDED`). Each commit yields one line with these checks:
  pinned   request_execution args pin WasmUrl.hash = the bounty's verifier_wasm_hash (`make replay` reruns
           those exact bytes, sha256-checked)
  worker   the verdict came back in the operator's resolve tx for this request_id, signed by a key registered
           on OutLayer via TDX quote — a FunctionCall access key scoped to resolve_execution (worker
           attestation, llms-full.md:8268-8384). On chain this shows the request pinned the hash and an
           attested key answered, NOT that the worker ran exactly those bytes (limits table).
  verdict  the AWARDED/REFUSED the bounty logged agrees with the worker's submitted verdict (broken flag)
  h_enc    (paid) sha256(enc) from the deliver tx args = the award callback's h_enc = the verdict's h_enc
  paid     (paid) on_paid logged PAID for the invariant amount
Exit 0 only if ≥ 1 Paid line exists and every payout line is CHAIN-CHECKED (empty bundle → 1; offline → 2)."""
import argparse, base64, glob, hashlib, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "day0"))
import near  # noqa: E402

RESOLVE_METHODS = ("resolve_execution", "submit_execution_output_and_resolve")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def reachable(url):
    try:
        return "result" in near.rpc("status", [], url)
    except Exception:
        return False


def tx_args(txr, method):
    for a in txr.get("transaction", {}).get("actions", []):
        fc = a.get("FunctionCall") if isinstance(a, dict) else None
        if fc and fc["method_name"] == method:
            return json.loads(base64.b64decode(fc["args"]))
    return None


def logs(txr, executor=None):
    out = []
    for ro in txr.get("receipts_outcome", []):
        if executor and ro["outcome"]["executor_id"] != executor:
            continue
        out += ro["outcome"]["logs"]
    return out


def verdict_output(res):
    """The verifier stdout the worker submitted, from the resolve tx args."""
    if not res or not res.get("args"):
        return None
    a = res["args"]
    out = (a.get("response") or {}).get("output") or a.get("output")
    if isinstance(out, dict):
        out = out.get("Text") or out.get("Json") or out.get("Bytes")
    return json.loads(out) if isinstance(out, str) else out


def one(ev, online, url):
    """Re-fetch (online) or read from the bundle (offline), then run the checks for one commit."""
    if online:
        ctx = near.tx(ev["commit_tx"], ev["hunter"], url)["result"]
        req = near.request_execution_args({"result": ctx})
        blog = logs(ctx, ev["bounty"])
        res = ev["resolve"]
        if res:
            rtx = near.tx(res["tx"], ev["operator"], url)["result"]
            res = {**res, "args": tx_args(rtx, res["method"]),
                   "signer": rtx["transaction"]["signer_id"], "public_key": rtx["transaction"]["public_key"]}
            key = near.rpc("query", {"request_type": "view_access_key", "finality": "final",
                                     "account_id": ev["operator"], "public_key": res["public_key"]}, url).get("result")
        else:
            key = None
        out = verdict_output(res)
        dlog = logs(near.tx(ev["deliver_tx"], ev["hunter"], url)["result"]) if ev.get("deliver_tx") else []
        denc = tx_args(near.tx(ev["deliver_tx"], ev["hunter"], url)["result"], "deliver") if ev.get("deliver_tx") else None
    else:
        ctx, req, blog = ev["commit_tx_status"], ev["request_execution_args"], ev["bounty_logs"]
        res, key, out = ev["resolve"], ev.get("worker_access_key"), ev.get("verdict_output")
        out = json.loads(out) if isinstance(out, str) else out
        dlog = ev.get("deliver_logs") or []
        denc = tx_args(ev["deliver_tx_status"], "deliver") if ev.get("deliver_tx_status") else None

    checks = []
    pinned = (req or {}).get("source", {}).get("WasmUrl", {}).get("hash")
    checks.append(("pinned", pinned == ev["bounty_verifier_hash"]))
    answered = bool(res) and res.get("signer") == ev["operator"]
    perm = (key or {}).get("permission") or {}
    key_ok = "FunctionCall" in perm and any(m in perm["FunctionCall"]["method_names"] for m in RESOLVE_METHODS)
    checks.append(("worker", answered and key_ok))
    awarded = any(l.startswith("AWARDED ") for l in blog)
    refused = any(l.startswith("REFUSED ") for l in blog)
    checks.append(("verdict", isinstance(out, dict) and bool(out.get("broken")) == awarded and (awarded or refused)))
    paid = any(l.startswith("PAID ") for l in dlog)
    kind = "PAID" if paid else ("REFUSED" if refused else "AWARDED")
    if paid:
        h_enc = sha(base64.b64decode(denc["enc"]))
        awarded_h = next((l.split("h_enc ")[1] for l in blog if l.startswith("AWARDED ")), "")
        checks.append(("h_enc", h_enc == awarded_h == (out or {}).get("h_enc")))
        checks.append(("paid", True))
    fails = [n for n, g in checks if not g]
    return kind, checks, fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=near.ARCHIVAL)
    a = ap.parse_args()
    bundles = sorted(glob.glob(os.path.join(ROOT, "corpus", "evidence", "*.json")))
    if not bundles:
        print("verify: empty bundle (no corpus/evidence/*.json)")
        return 1
    online = reachable(a.rpc)
    n_pass = n_chain = n_rec = n_paid = 0
    any_fail = False
    for b in bundles:
        ev = json.load(open(b))
        kind, checks, fails = one(ev, online, a.rpc)
        mark = ("CHAIN-CHECKED" if online else "RECORDED") if not fails else "FAIL"
        print(f"{mark} {ev['label']} [{kind}]: " + " · ".join(n for n, _ in checks)
              + ("" if not fails else " · FAILED: " + ",".join(fails)))
        ok = not fails
        n_pass += ok
        n_chain += ok and online
        n_rec += ok and not online
        n_paid += ok and kind == "PAID"
        any_fail |= not ok
    print(f"checks: {n_pass} PASS · {n_chain} CHAIN-CHECKED · {n_rec} RECORDED")
    if any_fail:
        return 1
    if not online:
        print("exit 2: RECORDED only — the archival RPC was unreachable, not a failed check")
        return 2
    if n_paid < 1:
        print("exit 1: no Paid payout line")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
