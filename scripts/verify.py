#!/usr/bin/env python3
"""`make verify`: prove each payout from chain data alone.

For every corpus/evidence/<label>.json, re-fetch the bundled txs from an archival RPC (default
`https://archival-rpc.testnet.fastnear.com`, `--rpc <url>` or NEAR_ARCHIVAL_RPC overrides; unreachable → read the
bundle, label `RECORDED`). Each commit yields one line with these checks:
  pinned   request_execution args pin WasmUrl.hash = the bounty's verifier_wasm_hash (`make replay` reruns
           those exact bytes, sha256-checked)
  worker   the verdict came back in the operator's resolve tx for this request_id, signed by a key registered
           on OutLayer via TDX quote — a FunctionCall access key scoped to resolve_execution (worker
           attestation, https://app.outlayer.ai/docs/tee-attestation). On chain this shows the request pinned the hash and an
           attested key answered, NOT that the worker ran exactly those bytes (ARCHITECTURE.md §Limits).
  verdict  the AWARDED/REFUSED the bounty logged agrees with the worker's submitted verdict (broken flag)
  h_enc    (paid) sha256(enc) from the deliver tx args = the award callback's h_enc = the verdict's h_enc
  paid     (paid) on_paid logged PAID for the invariant amount
Exit 0 only if ≥ 1 Paid line exists and every payout line is CHAIN-CHECKED (empty bundle → 1; offline or rate-limited → 2)."""
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


def req_id_of(ctx):
    """The OutLayer request_id this commit's request_execution produced (from the execution_requested event)."""
    for e in near.events({"result": ctx}, "execution_requested"):
        for d in e.get("data", []):
            rd = d.get("request_data")
            rd = json.loads(rd) if isinstance(rd, str) else rd
            if rd and "request_id" in rd:
                return int(rd["request_id"])
    return None


def live_verifier_hash(bounty, online, url, fallback):
    """The hash the bounty pins RIGHT NOW (view_state), so `pinned` is independent of the bundle. Offline:
    fall back to the bundled value (the bundle is all we have when the network is unreachable)."""
    if not online:
        return fallback
    try:
        return near.view(bounty, "view_state", url=url)["verifier_wasm_hash"]
    except Exception:
        return fallback


def one(ev, online, url):
    """Re-fetch (online) or read from the bundle (offline), then run the checks for one commit."""
    inv_amount = None
    if online:
        ctx = near.tx(ev["commit_tx"], ev["hunter"], url)["result"]
        req = near.request_execution_args({"result": ctx})
        blog = logs(ctx, ev["bounty"])
        res = ev["resolve"]
        if res:
            rtx = near.tx(res["tx"], ev["operator"], url)["result"]
            res = {**res, "args": tx_args(rtx, res["method"]),
                   "signer": rtx["transaction"]["signer_id"], "public_key": rtx["transaction"]["public_key"],
                   "block_hash": rtx["transaction_outcome"]["block_hash"]}
            # Scope the access-key lookup to the resolve tx's inclusion block: a later admin rotation/
            # revocation of the worker key must not fail a payout that was valid when the worker answered.
            kr = near.rpc("query", {"request_type": "view_access_key", "block_id": res["block_hash"],
                                    "account_id": ev["operator"], "public_key": res["public_key"]}, url)
            key = kr.get("result")
            if key is None and "UNKNOWN_ACCESS_KEY" not in json.dumps(kr.get("error", {})):
                # not "no such key" but an unusable answer (non-archival node, rate-limit body): unchecked, not FAIL
                raise ConnectionError(f"view_access_key: {json.dumps(kr.get('error', kr))[:160]}")
        else:
            key = None
        out = verdict_output(res)
        dtx = near.tx(ev["deliver_tx"], ev["hunter"], url)["result"] if ev.get("deliver_tx") else None
        dlog = logs(dtx, ev["bounty"]) if dtx else []
        denc = tx_args(dtx, "deliver") if dtx else None
    else:
        ctx, req, blog = ev["commit_tx_status"], ev["request_execution_args"], ev["bounty_logs"]
        res, key, out = ev["resolve"], ev.get("worker_access_key"), ev.get("verdict_output")
        out = json.loads(out) if isinstance(out, str) else out
        dlog = ev.get("deliver_logs") or []
        denc = tx_args(ev["deliver_tx_status"], "deliver") if ev.get("deliver_tx_status") else None

    checks = []
    pinned = (req or {}).get("source", {}).get("WasmUrl", {}).get("hash")
    checks.append(("pinned", bool(pinned) and pinned == live_verifier_hash(ev["bounty"], online, url, ev["bounty_verifier_hash"])))
    answered = bool(res) and res.get("signer") == ev["operator"]
    # The resolve tx must be for THIS commit's request, not just any run the same worker key signed.
    rid_ok = bool(res) and int((res.get("args") or {}).get("request_id", -1)) == ev["request_id"] == req_id_of(ctx)
    perm = (key or {}).get("permission") or {}
    key_ok = "FunctionCall" in perm and any(m in perm["FunctionCall"]["method_names"] for m in RESOLVE_METHODS)
    checks.append(("worker", answered and key_ok and rid_ok))
    awarded = any(l.startswith("AWARDED ") for l in blog)
    refused = any(l.startswith("REFUSED ") for l in blog)
    checks.append(("verdict", isinstance(out, dict) and bool(out.get("broken")) == awarded and (awarded or refused)))
    paid_logs = [l for l in dlog if l.startswith("PAID ")]
    kind = "PAID" if paid_logs else ("REFUSED" if refused else "AWARDED")
    if ev.get("expire_tx") and not paid_logs:
        # Awarded, never delivered, voided by `expire` after deliver_by: escrow back to the pool, bond slashed.
        elog = logs(near.tx(ev["expire_tx"], ev["expire_signer"], url)["result"], ev["bounty"]) if online else ev["expire_logs"]
        cid = next((l.split()[1] for l in blog if l.startswith("COMMIT ")), None)
        checks.append(("expired", any(l.startswith(f"EXPIRED {cid};") for l in elog)))
        kind = "VOIDED"
    if paid_logs:
        h_enc = sha(base64.b64decode(denc["enc"]))
        aw = next((l for l in blog if l.startswith("AWARDED ")), "")
        awarded_h = aw.split("h_enc ")[1] if "h_enc " in aw else ""
        awarded_amount = aw.split("amount ")[1].split(" ")[0] if "amount " in aw else None
        checks.append(("h_enc", h_enc == awarded_h == (out or {}).get("h_enc")))
        # PAID <commit_id> <amount>: the amount paid must equal the amount the award logged.
        paid_amount = paid_logs[-1].split()[2] if len(paid_logs[-1].split()) >= 3 else None
        checks.append(("paid", paid_amount is not None and paid_amount == awarded_amount))
    fails = [n for n, g in checks if not g]
    return kind, checks, fails


def bounty_integrity(bounty, online, url, require_keyless):
    """One line per bounty: access-key count + whether the code is a global-contract hash. The production
    bounty is keyless on a global hash (I6); the D3 throwaway is a keyed iteration account. INFO by default
    (not a payout check); `--require-keyless` turns a keyed bounty into a FAIL for the final judged run."""
    if not online:
        return f"bounty {bounty}: keys/code not re-checked (offline)", True
    try:
        kr = near.rpc("query", {"request_type": "view_access_key_list", "finality": "final", "account_id": bounty}, url)
        ar = near.rpc("query", {"request_type": "view_account", "finality": "final", "account_id": bounty}, url)
    except OSError as e:
        return f"bounty {bounty}: keys/code not re-checked (RPC error: {e})", None
    if "result" not in kr or "result" not in ar:  # an RPC error body must not read as "0 keys, own code"
        err = (kr if "result" not in kr else ar).get("error", {})
        return f"bounty {bounty}: keys/code not re-checked (RPC error: {json.dumps(err)[:160]})", None
    keys = kr["result"].get("keys", [])
    acct = ar["result"]
    glob = acct.get("global_contract_hash") or acct.get("global_contract_account_id")
    keyless = len(keys) == 0 and bool(glob)
    tag = "keyless+global-hash" if keyless else f"{len(keys)} key(s){'' if glob else ', own code'}"
    ok = keyless if require_keyless else True
    return f"bounty {bounty}: {tag}" + ("" if ok else "  FAIL (--require-keyless)"), ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=near.ARCHIVAL)
    ap.add_argument("--require-keyless", action="store_true",
                    help="fail if any bounty is keyed / not on a global-contract hash (the D5+ judged bounty)")
    ap.add_argument("--bounty", action="append", default=[],
                    help="only this bounty's bundles (repeatable); default: every bundle in corpus/evidence/")
    a = ap.parse_args()
    bundles = sorted(glob.glob(os.path.join(ROOT, "corpus", "evidence", "*.json")))
    if a.bounty:
        bundles = [b for b in bundles if json.load(open(b))["bounty"] in a.bounty]
    if not bundles:
        print("verify: empty bundle (no corpus/evidence/*.json)")
        return 1
    online = reachable(a.rpc)
    n_pass = n_chain = n_rec = n_paid = n_unb = 0
    any_fail = False
    for bounty in sorted({json.load(open(b))["bounty"] for b in bundles}):
        line_s, ok = bounty_integrity(bounty, online, a.rpc, a.require_keyless)
        if ok is None:  # RPC error: unchecked, never a pass — under --require-keyless it forces exit 2
            print("RPC-ERROR " + line_s)
            n_unb += a.require_keyless
            continue
        print(("INFO " if ok else "FAIL ") + line_s)
        any_fail |= not ok
    for b in bundles:
        ev = json.load(open(b))
        row_online = online
        try:
            kind, checks, fails = one(ev, online, a.rpc)
        except OSError as e:  # HTTP 429/5xx or a timeout after near.rpc's retries: not a failed check
            print(f"RPC-ERROR {ev['label']}: {e} — checked from the bundle only")
            row_online = False
            kind, checks, fails = one(ev, False, a.rpc)
        except KeyError as e:  # the archival node answered without a result (e.g. unknown tx): a real failure
            kind, checks, fails = "?", [], [f"rpc returned no result ({e})"]
        mark = ("CHAIN-CHECKED" if row_online else "RECORDED") if not fails else "FAIL"
        print(f"{mark} {ev['label']} [{kind}]: " + " · ".join(n for n, _ in checks)
              + ("" if not fails else " · FAILED: " + ",".join(fails)))
        ok = not fails
        n_pass += ok
        n_chain += ok and row_online
        n_rec += ok and not row_online
        n_paid += ok and kind == "PAID"
        any_fail |= not ok
    print(f"checks: {n_pass} PASS · {n_chain} CHAIN-CHECKED · {n_rec} RECORDED")
    if any_fail:
        return 1
    if n_rec or n_unb:
        print(f"exit 2: {n_rec} RECORDED line(s), {n_unb} bounty keyless check(s) unchecked — the archival RPC was unreachable or rate-limited, not a failed check; "
              "re-run later or pass RPC=<url>")
        return 2
    if n_paid < 1:
        print("exit 1: no Paid payout line")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
