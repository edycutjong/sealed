#!/usr/bin/env python3
"""Evidence bundle for one commit: chain data only (no secret), re-fetchable by `make verify`.

bundle() records, for one commit:
  commit tx  — every receipt + outcome: COMMIT → storage_balance_of → on_payout_checked → request_execution
               (its args: the pinned WasmUrl hash, secrets_ref, input_data) → on_execution_response → on_verdict
  request_id — from OutLayer's `execution_requested` event
  resolve tx — the worker's `resolve_execution` / `submit_execution_output_and_resolve` for that request_id,
               signed by worker.outlayer.testnet (OutLayer's operator = its register contract) with an access key
               the register contract added after checking the worker's TDX quote (llms-full.md:8268-8384)
  worker key — view_access_key(operator, signing key) at the resolve block: exists, FunctionCall to outlayer
  deliver tx — DELIVERED → ft_transfer → on_paid (PAID), when there is one
Usage: python3 scripts/evidence.py <label> <bounty> <hunter> <commit_tx> [deliver_tx]  (re-builds one bundle)"""
import base64, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "day0"))
import near  # noqa: E402

RESOLVE_METHODS = ("resolve_execution", "submit_execution_output_and_resolve")


def operator():
    return near.view(near.OUTLAYER, "get_config")[1]


def tx_full(h, sender, url=near.RPC):
    r = near.tx(h, sender, url)
    if "result" not in r:
        raise RuntimeError(f"tx {h}: {json.dumps(r)[:300]}")
    return r["result"]


def request_id(txr):
    for e in near.events({"result": txr}, "execution_requested"):
        for d in e.get("data", []):
            rd = d.get("request_data")
            rd = json.loads(rd) if isinstance(rd, str) else rd
            if rd and "request_id" in rd:
                return int(rd["request_id"]), rd
    return None, None


def outcome_block(txr, needle):
    """Block hash of the first receipt outcome whose logs contain `needle`."""
    for ro in txr["receipts_outcome"]:
        if any(needle in l for l in ro["outcome"]["logs"]):
            return ro["block_hash"]
    return None


def find_resolve(rid, callback_block, op, back=12):
    """Scan the blocks up to the callback's for the operator's resolve tx carrying this request_id."""
    b = near.rpc("block", {"block_id": callback_block})["result"]
    h = b["header"]["height"]
    for height in range(h, h - back, -1):
        blk = near.rpc("block", {"block_id": height})
        if "result" not in blk:
            continue
        for ch in blk["result"]["chunks"]:
            c = near.rpc("chunk", {"chunk_id": ch["chunk_hash"]}).get("result", {})
            for t in c.get("transactions", []):
                if t["signer_id"] != op or t["receiver_id"] != near.OUTLAYER:
                    continue
                for act in t["actions"]:
                    fc = act.get("FunctionCall") if isinstance(act, dict) else None
                    if not fc or fc["method_name"] not in RESOLVE_METHODS:
                        continue
                    args = json.loads(base64.b64decode(fc["args"]))
                    if int(args.get("request_id", -1)) == rid:
                        return {"tx": t["hash"], "signer": t["signer_id"], "public_key": t["public_key"],
                                "method": fc["method_name"], "args": args, "block_height": height}
    return None


def access_key(account, pk, block_height, url=near.RPC):
    r = near.rpc("query", {"request_type": "view_access_key", "block_id": block_height,
                           "account_id": account, "public_key": pk}, url)
    return r.get("result") or {"error": r.get("error", {}).get("cause", r.get("error"))}


def verdict_output(resolve):
    """The verifier's stdout as the worker submitted it (Text output)."""
    if not resolve:
        return None
    args = resolve["args"]
    out = (args.get("response") or {}).get("output") or args.get("output")
    if isinstance(out, dict):
        out = out.get("Text") or out.get("Json") or out.get("Bytes")
    return out


def bundle(label, bounty, hunter, commit_tx, deliver_tx=None):
    op = operator()
    ctx = tx_full(commit_tx, hunter)
    rid, rdata = request_id(ctx)
    cb_block = outcome_block(ctx, "AWARDED ") or outcome_block(ctx, "REFUSED ")
    resolve = find_resolve(rid, cb_block, op) if rid is not None and cb_block else None
    key = access_key(op, resolve["public_key"], resolve["block_height"]) if resolve else None
    bstate = near.view(bounty, "view_state")
    ev = {
        "label": label, "network": "testnet", "bounty": bounty, "hunter": hunter, "outlayer": near.OUTLAYER,
        "operator": op, "bounty_verifier_hash": bstate["verifier_wasm_hash"],
        "commit_tx": commit_tx, "request_id": rid,
        "request_execution_args": near.request_execution_args({"result": ctx}),
        "execution_requested": rdata,
        "execution_completed": near.events({"result": ctx}, "execution_completed"),
        "bounty_logs": [l["log"] for l in near.logs({"result": ctx}) if l["executor"] == bounty],
        "resolve": resolve, "worker_access_key": key, "verdict_output": verdict_output(resolve),
        "commit_tx_status": ctx,
    }
    if deliver_tx:
        dtx = tx_full(deliver_tx, hunter)
        ev["deliver_tx"] = deliver_tx
        ev["deliver_logs"] = [l["log"] for l in near.logs({"result": dtx}) if l["executor"] == bounty]
        ev["deliver_tx_status"] = dtx
    return ev


if __name__ == "__main__":
    label, bounty, hunter, ctx = sys.argv[1:5]
    dtx = sys.argv[5] if len(sys.argv) > 5 else None
    ev = bundle(label, bounty, hunter, ctx, dtx)
    os.makedirs(os.path.join(ROOT, "corpus", "evidence"), exist_ok=True)
    json.dump(ev, open(os.path.join(ROOT, "corpus", "evidence", f"{label}.json"), "w"), indent=1)
    print(json.dumps({k: ev.get(k) for k in ("label", "request_id")} | {"resolve": (ev["resolve"] or {}).get("tx")}))
