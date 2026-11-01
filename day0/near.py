#!/usr/bin/env python3
"""Thin NEAR testnet helpers for the day-0 scripts: JSON-RPC reads, and signed calls through near-cli-rs with
the key file under ~/.config/near/sealed-testnet/ (the key is never printed)."""
import base64, json, os, re, subprocess, time, urllib.request

RPC = os.environ.get("NEAR_RPC", "https://rpc.testnet.near.org")
ARCHIVAL = os.environ.get("NEAR_ARCHIVAL_RPC", "https://archival-rpc.testnet.near.org")
KEYS = os.path.expanduser("~/.config/near/sealed-testnet")
OUTLAYER = "outlayer.testnet"


def rpc(method, params, url=RPC):
    body = json.dumps({"jsonrpc": "2.0", "id": "d0", "method": method, "params": params}).encode()
    for attempt in range(5):
        try:
            req = urllib.request.Request(url, body, {"content-type": "application/json"})
            r = json.load(urllib.request.urlopen(req, timeout=60))
            if "error" in r and "TIMEOUT" in json.dumps(r["error"]).upper() and attempt < 4:
                time.sleep(2)
                continue
            return r
        except Exception:
            if attempt == 4:
                raise
            time.sleep(2)


def view(account, method, args=None):
    a = base64.b64encode(json.dumps(args or {}).encode()).decode()
    r = rpc("query", {"request_type": "call_function", "finality": "final", "account_id": account,
                      "method_name": method, "args_base64": a})
    if "result" not in r or "result" not in r["result"]:
        raise RuntimeError(f"view {account}.{method}: {json.dumps(r)[:400]}")
    return json.loads(bytes(r["result"]["result"]).decode())


def keyfile(account):
    return os.path.join(KEYS, f"{account}.json")


def call(signer, receiver, method, args, deposit="0 NEAR", gas="300 Tgas"):
    """Sign and send one function call; returns the tx hash (parsed from near-cli output)."""
    cmd = ["near", "contract", "call-function", "as-transaction", receiver, method, "json-args", json.dumps(args),
           "prepaid-gas", gas, "attached-deposit", deposit, "sign-as", signer, "network-config", "testnet",
           "sign-with-access-key-file", keyfile(signer), "send"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout + p.stderr
    m = re.search(r"Transaction ID: ([1-9A-HJ-NP-Za-km-z]{43,44})", out)
    if not m:
        raise RuntimeError(f"call {receiver}.{method} failed:\n{out[-1500:]}")
    return m.group(1)


def tx(tx_hash, sender, url=RPC):
    return rpc("EXPERIMENTAL_tx_status", {"tx_hash": tx_hash, "sender_account_id": sender, "wait_until": "FINAL"}, url)


def logs(txr):
    out = []
    for ro in txr.get("result", {}).get("receipts_outcome", []):
        for line in ro["outcome"]["logs"]:
            out.append({"receipt": ro["id"], "executor": ro["outcome"]["executor_id"], "log": line})
    return out


def events(txr, name=None):
    ev = []
    for l in logs(txr):
        if l["log"].startswith("EVENT_JSON:"):
            e = json.loads(l["log"][len("EVENT_JSON:"):])
            if name is None or e.get("event") == name:
                ev.append(e)
    return ev


def request_execution_args(txr):
    """The args our contract passed to outlayer.testnet request_execution, decoded from the receipts."""
    for r in txr.get("result", {}).get("receipts", []):
        if r.get("receiver_id") != OUTLAYER:
            continue
        for a in r["receipt"].get("Action", {}).get("actions", []):
            fc = a.get("FunctionCall")
            if fc and fc["method_name"] == "request_execution":
                return json.loads(base64.b64decode(fc["args"]))
    return None
