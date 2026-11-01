#!/usr/bin/env python3
"""Create a keyless probe account on the day-0 global code (G9) in ONE batch: CreateAccount, Transfer,
UseGlobalContract(hash), FunctionCall new(outlayer, wasm_url, wasm_hash). The pin has no setter, so a new
verifier url means a new probe account.  usage: mkprobe.py <name> <wasm_url> [deposit]"""
import json, re, subprocess, sys
import near

DEV = "sealed-dev-11010702.testnet"
GLOBAL_HASH = "6LeH16shVvqyppQ7kMpqKRWdV865qCXqkfKngz2uyZW9"  # results/g9.json
WASM_HASH = open(__file__.rsplit("/", 1)[0] + "/artifacts/verifier-day0.wasm.sha256").read().split()[0]


def main():
    name, url = sys.argv[1], sys.argv[2]
    deposit = sys.argv[3] if len(sys.argv) > 3 else "3 NEAR"
    acct = f"{name}.{DEV}"
    init = {"outlayer": near.OUTLAYER, "wasm_url": url, "wasm_hash": WASM_HASH}
    cmd = ["near", "transaction", "construct-transaction", DEV, "receiver-id", acct,
           "add-action", "create-account",
           "add-action", "transfer", deposit,
           "add-action", "use-global-contract", "use-global-hash", GLOBAL_HASH,
           "with-init-call", "new", "json-args", json.dumps(init), "prepaid-gas", "30 Tgas", "attached-deposit", "0 NEAR",
           "skip", "network-config", "testnet", "sign-with-access-key-file", near.keyfile(DEV), "send"]
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = p.stdout + p.stderr
    m = re.search(r"Transaction ID: ([1-9A-HJ-NP-Za-km-z]{43,44})", out)
    if not m:
        sys.exit(f"create {acct} failed:\n{out[-1500:]}")
    keys = near.rpc("query", {"request_type": "view_access_key_list", "finality": "final", "account_id": acct})
    print(json.dumps({"account": acct, "create_tx": m.group(1), "pin": near.view(acct, "get_pin"),
                      "access_keys": keys["result"]["keys"]}, indent=1))


if __name__ == "__main__":
    main()
