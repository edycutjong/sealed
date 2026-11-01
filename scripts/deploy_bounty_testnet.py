#!/usr/bin/env python3
"""Deploy one Sealed Exploit bounty to NEAR testnet.

Two creation paths exist; this is the "factory":

* PRODUCTION (keyless, immutable): deploy `bounty.wasm` once as NEAR global code *by hash*, then create each
  bounty account with a batch `CreateAccount, Transfer, UseGlobalContract(hash), FunctionCall new(cfg)` and
  NO `AddKey` — so the account has zero access keys for life (I6). near-sdk 5.9.0 exposes no UseGlobalContract
  promise action, so this batch is issued from near-cli-rs / near-api, not from a factory *contract*. Day-0 G9
  proved a global-hash account comes up with 0 access keys (`day0/results/g9.json`).

* ITERATION (this script's default `--keyed`): a normal funded subaccount with a key, for fast redeploys
  during the build. Used for the P1b first testnet deploy; never used for a bounty a judge or hunter touches.

Run from `build/`:  python3 -I scripts/deploy_bounty_testnet.py --account b1.sealed-dev-<id>.testnet --keyed
The key is read from ~/.config/near/sealed-testnet/<account>.json and never printed.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = os.path.expanduser("~/.config/near/sealed-testnet")
WASM = os.path.join(ROOT, "contracts/target/wasm32-unknown-unknown/release/bounty.wasm")
OPT_WASM = "/tmp/bounty-opt.wasm"


def sh(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout + p.stderr


def build_opt():
    """wasm-opt -Oz the release build; return (path, sha256). Deterministic per wasm-opt version."""
    subprocess.run(["wasm-opt", "-Oz", WASM, "-o", OPT_WASM], check=True)
    h = hashlib.sha256(open(OPT_WASM, "rb").read()).hexdigest()
    return OPT_WASM, h


def cfg(account, protocol, verifier_hash, verifier_url, snapshot_hash):
    return {
        "protocol": protocol,
        "protocol_enc_pk": os.environ.get("PROTOCOL_ENC_PK", "7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14"),
        "token": f"tusdc.{account}",
        "outlayer": "outlayer.testnet",
        "verifier_wasm_hash": verifier_hash,
        "verifier_wasm_url": verifier_url,
        "snapshot_hashes": [snapshot_hash],
        "invariants": [{"id": "fallback-owner-drained", "target": 0, "amount": "1000000", "bond": "500000000000000000000000"}],
        "bond_floor": "500000000000000000000000",
        "outlayer_deposit": "100000000000000000000000",
        "deliver_ttl_ns": 3_600_000_000_000,
        "timelock_ns": 604_800_000_000_000,
        "max_instructions": 2_000_000_000,
        "max_memory_mb": 512,
        "max_execution_seconds": 120,
        "stale_after_ns": 1_800_000_000_000,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--account", required=True)
    ap.add_argument("--protocol", default="sealed-dev-11010702.testnet")
    ap.add_argument("--verifier-hash", default="92a4681dd4eebe23cd0d230bd3d8012a902e94a51cfa8654e5300e547c6a179a")
    ap.add_argument("--verifier-url", default="")
    ap.add_argument("--snapshot-hash", default="57263dfb780961cfb0391a49684340ba627e7e39159b1d513fd2e2861c60a073")
    ap.add_argument("--keyed", action="store_true", help="iteration mode (keyed subaccount); omit for the keyless production path")
    a = ap.parse_args()
    if not a.keyed:
        print("Keyless global-hash creation is issued via near-cli batch; see this file's docstring and G9.", file=sys.stderr)
        sys.exit(2)

    path, h = build_opt()
    print(f"bounty.wasm (wasm-opt -Oz): {h} ({os.path.getsize(path)} B)")
    key = os.path.join(KEYS, f"{a.account}.json")
    deploy = sh(["near", "contract", "deploy", a.account, "use-file", path, "without-init-call",
                 "network-config", "testnet", "sign-with-access-key-file", key, "send"])
    print("deploy:", "ok" if "successfully deployed" in deploy else deploy[-400:])
    c = json.dumps({"cfg": cfg(a.account, a.protocol, a.verifier_hash, a.verifier_url or f"https://unset/{a.verifier_hash}.wasm", a.snapshot_hash)})
    init = sh(["near", "contract", "call-function", "as-transaction", a.account, "new", "json-args", c,
               "prepaid-gas", "30 Tgas", "attached-deposit", "0 NEAR", "sign-as", a.account,
               "network-config", "testnet", "sign-with-access-key-file", key, "send"])
    print("init:", "signed" if "signed successfully" in init else init[-400:])


if __name__ == "__main__":
    main()
