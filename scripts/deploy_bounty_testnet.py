#!/usr/bin/env python3
"""Deploy one Sealed Exploit bounty to NEAR testnet.

Two creation paths exist; this is the "factory":

* PRODUCTION (keyless, immutable): deploy `bounty.wasm` once as NEAR global code *by hash*, then create each
  bounty account with a batch `CreateAccount, Transfer, UseGlobalContract(hash), FunctionCall new(cfg)` and
  NO `AddKey` — so the account has zero access keys for life (I6). near-sdk 5.9.0 exposes no UseGlobalContract
  promise action, so this batch is issued from near-cli-rs / near-api, not from a factory *contract*. Day-0 G9
  proved a global-hash account comes up with 0 access keys (`day0/results/g9.json`).

* ITERATION (this script's `--keyed`): a normal funded subaccount with a key, for fast redeploys during the
  build (P1b `b1`, the D3 throwaway `d3`). Never the bounty a judge or outside hunter touches.

Run from `build/`:
  python3 scripts/deploy_bounty_testnet.py --account d3.sealed-dev-<id>.testnet --keyed \
      --create 5 --token --fund 2000000000 --register <hunter> [--register <hunter> ...]

`--create N` creates the keyed subaccount from the protocol account with N NEAR; `--token` creates
`tusdc.<account>`, deploys the committed `contracts/test-token.wasm` (fixed supply minted to the protocol) and
registers the bounty; `--register` storage-registers payout accounts; `--fund` moves that many token units
into the pool with `ft_transfer_call`. Deploys the committed `contracts/bounty.wasm` (`make contracts-wasm`).
Keys are read from ~/.config/near/sealed-testnet/<account>.json and never printed.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "day0"))
import near  # noqa: E402

BOUNTY_WASM = os.path.join(ROOT, "contracts/bounty.wasm")
TOKEN_WASM = os.path.join(ROOT, "contracts/test-token.wasm")
VERIFIER = os.path.join(ROOT, "verifier.wasm")
BLOB = "https://6pa7yka0ghwew5xh.public.blob.vercel-storage.com/wasm"
TOKEN_SUPPLY = "1000000000000"  # 1 000 000 test tokens, 6 decimals, minted once to the protocol


def sh(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout + p.stderr


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def txid(out):
    import re
    m = re.search(r"Transaction ID: ([1-9A-HJ-NP-Za-km-z]{43,44})", out)
    return m.group(1) if m else None


def create(account, parent, near_amount):
    pk = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "day0/keygen.py"), account],
                        capture_output=True, text=True, check=True).stdout.strip()
    out = sh(["near", "account", "create-account", "fund-myself", account, f"{near_amount} NEAR",
              "use-manually-provided-public-key", pk, "sign-as", parent, "network-config", "testnet",
              "sign-with-access-key-file", near.keyfile(parent), "send"])
    t = txid(out)
    if not t:
        sys.exit(f"create {account} failed:\n{out[-800:]}")
    return t


def deploy(account, wasm, init_method, init_args):
    out = sh(["near", "contract", "deploy", account, "use-file", wasm, "with-init-call", init_method,
              "json-args", json.dumps(init_args), "prepaid-gas", "100 Tgas", "attached-deposit", "0 NEAR",
              "network-config", "testnet", "sign-with-access-key-file", near.keyfile(account), "send"])
    t = txid(out)
    if not t:
        sys.exit(f"deploy {account} failed:\n{out[-800:]}")
    return t


def protocol_key(account):
    """The protocol's X25519 keypair for this bounty (opens `enc`): ~/.config/sealed/<account>.protocol.json,
    mode 600, created once. Returns the public key hex; the secret key is never printed."""
    from nacl.public import PrivateKey
    d = os.path.expanduser("~/.config/sealed")
    os.makedirs(d, mode=0o700, exist_ok=True)
    path = os.path.join(d, f"{account}.protocol.json")
    if not os.path.exists(path):
        sk = PrivateKey.generate()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"bounty": account, "sk": bytes(sk).hex(), "pk": bytes(sk.public_key).hex()}, f)
    return json.load(open(path))["pk"]


def cfg(a, token):
    return {
        "protocol": a.protocol,
        "protocol_enc_pk": a.protocol_enc_pk,
        "token": token,
        "outlayer": "outlayer.testnet",
        "verifier_wasm_hash": a.verifier_hash,
        "verifier_wasm_url": a.verifier_url or f"{BLOB}/{a.verifier_hash}.wasm",
        "snapshot_hashes": [a.snapshot_hash],
        "invariants": [{"id": "fallback-owner-drained", "target": 0, "amount": a.amount, "bond": a.bond}],
        "bond_floor": a.bond,
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
    ap.add_argument("--protocol-enc-pk", required=False, help="X25519 public key (hex) the protocol opens enc with")
    ap.add_argument("--verifier-hash", default=None, help="default: sha256 of the committed verifier.wasm")
    ap.add_argument("--verifier-url", default="")
    ap.add_argument("--snapshot-hash", default="57263dfb780961cfb0391a49684340ba627e7e39159b1d513fd2e2861c60a073")
    ap.add_argument("--amount", default="1000000000", help="payout per invariant in token units (default 1000 tokens)")
    ap.add_argument("--bond", default="500000000000000000000000")
    ap.add_argument("--keyed", action="store_true", help="iteration mode (keyed subaccount); omit for the keyless production path")
    ap.add_argument("--create", type=float, help="create the keyed account first, funded with this many NEAR")
    ap.add_argument("--token", action="store_true", help="create tusdc.<account> and deploy the test token")
    ap.add_argument("--register", action="append", default=[], help="storage-register a payout account on the token")
    ap.add_argument("--fund", help="token units the protocol moves into the pool")
    ap.add_argument("--record", help="write the deploy record (JSON) here")
    a = ap.parse_args()
    if not a.keyed:
        print("Keyless global-hash creation is issued via near-cli batch; see this file's docstring and G9.", file=sys.stderr)
        sys.exit(2)
    a.verifier_hash = a.verifier_hash or sha(VERIFIER)
    a.protocol_enc_pk = a.protocol_enc_pk or protocol_key(a.account)

    rec = {"network": "testnet", "bounty_account": a.account, "protocol": a.protocol,
           "bounty_wasm_sha256": sha(BOUNTY_WASM), "bounty_wasm_bytes": os.path.getsize(BOUNTY_WASM)}
    token = f"tusdc.{a.account}"
    if a.create:
        rec["create_account_tx"] = create(a.account, a.protocol, a.create)
        print("created", a.account, rec["create_account_tx"])
    if a.token:
        rec["token_create_tx"] = create(token, a.account, 2.5)
        rec["token_wasm_sha256"] = sha(TOKEN_WASM)
        rec["token_deploy_tx"] = deploy(token, TOKEN_WASM, "new",
                                        {"owner": a.protocol, "total_supply": TOKEN_SUPPLY, "decimals": 6})
        print("token", token, rec["token_deploy_tx"])
    c = cfg(a, token)
    rec["config"] = c
    rec["deploy_tx"] = deploy(a.account, BOUNTY_WASM, "new", {"cfg": c})
    print("bounty", a.account, rec["deploy_tx"])
    rec["register_txs"] = {}
    for acct in [a.account] + a.register:
        rec["register_txs"][acct] = near.call(a.protocol, token, "storage_deposit",
                                              {"account_id": acct, "registration_only": True}, deposit="0.01 NEAR")
    if a.fund:
        rec["fund_tx"] = near.call(a.protocol, token, "ft_transfer_call",
                                   {"receiver_id": a.account, "amount": a.fund, "msg": ""},
                                   deposit="1 yoctonear", gas="100 Tgas")
        print("funded", a.fund, rec["fund_tx"])
    rec["view_state"] = near.view(a.account, "view_state")
    if a.record:
        json.dump(rec, open(a.record, "w"), indent=1)
    print(json.dumps({k: rec["view_state"][k] for k in ("pool", "reserved", "verifier_wasm_hash", "verifier_wasm_url")}))


if __name__ == "__main__":
    main()
