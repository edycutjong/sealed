#!/usr/bin/env python3
"""D7 mainnet leg: ONE small USDC bounty on NEAR mainnet, paid to a 1Click deposit address. This script never signs and
never sends a transaction: `plan` prints the exact commands, you run them with your own key (keychain / ledger).

  python3 scripts/mainnet_leg.py check                         # read-only preflight: tools, RPC, OutLayer, USDC, 1Click
  python3 scripts/mainnet_leg.py quote --to base --recipient 0x…   # 1Click quote for the payout (--live → real deposit address)
  python3 scripts/mainnet_leg.py plan --protocol you.near --bounty fallback.you.near --hunter hunter.near \\
        --payout-to <1Click deposit address or a NEAR account> [--gen-key | --protocol-enc-pk <hex>]
  python3 scripts/mainnet_leg.py status <1Click deposit address>   # PENDING_DEPOSIT / PROCESSING / SUCCESS / REFUNDED

The commands are the mainnet twins of the testnet runs in corpus/ (same bounty.wasm, same verifier.wasm, same call
shapes: scripts/deploy_bounty_testnet.py, scripts/hunter.py). Differences: outlayer.near, native USDC, and a small bond.
Mainnet has NOT been exercised by us: nothing here is claimed as run until the transaction hashes exist."""
import argparse, base64, hashlib, json, os, shutil, sys, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.join(ROOT, "day0"))

USDC = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"  # Circle native USDC on NEAR, 6 decimals
OUTLAYER = "outlayer.near"
RPC = "https://rpc.mainnet.fastnear.com"
ONECLICK = "https://1click.chaindefuser.com"
CHAINS = {"base": "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near",
          "arb": "nep141:arb-0xaf88d065e77c8cc2239327c5edb3a432268e5831.omft.near",
          "eth": "nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near",
          "near": "nep141:" + USDC}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(b):
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def http(url, body=None):
    req = urllib.request.Request(url, json.dumps(body).encode() if body is not None else None,
                                 {"Content-Type": "application/json", "User-Agent": "sealed-exploit/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()[:300]}
    except Exception as e:  # noqa: BLE001
        return 0, {"error": f"{type(e).__name__}: {e}"}


def rpc_view(account, method, args):
    a = base64.b64encode(json.dumps(args).encode()).decode()
    _, r = http(RPC, {"jsonrpc": "2.0", "id": 1, "method": "query", "params": {
        "request_type": "call_function", "finality": "final", "account_id": account, "method_name": method, "args_base64": a}})
    res = r.get("result", {}).get("result")
    return json.loads(bytes(res).decode()) if res else {"error": json.dumps(r.get("error", r))[:200]}


def global_hash():
    return b58(hashlib.sha256(open(os.path.join(ROOT, "contracts", "bounty.wasm"), "rb").read()).digest())


def check(_):
    ok = True
    for tool in ("near", "outlayer", "wasmtime"):
        have = shutil.which(tool)
        ok &= bool(have)
        print(f"{'OK  ' if have else 'MISS'} {tool}: {have or 'not on PATH'}")
    code, r = http(RPC, {"jsonrpc": "2.0", "id": 1, "method": "status", "params": []})
    print(f"{'OK  ' if code == 200 else 'FAIL'} mainnet RPC {RPC}: HTTP {code}")
    ok &= code == 200
    cfg = rpc_view(OUTLAYER, "get_config", {})
    print(f"{'OK  ' if 'error' not in cfg else 'FAIL'} {OUTLAYER} get_config: {json.dumps(cfg)[:140]}")
    meta = rpc_view(USDC, "ft_metadata", {})
    print(f"{'OK  ' if meta.get('symbol') == 'USDC' else 'FAIL'} native USDC ft_metadata: {meta.get('symbol')} decimals {meta.get('decimals')}")
    code, toks = http(ONECLICK + "/v0/tokens")
    have = {t["assetId"] for t in toks} if code == 200 and isinstance(toks, list) else set()
    for name, asset in CHAINS.items():
        print(f"{'OK  ' if asset in have else 'MISS'} 1Click asset {name}: {asset}")
    print(f"contracts/bounty.wasm global-code hash (bs58 of sha256): {global_hash()}")
    sys.exit(0 if ok else 1)


def quote(a):
    import datetime
    dl = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=a.deadline_h)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = {"dry": not a.live, "swapType": "EXACT_INPUT", "slippageTolerance": 100, "originAsset": CHAINS["near"],
            "depositType": "ORIGIN_CHAIN", "destinationAsset": CHAINS[a.to], "amount": str(a.amount),
            "refundTo": a.refund_to, "refundType": "ORIGIN_CHAIN", "recipient": a.recipient,
            "recipientType": "DESTINATION_CHAIN", "deadline": dl}
    code, r = http(ONECLICK + "/v0/quote", body)
    print(json.dumps({"http": code, **r}, indent=1)[:2500])
    if a.live and code in (200, 201):
        print("\nUse quote.depositAddress as --payout-to. Check progress with: mainnet_leg.py status <depositAddress>")
    sys.exit(0 if code in (200, 201) else 1)


def status(a):
    code, r = http(f"{ONECLICK}/v0/status?depositAddress={a.deposit}")
    print(json.dumps({"http": code, **r}, indent=1)[:2500])


def plan(a):
    import hunter  # the testnet client: only its local verifier run + exploit table are reused (no network)
    pk = a.protocol_enc_pk
    if a.gen_key:
        import deploy_bounty_testnet as d
        pk = d.protocol_key(a.bounty)
    sign = a.sign
    net = f"network-config mainnet {sign} send"
    gh = global_hash()
    vh = open(os.path.join(ROOT, "verifier.wasm.sha256")).read().split()[0]
    url = f"https://6pa7yka0ghwew5xh.public.blob.vercel-storage.com/wasm/{vh}.wasm"
    levels = json.load(open(os.path.join(ROOT, "corpus", "manifest.json")))["levels"]
    lv = next(l for l in levels if l["level"] == "fallback")
    snaps = [hashlib.sha256(open(os.path.join(ROOT, "verifier", "snapshots", f"{l['level']}.json"), "rb").read()).hexdigest()
             for l in levels]
    cfg = {"protocol": a.protocol, "protocol_enc_pk": pk or "<PROTOCOL_ENC_PK_HEX>", "token": USDC, "outlayer": OUTLAYER,
           "verifier_wasm_hash": vh, "verifier_wasm_url": url, "snapshot_hashes": snaps,
           "invariants": [{"id": lv["invariant_id"], "target": lv["target"], "amount": str(a.amount), "bond": a.bond}],
           "bond_floor": a.bond, "outlayer_deposit": a.outlayer_deposit, "deliver_ttl_ns": 3600 * 10**9,
           "timelock_ns": 604800 * 10**9, "max_instructions": 2_000_000_000, "max_memory_mb": 512,
           "max_execution_seconds": 120, "stale_after_ns": 1_800_000_000_000}
    steps = [
        ("0. preflight (read-only)", "python3 scripts/mainnet_leg.py check"),
        ("1. deploy bounty.wasm as GLOBAL code by hash (once per network; skips if already deployed; costs NEAR storage)",
         f"near contract deploy-as-global use-file contracts/bounty.wasm as-global-hash {a.protocol} {net}\n"
         f"   # expected hash: {gh}"),
        ("2. create the KEYLESS bounty account in one batch (CreateAccount + Transfer + UseGlobalContract + new, no AddKey)",
         f"near transaction construct-transaction {a.protocol} receiver-id {a.bounty} add-action create-account "
         f"add-action transfer '{a.bounty_funds} NEAR' add-action use-global-contract use-global-hash {gh} "
         f"with-init-call new json-args '{json.dumps(cfg, separators=(',', ':'))}' prepaid-gas '100 Tgas' "
         f"attached-deposit '0 NEAR' skip {net}"),
    ]
    regs = [a.bounty, a.hunter] + ([a.payout_to] if not a.payout_to.startswith("0x") else [])
    for acct in dict.fromkeys(regs):
        steps.append((f"3. register {acct} on USDC (storage_deposit, skip if already registered)",
                      f"near contract call-function as-transaction {USDC} storage_deposit json-args "
                      f"'{json.dumps({'account_id': acct, 'registration_only': True})}' prepaid-gas '30 Tgas' "
                      f"attached-deposit '0.00125 NEAR' sign-as {a.protocol} {net}"))
    steps.append((f"4. fund the pool: {a.amount} USDC base units ({a.amount / 1e6:g} USDC) from {a.protocol}",
                  f"near contract call-function as-transaction {USDC} ft_transfer_call json-args "
                  f"'{json.dumps({'receiver_id': a.bounty, 'amount': str(a.amount), 'msg': ''})}' prepaid-gas '100 Tgas' "
                  f"attached-deposit '1 yoctoNEAR' sign-as {a.protocol} {net}"))
    steps.append(("5. verify the bounty is keyless and pinned (read-only)",
                  f"near account list-keys {a.bounty} network-config mainnet now   # expect: no access keys\n"
                  f"   near contract call-function as-read-only {a.bounty} view_state json-args '{{}}' network-config mainnet now"))
    if pk:
        exploit = hunter.EXPLOITS["fallback"]
        ex = json.dumps(exploit, separators=(",", ":"))
        salt, esk = os.urandom(32).hex(), os.urandom(32).hex()
        commit = hashlib.sha256(ex.encode() + a.hunter.encode() + bytes.fromhex(salt)).hexdigest()
        inp = {"target": lv["target"], "invariant_id": lv["invariant_id"], "hunter": a.hunter, "commit_hash": commit,
               "protocol_enc_pk": pk}
        secrets = {"EXPLOIT": ex, "SALT": salt, "EPH_SK": esk}
        verdict, enc = hunter.local_run(inp, secrets)
        assert verdict["broken"], "the built-in Fallback exploit must break the level locally"
        path = os.path.expanduser(f"~/.config/sealed/mainnet-{a.hunter}-{commit[:8]}.json")
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"secrets": secrets, "input": inp, "enc_hex": enc}, f)
        prof = f"c-{commit[:8]}"
        steps += [
            (f"6. hunter {a.hunter} stores the sealed exploit (secrets file {path}, mode 600; never printed)",
             f"OUTLAYER_NETWORK=mainnet outlayer secrets set \"$(python3 -c \"import json;print(json.dumps(json.load(open('{path}'))['secrets']))\")\" "
             f"--wasm-hash {vh} --profile {prof} --access whitelist:{a.hunter} --via {a.bounty}\n"
             f"   # the stock CLI attaches 0.1 NEAR; this row is small enough (needs a funded {a.hunter}, run `outlayer login` first)"),
            (f"7. run `mainnet_leg.py quote --live` first if payout_to is a 1Click deposit address (its deadline must outlive the payout); commit (bond {a.bond} + OutLayer deposit {a.outlayer_deposit} yocto) — payout_to is the 1Click deposit address or NEAR account",
             f"near contract call-function as-transaction {a.bounty} commit json-args "
             f"'{json.dumps({'commit_hash': commit, 'invariant_id': lv['invariant_id'], 'payout_to': a.payout_to})}' "
             f"prepaid-gas '300 Tgas' attached-deposit '{int(a.bond) + int(a.outlayer_deposit)} yoctoNEAR' sign-as {a.hunter} {net}\n"
             f"   # then poll: near contract call-function as-read-only {a.bounty} view_commit json-args '{{\"commit_id\":<id>}}' network-config mainnet now"),
            ("8. deliver once the commit reads Awarded (sha256(enc) must equal the attested h_enc → PAID)",
             f"near contract call-function as-transaction {a.bounty} deliver json-args "
             f"'{json.dumps({'commit_id': '<id from step 7 log: COMMIT <id>>', 'enc': base64.b64encode(bytes.fromhex(enc)).decode()})}' "
             f"prepaid-gas '100 Tgas' attached-deposit '0 NEAR' sign-as {a.hunter} {net}"),
            ("9. 1Click: wait for the payout to cross chains", f"python3 scripts/mainnet_leg.py status {a.payout_to}"),
        ]
    else:
        steps.append(("6–9. hunter commands", "re-run `plan` with --gen-key (or --protocol-enc-pk <hex>) after step 1: `enc` is sealed to "
                      "the bounty's protocol key, so the hunter's commit_hash and deliver bytes depend on it"))
    for title, cmd in steps:
        print(f"\n# {title}\n{cmd}")
    print("\n# After the run: copy every transaction hash into corpus/mainnet.json (hash, signer, step) and re-check with\n"
          "#   python3 scripts/verify.py --rpc https://archival-rpc.mainnet.near.org --bounty %s   (mainnet support: not yet exercised)" % a.bounty)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="sub", required=True)
    sub.add_parser("check").set_defaults(f=check)
    q = sub.add_parser("quote")
    q.add_argument("--to", choices=sorted(CHAINS), default="base")
    q.add_argument("--recipient", required=True)
    q.add_argument("--refund-to", default="example.near", help="NEAR account refunded if the swap fails")
    q.add_argument("--amount", type=int, default=5_000_000, help="USDC base units (6 decimals); default 5 USDC")
    q.add_argument("--deadline-h", type=float, default=6, help="the deposit address stops being honoured after this")
    q.add_argument("--live", action="store_true", help="real quote with a deposit address (default: dry)")
    q.set_defaults(f=quote)
    s = sub.add_parser("status")
    s.add_argument("deposit")
    s.set_defaults(f=status)
    p = sub.add_parser("plan")
    p.add_argument("--protocol", required=True, help="your funded mainnet account (signs 1–5)")
    p.add_argument("--bounty", required=True, help="the new keyless account, e.g. fallback.<protocol>")
    p.add_argument("--hunter", required=True, help="a second funded mainnet account (signs 6–8)")
    p.add_argument("--payout-to", required=True)
    p.add_argument("--amount", type=int, default=5_000_000)
    p.add_argument("--bond", default="100000000000000000000000", help="yoctoNEAR, default 0.1 NEAR")
    p.add_argument("--outlayer-deposit", default="100000000000000000000000")
    p.add_argument("--bounty-funds", default="1", help="NEAR sent to the new bounty account for storage")
    p.add_argument("--sign", default="sign-with-keychain", help="near-cli-rs signer, e.g. sign-with-ledger")
    p.add_argument("--protocol-enc-pk")
    p.add_argument("--gen-key", action="store_true", help="create ~/.config/sealed/<bounty>.protocol.json (mode 600)")
    p.set_defaults(f=plan)
    a = ap.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
