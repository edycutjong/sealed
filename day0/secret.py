#!/usr/bin/env python3
"""G7 + G7d: per-hunter sealed secrets read by the pinned verifier, and how each secret failure arrives.

usage: secret.py ok | neg | fail

ok    stores, then reads, hunter A's row (WasmHash accessor, profile c-<commit prefix>, access
      And[Whitelist[A], Predecessor{Whitelist[probe]}]) is read inside the TEE: broken:true, h_exploit = commit.
neg   the same secrets_ref is refused (a) when hunter B signs through the probe, (b) when A calls OutLayer
      directly with no contract in between.
fail  G7d arrival types: missing profile, undecryptable row, oversized EXPLOIT.
Each case writes day0/results/g6-<label>.json via callback.py (direct calls: results/g7-<label>.json)."""
import base64, json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import near  # noqa: E402

A = "sealed-hunter-a-11010702.testnet"
B = "sealed-hunter-b-11010702.testnet"
PROBE = os.environ.get("PROBE", "probe1.sealed-dev-11010702.testnet")
INPUT = os.path.join(HERE, "fallback.json")
PROFILE = "c-" + json.load(open(INPUT))["commit_hash"][:8]
PIN_URL, PIN_HASH = near.view(PROBE, "get_pin")
LIMITS = {"max_instructions": 2_000_000_000, "max_memory_mb": 512, "max_execution_seconds": 120}


def via_probe(label, signer, profile, owner=A, inp=INPUT):
    ref = json.dumps({"profile": profile, "account_id": owner})
    subprocess.run([sys.executable, os.path.join(HERE, "callback.py"), inp, label, "--signer", signer,
                    "--secrets-ref", ref], check=False)


def direct(label, signer, profile, owner=A):
    """A calls outlayer.testnet itself: predecessor = A, so Predecessor{Whitelist[probe]} must refuse."""
    sent = json.load(open(INPUT))
    sent.pop("secrets", None)
    args = {"source": {"WasmUrl": {"url": PIN_URL, "hash": PIN_HASH, "build_target": "wasm32-wasip1"}},
            "resource_limits": LIMITS, "input_data": json.dumps(sent, separators=(",", ":")),
            "secrets_ref": {"profile": profile, "account_id": owner}, "response_format": "Text",
            "payer_account_id": signer}
    t0 = time.time()
    txh = near.call(signer, near.OUTLAYER, "request_execution", args, deposit="0.05 NEAR")
    txr = near.tx(txh, signer)
    status = txr.get("result", {}).get("status")
    out = {"label": label, "signer": signer, "request_tx": txh, "secrets_ref": args["secrets_ref"],
           "final_status": status, "wall_s_client": round(time.time() - t0, 1),
           "execution_completed": near.events(txr, "execution_completed"),
           "logs": [l["log"][:300] for l in near.logs(txr)][-8:]}
    if isinstance(status, dict) and "SuccessValue" in status:
        out["return"] = base64.b64decode(status["SuccessValue"]).decode(errors="replace")[:1200]
    json.dump(out, open(os.path.join(HERE, "results", f"g7-{label}.json"), "w"), indent=1)
    print(json.dumps({k: out.get(k) for k in ("label", "request_tx", "return")} | {"status": str(status)[:200]}))


def store_garbage(profile):
    """A row whose ciphertext nothing can decrypt (the CLI would encrypt; this calls store_secrets raw)."""
    cost = near.view(near.OUTLAYER, "estimate_storage_cost", {
        "accessor": {"WasmHash": {"hash": PIN_HASH}}, "profile": profile, "owner": A,
        "encrypted_secrets_base64": base64.b64encode(b"\x00" * 64).decode(),
        "access": "AllowAll", "vault_id": None})
    dep = f"{(int(cost) * 2) / 1e24:.6f} NEAR"
    return near.call(A, near.OUTLAYER, "store_secrets", {
        "accessor": {"WasmHash": {"hash": PIN_HASH}}, "profile": profile,
        "encrypted_secrets_base64": base64.b64encode(b"\x00" * 64).decode(),
        "access": "AllowAll", "vault_id": None}, deposit=dep)


def store_cli(profile, secrets):
    env = {**os.environ, "OUTLAYER_HOME": os.path.expanduser("~/.config/outlayer/home-hunter-a"),
           "OUTLAYER_NETWORK": "testnet"}
    # OUTLAYER_BIN: outlayer CLI 0.2.1 attaches a fixed 0.1 NEAR to `secrets set` (too little for a ~60 KB row);
    # day-0 used a local build that reads SEALED_SECRETS_DEPOSIT_YOCTO for the oversized case only.
    p = subprocess.run([os.environ.get("OUTLAYER_BIN", "outlayer"), "secrets", "set", json.dumps(secrets), "--wasm-hash", PIN_HASH, "--profile",
                        profile, "--access", f"whitelist:{A}", "--via", PROBE], env=env, capture_output=True, text=True)
    return (p.stdout + p.stderr).strip().splitlines()[-1]


if __name__ == "__main__":
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    mode = sys.argv[1]
    if mode == "ok":
        # rows are keyed by the pinned wasm hash: a new pin needs its row stored again
        print("row", store_cli(PROFILE, json.load(open(INPUT))["secrets"]))
        via_probe("g7-ok", A, PROFILE)
    elif mode == "neg":
        via_probe("g7-neg-signer-b", B, PROFILE)
        direct("neg-direct", A, PROFILE)
    elif mode in ("fail", "oversized"):
        if mode == "fail":
            via_probe("g7d-missing", A, "c-00000000")
            print("garbage row tx", store_garbage("c-badbad00"))
            via_probe("g7d-undecryptable", A, "c-badbad00")
        big = json.load(open(INPUT))["secrets"] | {"EXPLOIT": json.dumps(
            [{"to": None, "data": "0x" + "ab" * 15000, "value": "0"}] * 2, separators=(",", ":"))}
        os.environ.setdefault("SEALED_SECRETS_DEPOSIT_YOCTO", str(10**24))
        print("oversized row", store_cli("c-b1600000", big))
        via_probe("g7d-oversized", A, "c-b1600000")
