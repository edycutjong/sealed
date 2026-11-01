#!/usr/bin/env python3
"""Sealed Exploit hunter client (testnet): seal an exploit, commit it, let OutLayer judge it, deliver, get paid.

usage: python3 scripts/hunter.py --bounty <acct> --hunter <acct> --exploit <name|file.json> --label <label>
       [--payout-to <acct>] [--no-deliver]
       python3 scripts/hunter.py --finish <label>   (re-build the evidence + published files of a saved run)

  1. EXPLOIT = the tx list (compact JSON); SALT, EPH_SK = 32 fresh random bytes each.
     commit_hash = sha256(EXPLOIT ‖ hunter ‖ SALT). The private run (secrets included) is saved FIRST to
     ~/.config/sealed/hunter-runs/<label>.json (mode 600), before anything touches the chain.
  2. Local pre-flight: the committed verifier.wasm under wasmtime, same input the bounty will send → verdict +
     the sealed `enc` (the verifier's deterministic sealed box), so the hunter knows h_enc before paying anything.
  3. store_secrets: OutLayer CLI row on accessor WasmHash(<pinned hash>), profile c-<commit_hash[..8]>, readable
     only when the hunter signs AND the call comes through this bounty (whitelist:<hunter> --via <bounty>).
  4. commit(commit_hash, invariant, payout_to) with bond + OutLayer deposit → the bounty checks payout_to's token
     registration → request_execution → the TDX worker runs the pinned verifier → on_verdict AWARDS or REFUSES.
  5. AWARDED → deliver(enc): sha256(enc) must equal the attested h_enc → PAID by ft_transfer to payout_to.
  6. Evidence bundle → corpus/evidence/<label>.json (chain data only, see scripts/evidence.py); the published
     run → corpus/published/<label>.json once the commit is terminal (self-play corpus: we are both sides, so the
     secrets are published in full, architecture.md "Publication rule").
Keys are read from ~/.config/near/sealed-testnet/ and never printed."""
import argparse, base64, hashlib, json, os, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "day0"))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import near  # noqa: E402
import evidence  # noqa: E402

VERIFIER = os.path.join(ROOT, "verifier.wasm")
PRIVATE = os.path.expanduser("~/.config/sealed/hunter-runs")
SNAP = json.load(open(os.path.join(ROOT, "verifier", "snapshots", "fallback.json")))
INST = SNAP["instance"]
# Built-in exploits for the Fallback level (target 0). A judge's own tx list: --exploit file.json.
EXPLOITS = {
    "fallback": [
        {"to": INST, "data": "0xd7bb99ba", "value": "1"},  # contribute() with 1 wei
        {"to": INST, "data": "0x", "value": "1"},          # receive(): owner = player
        {"to": INST, "data": "0x3ccfd60b", "value": "0"},  # withdraw(): drain
    ],
    "noop": [],  # a "fake": claims a break, executes nothing
    "contribute-only": [{"to": INST, "data": "0xd7bb99ba", "value": "1"}],  # near miss: never takes ownership
}
TERMINAL = ("Paid", "Refused", "Voided")


def status_name(s):
    return s if isinstance(s, str) else next(iter(s))


def local_run(inp, secrets):
    env = {**os.environ, **secrets, "SEALED_DEBUG_ENC": "1"}
    p = subprocess.run(["wasmtime", "run", "--env", "EXPLOIT", "--env", "SALT", "--env", "EPH_SK",
                        "--env", "SEALED_DEBUG_ENC", VERIFIER], input=json.dumps(inp).encode(),
                       capture_output=True, env=env)
    verdict = json.loads(p.stdout)
    enc = next((l[4:] for l in p.stderr.decode().splitlines() if l.startswith("enc=")), None)
    return verdict, enc


def store_secrets(hunter, bounty, wasm_hash, profile, secrets):
    home = os.path.expanduser(f"~/.config/outlayer/home-{hunter.split('-11010702')[0].replace('sealed-', '')}")
    env = {**os.environ, "OUTLAYER_HOME": home, "OUTLAYER_NETWORK": "testnet"}
    p = subprocess.run(["outlayer", "secrets", "set", json.dumps(secrets), "--wasm-hash", wasm_hash,
                        "--profile", profile, "--access", f"whitelist:{hunter}", "--via", bounty],
                       env=env, capture_output=True, text=True)
    out = (p.stdout + p.stderr).strip()
    if p.returncode != 0:
        sys.exit(f"store_secrets failed:\n{out[-800:]}")
    return out.splitlines()[-1]


def wait_commit(bounty, cid, done, timeout=900):
    t0 = time.time()
    while time.time() - t0 < timeout:
        c = near.view(bounty, "view_commit", {"commit_id": cid})
        if c and done(status_name(c["status"])):
            return c
        time.sleep(3)
    sys.exit(f"commit {cid} did not settle in {timeout}s")


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--finish":
        return finish(json.load(open(os.path.join(PRIVATE, f"{sys.argv[2]}.json"))))
    ap = argparse.ArgumentParser()
    ap.add_argument("--bounty", required=True)
    ap.add_argument("--hunter", required=True)
    ap.add_argument("--exploit", required=True)
    ap.add_argument("--label", required=True)
    ap.add_argument("--invariant", default="fallback-owner-drained")
    ap.add_argument("--payout-to")
    ap.add_argument("--no-deliver", action="store_true")
    ap.add_argument("--skip-store", action="store_true", help="commit without a secret row (refusal tests)")
    a = ap.parse_args()
    payout_to = a.payout_to or a.hunter

    st = near.view(a.bounty, "view_state")
    inv = next(i for i in st["invariants"] if i["id"] == a.invariant)
    txs = EXPLOITS[a.exploit] if a.exploit in EXPLOITS else json.load(open(a.exploit))["txs"]
    exploit = json.dumps(txs, separators=(",", ":"))
    secrets = {"EXPLOIT": exploit, "SALT": os.urandom(32).hex(), "EPH_SK": os.urandom(32).hex()}
    commit_hash = hashlib.sha256(exploit.encode() + a.hunter.encode() + bytes.fromhex(secrets["SALT"])).hexdigest()
    # Exactly the input_data the bounty builds in request_args (lib.rs): the verifier reads these five fields.
    inp = {"target": inv["target"], "invariant_id": a.invariant, "hunter": a.hunter,
           "commit_hash": commit_hash, "protocol_enc_pk": st["protocol_enc_pk"]}
    profile = f"c-{commit_hash[:8]}"

    os.makedirs(PRIVATE, mode=0o700, exist_ok=True)
    priv = os.path.join(PRIVATE, f"{a.label}.json")
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    run = {"label": a.label, "bounty": a.bounty, "hunter": a.hunter, "payout_to": payout_to,
           "exploit_name": a.exploit, "input": inp, "secrets": secrets, "profile": profile}
    with os.fdopen(fd, "w") as f:
        json.dump(run, f)

    verdict, enc = local_run(inp, secrets)
    run["local_verdict"] = verdict
    print(f"[{a.label}] local verdict broken={verdict['broken']} h_enc={verdict['h_enc'][:16]}… err={verdict['err']}")

    if not a.skip_store:
        run["store_secrets"] = store_secrets(a.hunter, a.bounty, st["verifier_wasm_hash"], profile, secrets)
        print(f"[{a.label}] secret row: {run['store_secrets'][:120]}")
    cid = int(st["commits"])
    bond = int(inv["bond"]) + int(st["outlayer_deposit"])
    t0 = time.time()
    commit_tx = near.call(a.hunter, a.bounty, "commit",
                          {"commit_hash": commit_hash, "invariant_id": a.invariant, "payout_to": payout_to},
                          deposit=f"{bond} yoctonear", gas="300 Tgas")
    print(f"[{a.label}] commit {cid} tx {commit_tx}")
    c = wait_commit(a.bounty, cid, lambda s: s not in ("AwaitingRegistration", "Pending"))
    run.update(commit_id=cid, commit_tx=commit_tx, verdict_status=c["status"],
               commit_to_verdict_s=round(time.time() - t0, 1))
    print(f"[{a.label}] verdict {c['status']} after {run['commit_to_verdict_s']} s")

    if status_name(c["status"]) == "Awarded" and not a.no_deliver:
        t1 = time.time()
        run["deliver_tx"] = near.call(a.hunter, a.bounty, "deliver",
                                      {"commit_id": cid, "enc": base64.b64encode(bytes.fromhex(enc)).decode()},
                                      gas="100 Tgas")
        c = wait_commit(a.bounty, cid, lambda s: s in TERMINAL, timeout=300)
        run["deliver_to_paid_s"] = round(time.time() - t1, 1)
        run["final_status"] = c["status"]
        print(f"[{a.label}] deliver tx {run['deliver_tx']} → {c['status']} after {run['deliver_to_paid_s']} s")
    run["final_status"] = c["status"]
    with open(priv, "w") as f:
        json.dump(run, f)
    finish(run)


def finish(run):
    """Evidence bundle + (terminal commits) the published run. Re-runnable: `--finish <label>`."""
    label = run["label"]
    ev = evidence.bundle(label, run["bounty"], run["hunter"], run["commit_tx"], run.get("deliver_tx"))
    os.makedirs(os.path.join(ROOT, "corpus", "evidence"), exist_ok=True)
    json.dump(ev, open(os.path.join(ROOT, "corpus", "evidence", f"{label}.json"), "w"), indent=1)
    if status_name(run["final_status"]) in TERMINAL:
        os.makedirs(os.path.join(ROOT, "corpus", "published"), exist_ok=True)
        pub = {"label": label, "bounty": run["bounty"], "commit_id": run["commit_id"], "input": run["input"],
               "secrets": run["secrets"], "exploit_name": run["exploit_name"], "final_status": run["final_status"],
               "timing_s": {k: run[k] for k in ("commit_to_verdict_s", "deliver_to_paid_s") if k in run}}
        json.dump(pub, open(os.path.join(ROOT, "corpus", "published", f"{label}.json"), "w"), indent=1)
    print(f"[{label}] evidence → corpus/evidence/{label}.json")


if __name__ == "__main__":
    main()
