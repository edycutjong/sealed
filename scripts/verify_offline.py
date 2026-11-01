#!/usr/bin/env python3
"""`make replay`: re-run every published commit under wasmtime from the committed verifier.wasm — no network,
no NEAR credentials, no Rust toolchain.

For each corpus/published/<label>.json:
  1. The wasm run is the one whose sha256 equals the hash the bounty pinned (from the evidence bundle's request
     args): verifier.wasm (HEAD), or verifiers/<sha256>.wasm for a bounty pinned to an earlier build (the D3
     throwaway pins 92a4681d…, the pre-D4 Fallback-only verifier; rebuildable from the commit that introduced it).
  2. wasmtime runs the verifier on the exact input_data the bounty sent, with the published secrets.
  3. The replayed verdict (minus `lim`, the worker's environment report) must equal the verdict the TDX worker
     submitted on chain (corpus/evidence/<label>.json → resolve tx args), byte for byte after JSON parsing.
  4. h_exploit = sha256(EXPLOIT ‖ hunter ‖ SALT) = the commit_hash the hunter committed.
  5. For a delivered commit: sha256(rebuilt enc) = h_enc = sha256(enc in the deliver tx args).

`make replay INPUT=<file>`: run a judge's own tx list ({target, invariant_id, txs:[{to|null,data,value}]})
against the same verifier and print its verdict (fresh random SALT / EPH_SK, a placeholder hunter).
Exit 0 only if every published commit replays to its on-chain verdict."""
import base64, glob, hashlib, json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERIFIER = os.path.join(ROOT, "verifier.wasm")
JUDGE = "judge.testnet"
DEMO_PK = "0" * 63 + "9"  # INPUT= mode only: any 32-byte key works; nothing is delivered


def sha(b):
    return hashlib.sha256(b).hexdigest()


def wasm_for(pinned):
    """The committed wasm whose bytes hash to `pinned`, or None. Never trusts a file name alone."""
    for path in (VERIFIER, os.path.join(ROOT, "verifiers", f"{pinned}.wasm")):
        if os.path.exists(path) and sha(open(path, "rb").read()) == pinned:
            return path
    return None


def run(inp, secrets, wasm=VERIFIER):
    env = {**os.environ, **secrets, "SEALED_DEBUG_ENC": "1"}
    p = subprocess.run(["wasmtime", "run", "--env", "EXPLOIT", "--env", "SALT", "--env", "EPH_SK",
                        "--env", "SEALED_DEBUG_ENC", wasm], input=json.dumps(inp).encode(),
                       capture_output=True, env=env)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode()[-400:])
    enc = next((l[4:] for l in p.stderr.decode().splitlines() if l.startswith("enc=")), None)
    return json.loads(p.stdout), enc


def strip(v):
    return {k: x for k, x in v.items() if k != "lim"}


def deliver_enc(ev):
    for r in ev.get("deliver_tx_status", {}).get("transaction", {}).get("actions", []):
        fc = r.get("FunctionCall") if isinstance(r, dict) else None
        if fc and fc["method_name"] == "deliver":
            return base64.b64decode(json.loads(base64.b64decode(fc["args"]))["enc"])
    return None


def judge_input(path):
    j = json.load(open(path))
    secrets = {"EXPLOIT": json.dumps(j["txs"], separators=(",", ":")), "SALT": os.urandom(32).hex(),
               "EPH_SK": os.urandom(32).hex()}
    commit = sha(secrets["EXPLOIT"].encode() + JUDGE.encode() + bytes.fromhex(secrets["SALT"]))
    inp = {"target": j.get("target", 0), "invariant_id": j.get("invariant_id", "fallback-owner-drained"),
           "hunter": JUDGE, "commit_hash": commit, "protocol_enc_pk": DEMO_PK}
    v, _ = run(inp, secrets)
    print(json.dumps(strip(v)))
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1]:
        return judge_input(sys.argv[1])
    wasm_hash = sha(open(VERIFIER, "rb").read())
    pubs = sorted(glob.glob(os.path.join(ROOT, "corpus", "published", "*.json")))
    if not pubs:
        print("no published commits in corpus/published/")
        return 1
    ok = bad = 0
    for p in pubs:
        pub = json.load(open(p))
        label = pub["label"]
        ev = json.load(open(os.path.join(ROOT, "corpus", "evidence", f"{label}.json")))
        fails = []
        pinned = ev["request_execution_args"]["source"]["WasmUrl"]["hash"]
        wasm = wasm_for(pinned)
        if wasm is None:
            print(f"REPLAY-FAIL {label}: no committed wasm hashes to the pinned {pinned[:12]}…")
            bad += 1
            continue
        sent = json.loads(ev["request_execution_args"]["input_data"])
        if sent != pub["input"]:
            fails.append("published input != input_data the bounty sent")
        v, enc = run(sent, pub["secrets"], wasm)
        chain = ev.get("verdict_output")
        chain = json.loads(chain) if isinstance(chain, str) else chain
        if not isinstance(chain, dict) or strip(chain) != strip(v):
            fails.append("replayed verdict != on-chain worker verdict")
        if v["h_exploit"] != sent["commit_hash"]:
            fails.append("h_exploit != commit_hash")
        d = deliver_enc(ev)
        if d is not None and not (sha(d) == v["h_enc"] == sha(bytes.fromhex(enc))):
            fails.append("delivered enc != rebuilt enc / h_enc")
        tag = "REPLAY-OK" if not fails else "REPLAY-FAIL"
        what = "broken" if v["broken"] else f"not broken ({v['err'] or 'no invariant broken'})"
        extra = f" · enc {len(d)} B = h_enc" if d is not None else ""
        print(f"{tag} {label}: {what} · wasm {pinned[:8]} · h_exploit {v['h_exploit'][:12]}… = commit · verdict = chain{extra}"
              + ("" if not fails else " · " + "; ".join(fails)))
        ok, bad = ok + (not fails), bad + bool(fails)
    print(f"replay: {ok} OK · {bad} FAIL · verifier.wasm {wasm_hash[:16]}…")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
