#!/usr/bin/env python3
"""`make replay`: re-run every published commit under wasmtime from the committed verifier.wasm — no network,
no NEAR credentials, no Rust toolchain.

For each corpus/published/<label>.json:
  1. The wasm run is the one whose sha256 equals the hash the bounty pinned (from the evidence bundle's request
     args): verifier.wasm (HEAD), or verifiers/<sha256>.wasm for a bounty pinned to an earlier build (the D3
     throwaway pins 92a4681d…, the pre-D4 Fallback-only verifier; rebuildable from the commit that introduced it).
  2. wasmtime runs the verifier on the exact input_data the bounty sent, with the published secrets.
  3. The replayed verdict (minus `lim`, the worker's environment report) must equal the verdict the TDX worker
     submitted on chain, byte for byte after JSON parsing. Offline, "on chain" means the bundle's copy of the
     resolve tx args (corpus/evidence/<label>.json); `make verify` re-fetches that tx and fails its `bundle`
     check if the copy differs, so the two targets together anchor replay to the chain.
  4. h_exploit = sha256(EXPLOIT ‖ hunter ‖ SALT) = the commit_hash the hunter committed.
  5. For a delivered commit: sha256(rebuilt enc) = h_enc = sha256(enc in the deliver tx args) — required for
     every commit whose bundle logs PAID (a paid row without its deliver tx is a FAIL, not a skip).

`make replay INPUT=<file>`: run a judge's own tx list ({target, invariant_id, txs:[{to|null,data,value}]}) — or
any corpus/vectors/*.json item as-is — against the same verifier and print its verdict (fresh random SALT /
EPH_SK, a placeholder hunter). Exit 0 = the verifier ran (the verdict is the output, broken or not); 1 = bad input.
Exit 0 only if every published commit replays to its on-chain verdict."""
import base64, glob, hashlib, json, os, re, shutil, subprocess, sys

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
    env = {**os.environ, **secrets, "SEALED_DEBUG_ENC": "1", "SEALED_TRACE": "1"}
    if shutil.which("wasmtime") is None:
        raise SystemExit("replay: wasmtime not on PATH — install it first (`brew install wasmtime` or "
                         "`curl https://wasmtime.dev/install.sh -sSf | bash`), then re-run")
    p = subprocess.run(["wasmtime", "run", "--env", "EXPLOIT", "--env", "SALT", "--env", "EPH_SK",
                        "--env", "SEALED_DEBUG_ENC", "--env", "SEALED_TRACE", wasm], input=json.dumps(inp).encode(),
                       capture_output=True, env=env)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.decode()[-400:])
    err = p.stderr.decode().splitlines()
    enc = next((l[4:] for l in err if l.startswith("enc=")), None)
    return json.loads(p.stdout), enc, validate_call(err)


def validate_call(stderr_lines):
    """The invariant check itself, from the verifier's trace: the EVM call validateInstance(instance, player) on the
    level's factory and what it returned (1 = broken). None when the exploit was rejected before that call.
    The verifier makes that call exactly once per run (lib.rs, after the exploit txs), so the first match is it."""
    for l in stderr_lines:
        m = re.match(r"trace: call (validateInstance\((0x[0-9a-f]+),(0x[0-9a-f]+)\)) from 0x[0-9a-f]+ "
                     r"on factory (0x[0-9a-f]+) -> (\w+) ?(0x[0-9a-f]*)?", l)
        if m:
            ret = m.group(6) or ""
            shown = str(int(ret, 16)) if m.group(5) == "success" and ret else m.group(5)
            return f"factory {m.group(4)[:10]}….validateInstance({m.group(2)[:10]}…, {m.group(3)[:10]}…) → {shown}"
    return None


def strip(v):
    return {k: x for k, x in v.items() if k != "lim"}


def deliver_enc(ev):
    for r in ev.get("deliver_tx_status", {}).get("transaction", {}).get("actions", []):
        fc = r.get("FunctionCall") if isinstance(r, dict) else None
        if fc and fc["method_name"] == "deliver":
            return base64.b64decode(json.loads(base64.b64decode(fc["args"]))["enc"])
    return None


def judge_input(path):
    try:
        j = json.load(open(path))
    except (OSError, ValueError) as e:
        print(f"replay: INPUT={path}: {e}", file=sys.stderr)
        return 1
    if isinstance(j, dict) and isinstance(j.get("txs"), list):
        exploit = json.dumps(j["txs"], separators=(",", ":"))
    elif isinstance(j, dict) and isinstance((j.get("secrets") or {}).get("EXPLOIT"), str):
        exploit = j["secrets"]["EXPLOIT"]  # a corpus/vectors item: its exploit string, byte for byte
    else:
        print(f'replay: INPUT={path}: expected {{"target": 0, "invariant_id": "...", "txs": [{{"to": "0x…", '
              f'"data": "0x…", "value": "0"}}]}} or a corpus/vectors/*.json file', file=sys.stderr)
        return 1
    secrets = {"EXPLOIT": exploit, "SALT": os.urandom(32).hex(), "EPH_SK": os.urandom(32).hex()}
    commit = sha(secrets["EXPLOIT"].encode() + JUDGE.encode() + bytes.fromhex(secrets["SALT"]))
    inp = {"target": j.get("target", 0), "invariant_id": j.get("invariant_id", "fallback-owner-drained"),
           "hunter": JUDGE, "commit_hash": commit, "protocol_enc_pk": DEMO_PK}
    v, _, call = run(inp, secrets)
    print(json.dumps(strip(v)))
    print(f"EVM {call}" if call else "EVM no validateInstance call (exploit rejected before the invariant check)",
          file=sys.stderr)
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
        v, enc, call = run(sent, pub["secrets"], wasm)
        chain = ev.get("verdict_output")
        chain = json.loads(chain) if isinstance(chain, str) else chain
        if not isinstance(chain, dict) or strip(chain) != strip(v):
            fails.append("replayed verdict != on-chain worker verdict")
        if v["h_exploit"] != sent["commit_hash"]:
            fails.append("h_exploit != commit_hash")
        d = deliver_enc(ev)
        if d is None and any(l.startswith("PAID ") for l in ev.get("deliver_logs") or []):
            fails.append("paid commit without its deliver tx in the bundle")
        if d is not None and not (sha(d) == v["h_enc"] == sha(bytes.fromhex(enc))):
            fails.append("delivered enc != rebuilt enc / h_enc")
        tag = "REPLAY-OK" if not fails else "REPLAY-FAIL"
        what = "broken" if v["broken"] else f"not broken ({v['err'] or 'no invariant broken'})"
        extra = f" · enc {len(d)} B = h_enc" if d is not None else ""
        print(f"{tag} {label}: {what} · wasm {pinned[:8]} · h_exploit {v['h_exploit'][:12]}… = commit · verdict = chain{extra}"
              + ("" if not fails else " · " + "; ".join(fails)))
        print(f"    EVM {call}" if call else "    EVM no validateInstance call (exploit rejected before the invariant check)")
        ok, bad = ok + (not fails), bad + bool(fails)
    print(f"replay: {ok} OK · {bad} FAIL · verifier.wasm {wasm_hash[:16]}…")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
