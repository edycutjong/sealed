#!/usr/bin/env python3
"""`make open`: show that each paid delivery opens to the exploit the TEE verified — offline, no NEAR credentials.

The paid set must be exactly the Paid runs in corpus/results.json, each with one published record and one evidence
bundle (else FAIL before any box is opened). Per paid run, from corpus/evidence/<label>.json (the bundle `make verify`
ties to the chain):
  0. bindings: the published input is the request input the bounty sent; the worker's verdict says broken, for this
     invariant, with h_exploit = the commit hash; the bounty logged AWARDED and DELIVERED with that h_enc and
     PAID for this commit id; the deliver tx names this commit id. Take `enc` from the deliver tx args, then:
  1. sha256(enc) = the verdict's h_enc (the hash `deliver` was paid against);
  2. open the box. `enc = epk ‖ crypto_box(PT, nonce, protocol_pk, EPH_SK)` (verifier/src/seal.rs), and a crypto_box
     key is shared: X25519(EPH_SK, protocol_pk) = X25519(protocol_sk, epk). After payment the hunter's EPH_SK is
     published, so anyone opens the same box the protocol opens with its own key;
  3. the plaintext's exploit, salt and hunter equal the published ones that `make replay` re-runs, and
     sha256(exploit ‖ hunter ‖ salt) = the commit hash the hunter committed before the verdict.
If the protocol's own key is on this machine (~/.config/sealed/<bounty>.protocol.json), it also opens enc as a
libsodium SealedBox and must get the same plaintext. Needs PyNaCl (`pip install pynacl`). Exit 0 only if every paid
delivery opens and matches."""
import base64, glob, hashlib, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    from nacl.public import Box, PrivateKey, PublicKey, SealedBox
except ImportError:
    print("open: needs PyNaCl — pip install pynacl", file=sys.stderr)
    sys.exit(2)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def deliver_args(ev):
    for a in (ev.get("deliver_tx_status") or {}).get("transaction", {}).get("actions", []):
        fc = a.get("FunctionCall") if isinstance(a, dict) else None
        if fc and fc["method_name"] == "deliver":
            return json.loads(base64.b64decode(fc["args"]))
    return {}


def deliver_enc(ev):
    enc = deliver_args(ev).get("enc")
    return base64.b64decode(enc) if enc else None


def check(pub):
    ev = json.load(open(os.path.join(ROOT, "corpus", "evidence", pub["label"] + ".json")))
    inp, sec = pub["input"], pub["secrets"]
    out = ev["verdict_output"]
    verdict = json.loads(out) if isinstance(out, str) else out
    enc = deliver_enc(ev)
    if enc is None:
        return ["deliver tx"], None
    cid, h_enc = str(pub["commit_id"]), verdict.get("h_enc")
    logs = ev.get("bounty_logs", []) + ev.get("deliver_logs", [])
    commit_log = next((l.split()[1] for l in logs if l.startswith("COMMIT ")), None)
    fails = [name for name, ok in (
        ("published commit id = the COMMIT log", commit_log == cid),
        ("published input = the request input", inp == json.loads(ev["request_execution_args"]["input_data"])),
        ("verdict broken", verdict.get("broken") is True),
        ("verdict invariant", verdict.get("invariant_id") == inp["invariant_id"]),
        ("verdict h_exploit = commit", verdict.get("h_exploit") == inp["commit_hash"]),
        ("AWARDED log", any(l.startswith(f"AWARDED {cid} ") and l.endswith(f" h_enc {h_enc}") for l in logs)),
        ("DELIVERED log", f"DELIVERED {cid} {h_enc}" in logs),
        ("PAID log", any(l.split()[:2] == ["PAID", cid] for l in logs)),
        ("deliver commit id", str(deliver_args(ev).get("commit_id")) == cid)) if not ok]
    pk = bytes.fromhex(inp["protocol_enc_pk"])
    eph = PrivateKey(bytes.fromhex(sec["EPH_SK"]))
    epk, ct = enc[:32], enc[32:]
    nonce = hashlib.blake2b(epk + pk, digest_size=24).digest()
    if sha(enc) != h_enc:
        fails.append("sha256(enc)=h_enc")
    if epk != bytes(eph.public_key):
        fails.append("epk")
    try:
        pt = Box(eph, PublicKey(pk)).decrypt(ct, nonce)
    except Exception:
        return fails + ["open"], None
    p = json.loads(pt)
    exploit = base64.b64decode(p["exploit"])
    if (exploit != sec["EXPLOIT"].encode() or p["salt"] != sec["SALT"] or p["hunter"] != inp["hunter"]):
        fails.append("plaintext=published")
    if sha(exploit + p["hunter"].encode() + bytes.fromhex(p["salt"])) != inp["commit_hash"]:
        fails.append("commit")
    key = os.path.expanduser(f"~/.config/sealed/{pub['bounty']}.protocol.json")
    proto = None
    if os.path.exists(key):
        proto = SealedBox(PrivateKey(bytes.fromhex(json.load(open(key))["sk"]))).decrypt(enc) == pt
        if not proto:
            fails.append("protocol key")
    return fails, proto


def main():
    runs = json.load(open(os.path.join(ROOT, "corpus", "results.json")))["runs"]
    want = sorted(r["label"] for r in runs if r.get("final_status") == "Paid")
    pubs = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(ROOT, "corpus", "published", "*.json")))]
    paid = [p for p in pubs if p.get("final_status") == "Paid"]
    have = sorted(p["label"] for p in paid)
    missing = [l for l in want if not os.path.exists(os.path.join(ROOT, "corpus", "evidence", l + ".json"))]
    if not want or have != want or missing:
        print(f"FAIL paid set: corpus/results.json Paid {want} vs published {have}; no evidence bundle: {missing}")
        return 1
    bad = 0
    for pub in paid:
        fails, proto = check(pub)
        bad += bool(fails)
        extra = "" if proto is None else " · protocol key opened the same plaintext"
        print(f"OPENED {pub['label']} [{pub['bounty'].split('.')[0]}]: verdict broken, h_exploit = commit · AWARDED, "
              f"DELIVERED, PAID for commit {pub['commit_id']} · sha256(enc) = h_enc · box opens to the published exploit"
              f" · sha256(exploit‖hunter‖salt) = commit{extra}" if not fails
              else f"FAIL {pub['label']}: {', '.join(fails)}")
    print(f"open: {len(paid) - bad} of {len(want)} paid runs (corpus/results.json) open to the exploit their verdict "
          f"and payout name")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
