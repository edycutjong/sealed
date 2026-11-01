#!/usr/bin/env python3
"""`make open`: show that each paid delivery opens to the exploit the TEE verified — offline, no NEAR credentials.

For each paid corpus/published/<label>.json, take `enc` from the deliver tx args in corpus/evidence/<label>.json and:
  1. sha256(enc) = the h_enc in the worker's on-chain verdict (the hash `deliver` was paid against);
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


def deliver_enc(ev):
    for a in (ev.get("deliver_tx_status") or {}).get("transaction", {}).get("actions", []):
        fc = a.get("FunctionCall") if isinstance(a, dict) else None
        if fc and fc["method_name"] == "deliver":
            return base64.b64decode(json.loads(base64.b64decode(fc["args"]))["enc"])
    return None


def check(pub):
    ev = json.load(open(os.path.join(ROOT, "corpus", "evidence", pub["label"] + ".json")))
    inp, sec = pub["input"], pub["secrets"]
    out = ev["verdict_output"]
    verdict = json.loads(out) if isinstance(out, str) else out
    enc = deliver_enc(ev)
    if enc is None:
        return ["deliver tx"], None
    pk = bytes.fromhex(inp["protocol_enc_pk"])
    eph = PrivateKey(bytes.fromhex(sec["EPH_SK"]))
    epk, ct = enc[:32], enc[32:]
    nonce = hashlib.blake2b(epk + pk, digest_size=24).digest()
    fails = []
    if sha(enc) != verdict["h_enc"]:
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
    pubs = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(ROOT, "corpus", "published", "*.json")))]
    paid = [p for p in pubs if p.get("final_status") == "Paid"]
    if not paid:
        print("open: no paid deliveries in corpus/published/")
        return 1
    bad = 0
    for pub in paid:
        fails, proto = check(pub)
        bad += bool(fails)
        extra = "" if proto is None else " · protocol key opened the same plaintext"
        print(f"OPENED {pub['label']} [{pub['bounty'].split('.')[0]}]: sha256(enc)=h_enc · box opens · exploit = "
              f"the replayed one · sha256(exploit‖hunter‖salt) = commit{extra}" if not fails
              else f"FAIL {pub['label']}: {', '.join(fails)}")
    print(f"open: {len(paid) - bad} of {len(paid)} paid deliveries open to the verified exploit")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
