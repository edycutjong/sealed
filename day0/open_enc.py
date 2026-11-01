#!/usr/bin/env python3
"""Independent libsodium check: open `enc` with PyNaCl SealedBox and recompute h_exploit from the plaintext.

usage: open_enc.py <enc_hex> <h_enc_hex> <commit_hash_hex> [vectors.json]"""
import base64, hashlib, json, os, sys
from nacl.public import PrivateKey, SealedBox

enc = bytes.fromhex(sys.argv[1])
want_h_enc, want_commit = sys.argv[2], sys.argv[3]
vec = json.load(open(sys.argv[4] if len(sys.argv) > 4 else os.path.join(os.path.dirname(__file__), "vectors.json")))
ok = hashlib.sha256(enc).hexdigest() == want_h_enc
pt = json.loads(SealedBox(PrivateKey(bytes.fromhex(vec["protocol_sk"]))).decrypt(enc))
h = hashlib.sha256(base64.b64decode(pt["exploit"]) + pt["hunter"].encode() + bytes.fromhex(pt["salt"])).hexdigest()
ok = ok and h == want_commit
print(json.dumps({"sha256(enc)==h_enc": hashlib.sha256(enc).hexdigest() == want_h_enc,
                  "opened": True, "h_exploit_from_plaintext==commit": h == want_commit}))
sys.exit(0 if ok else 1)
