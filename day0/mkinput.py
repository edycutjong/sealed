#!/usr/bin/env python3
"""Write the day-0 verifier inputs (TEST VECTORS ONLY: fixed keys, never used for a real bounty).

day0/fallback.json  — Ethernaut Fallback: contribute(1 wei) → send 1 wei (receive) → withdraw()
day0/noop.json      — same envelope, empty tx list
Secrets ride in the input's `secrets` field (day-0 runs without OutLayer secrets); the protocol test
secret key is in day0/vectors.json so PyNaCl can open `enc`."""
import hashlib, json, os, sys
from nacl.public import PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
SNAP = json.load(open(os.path.join(HERE, "..", "verifier", "snapshots", "fallback.json")))
INST = SNAP["instance"]

# Fixed test values (32 B each). Real hunters draw SALT and EPH_SK from a CSPRNG per commit.
SALT = "11" * 32
EPH_SK = "22" * 32
PROTOCOL_SK = bytes.fromhex("33" * 32)
PROTOCOL_PK = bytes(PrivateKey(PROTOCOL_SK).public_key).hex()
HUNTER = "sealed-hunter-a-11010702.testnet"

def exploit_bytes(txs):
    return json.dumps(txs, separators=(",", ":")).encode()

def envelope(txs, invariant_id):
    ex = exploit_bytes(txs)
    commit = hashlib.sha256(ex + HUNTER.encode() + bytes.fromhex(SALT)).hexdigest()
    return {
        "target": 0,
        "invariant_id": invariant_id,
        "hunter": HUNTER,
        "commit_hash": commit,
        "protocol_enc_pk": PROTOCOL_PK,
        "secrets": {"EXPLOIT": ex.decode(), "SALT": SALT, "EPH_SK": EPH_SK},
    }

FALLBACK = [
    {"to": INST, "data": "0xd7bb99ba", "value": "1"},  # contribute()
    {"to": INST, "data": "0x", "value": "1"},          # receive()
    {"to": INST, "data": "0x3ccfd60b", "value": "0"},  # withdraw()
]

def write(name, obj):
    with open(os.path.join(HERE, name), "w") as f:
        json.dump(obj, f, separators=(",", ":"))
        f.write("\n")

if __name__ == "__main__":
    write("fallback.json", envelope(FALLBACK, "fallback-owner-drained"))
    write("noop.json", envelope([], "fallback-owner-drained"))
    write("vectors.json", {"note": "TEST ONLY", "protocol_sk": PROTOCOL_SK.hex(), "protocol_pk": PROTOCOL_PK,
                           "salt": SALT, "eph_sk": EPH_SK, "hunter": HUNTER})
    print("wrote fallback.json noop.json vectors.json", file=sys.stderr)
