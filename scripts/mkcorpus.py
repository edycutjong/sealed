#!/usr/bin/env python3
"""Write the D4 corpus: one verifier input per item in corpus/vectors/<name>.json + corpus/manifest.json.

TEST VECTORS ONLY (fixed salt / ephemeral / protocol keys from day0/vectors.json) — the testnet run in D5 re-seals
each item with fresh secrets through scripts/hunter.py. `expect` is the DESIGNED verdict for every hand-made item;
LLM-written items (corpus/llm/) have no designed verdict — `expect` is null and the golden file records what the
verifier says. `make corpus` re-runs every vector under wasmtime and compares it with its golden verdict.

  real          the level's real exploit (attack contracts: levels/src/attacks/Attacks.sol)
  near-miss     the intuitive wrong answer for that level (looks right, validateInstance says no)
  wrong-snapshot a real exploit committed against another level's invariant
  malformed     input the verifier must refuse as `exploit invalid: …` (never a verifier error = free retry)
  abuse         day-0 resource-abuse shapes (day0/abuse-*.json, G5b) — referenced, not copied
  llm           exploits written by outside models from the level source alone, kept verbatim

usage: (cd levels && forge build) && python3 scripts/mkcorpus.py   (rewrites corpus/vectors/ + corpus/manifest.json)"""
import glob, hashlib, json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEC = os.path.join(ROOT, "corpus", "vectors")
KEYS = json.load(open(os.path.join(ROOT, "day0", "vectors.json")))
PLAYER = "0x2000000000000000000000000000000000000002"

# target index = position in verifier SNAPSHOTS (verifier/src/lib.rs); invariant ids are the bounty's.
LEVELS = [
    ("fallback", "fallback-owner-drained"),
    ("telephone", "telephone-owner-taken"),
    ("delegation", "delegation-owner-taken"),
    ("force", "force-balance-nonzero"),
    ("king", "king-throne-locked"),
]
TARGET = {name: i for i, (name, _) in enumerate(LEVELS)}
INVARIANT = dict(LEVELS)


def snap(level):
    return json.load(open(os.path.join(ROOT, "verifier", "snapshots", f"{level}.json")))


def word(addr):
    return addr.lower().removeprefix("0x").rjust(64, "0")


def initcode(contract, *addrs):
    art = json.load(open(os.path.join(ROOT, "levels", "out", "Attacks.sol", f"{contract}.json")))
    return art["bytecode"]["object"] + "".join(word(a) for a in addrs)


def envelope(level, exploit_bytes):
    commit = hashlib.sha256(exploit_bytes + KEYS["hunter"].encode() + bytes.fromhex(KEYS["salt"])).hexdigest()
    return {
        "target": TARGET[level],
        "invariant_id": INVARIANT[level],
        "hunter": KEYS["hunter"],
        "commit_hash": commit,
        "protocol_enc_pk": KEYS["protocol_pk"],
        "secrets": {"EXPLOIT": exploit_bytes.decode(), "SALT": KEYS["salt"], "EPH_SK": KEYS["eph_sk"]},
    }


def compact(txs):
    return json.dumps(txs, separators=(",", ":")).encode()


def real_exploits():
    fb = snap("fallback")["instance"]
    tel = snap("telephone")["instance"]
    dl = snap("delegation")["instance"]
    fo = snap("force")["instance"]
    kg = snap("king")["instance"]
    return {
        "fallback": [
            {"to": fb, "data": "0xd7bb99ba", "value": "1"},  # contribute() with 1 wei
            {"to": fb, "data": "0x", "value": "1"},          # receive(): owner = player
            {"to": fb, "data": "0x3ccfd60b", "value": "0"},  # withdraw(): drain
        ],
        # CREATE TelephoneAttack(telephone, player): its constructor calls changeOwner, so tx.origin != msg.sender.
        "telephone": [{"to": None, "data": "0x" + initcode("TelephoneAttack", tel, PLAYER), "value": "0"}],
        # pwn() selector hits Delegation's fallback → delegatecall into Delegate → writes Delegation's slot 0.
        "delegation": [{"to": dl, "data": "0xdd365b8b", "value": "0"}],
        # CREATE ForceAttack(force) with 1 wei; its constructor selfdestructs into the receive-less level.
        "force": [{"to": None, "data": "0x" + initcode("ForceAttack", fo), "value": "1"}],
        # CREATE KingAttack(king) with the prize; the new king cannot receive, so the factory's reclaim reverts.
        "king": [{"to": None, "data": "0x" + initcode("KingAttack", kg), "value": "1000000000000000"}],
    }


def near_misses():
    fb = snap("fallback")["instance"]
    tel = snap("telephone")["instance"]
    dsnap = snap("delegation")
    delegate = "0x" + dsnap["accounts"][dsnap["factory"]]["storage"]["0x1"][-40:]
    fo = snap("force")["instance"]
    kg = snap("king")["instance"]
    return {
        # contribute + withdraw, skipping the receive() step that hands over ownership → withdraw reverts.
        ("fallback", "nearmiss-fallback-no-receive"): [
            {"to": fb, "data": "0xd7bb99ba", "value": "1"},
            {"to": fb, "data": "0x3ccfd60b", "value": "0"},
        ],
        # changeOwner(player) straight from the EOA: tx.origin == msg.sender, so nothing changes.
        ("telephone", "nearmiss-telephone-direct"): [{"to": tel, "data": "0xa6f9dae1" + word(PLAYER), "value": "0"}],
        # pwn() on the Delegate library itself: takes the Delegate's owner, not the Delegation instance's.
        ("delegation", "nearmiss-delegation-wrong-contract"): [{"to": delegate, "data": "0xdd365b8b", "value": "0"}],
        # plain ether transfer to a contract with no receive/fallback → reverts, balance stays 0.
        ("force", "nearmiss-force-transfer"): [{"to": fo, "data": "0x", "value": "1"}],
        # become king from the EOA: the factory reclaims the throne in validateInstance.
        ("king", "nearmiss-king-eoa"): [{"to": kg, "data": "0x", "value": "1000000000000000"}],
    }


def items():
    out = []
    real = real_exploits()
    for level, txs in real.items():
        out.append((f"real-{level}", "real", level, compact(txs), {"broken": True, "err": None}))
    for (level, name), txs in near_misses().items():
        out.append((name, "near-miss", level, compact(txs), {"broken": False, "err": None}))
    # The empty tx list on every kept level (Fallback's no-op is the day-0 `noop` golden).
    for level in ("telephone", "delegation", "force", "king"):
        out.append((f"noop-{level}", "near-miss", level, compact([]), {"broken": False, "err": None}))
    # Real exploits committed to the wrong invariant (another level's snapshot).
    out.append(("wrong-snapshot-fallback-on-telephone", "wrong-snapshot", "telephone", compact(real["fallback"]),
                {"broken": False, "err": None}))
    out.append(("wrong-snapshot-king-on-force", "wrong-snapshot", "force", compact(real["king"]),
                {"broken": False, "err": None}))
    # Malformed EXPLOIT payloads.
    tel = snap("telephone")["instance"]
    out.append(("malformed-not-json", "malformed", "telephone", b"call changeOwner from a contract",
                {"broken": False, "err": "exploit invalid: json"}))
    out.append(("malformed-bad-hex", "malformed", "telephone",
                compact([{"to": tel, "data": "0xzz", "value": "0"}]), {"broken": False, "err": "exploit invalid: data"}))
    out.append(("malformed-bad-address", "malformed", "delegation",
                compact([{"to": "0x1234", "data": "0xdd365b8b", "value": "0"}]),
                {"broken": False, "err": "exploit invalid: to"}))
    out.append(("malformed-too-many-txs", "malformed", "delegation",
                compact([{"to": tel, "data": "0x", "value": "0"}] * 5), {"broken": False, "err": "exploit invalid: too many txs"}))
    return out


def llm_items():
    """corpus/llm/<model>.md: the raw transcript. Every ```json block under `## <Level>` becomes one item, verbatim
    (the exact block text is the EXPLOIT secret — nothing re-serialized)."""
    out = []
    for path in sorted(glob.glob(os.path.join(ROOT, "corpus", "llm", "*.md"))):
        model = os.path.basename(path)[:-3]
        if model == "prompt":
            continue
        text = open(path).read()
        for m in re.finditer(r"^##+\s*\**\s*([A-Za-z]+)[^\n]*\n(.*?)```json\s*\n(.*?)\n```", text, re.S | re.M):
            level = m.group(1).lower()
            if level not in TARGET:
                continue
            out.append((f"llm-{model}-{level}", "llm", level, m.group(3).strip().encode(), None))
    return out


def main():
    os.makedirs(VEC, exist_ok=True)
    for old in glob.glob(os.path.join(VEC, "*.json")):
        os.remove(old)
    manifest = []
    for name, cat, level, ex, expect in items() + llm_items():
        with open(os.path.join(VEC, f"{name}.json"), "w") as f:
            json.dump(envelope(level, ex), f, separators=(",", ":"))
            f.write("\n")
        manifest.append({"name": name, "category": cat, "level": level, "target": TARGET[level],
                         "invariant_id": INVARIANT[level], "vector": f"corpus/vectors/{name}.json", "expect": expect})
    for path in sorted(glob.glob(os.path.join(ROOT, "day0", "abuse-*.json"))):
        name = os.path.basename(path)[:-5]
        manifest.append({"name": name, "category": "abuse", "level": "fallback", "target": 0,
                         "invariant_id": INVARIANT["fallback"], "vector": f"day0/{name}.json",
                         "expect": {"broken": False}})
    with open(os.path.join(ROOT, "corpus", "manifest.json"), "w") as f:
        json.dump({"v": 1, "levels": [{"target": i, "level": l, "invariant_id": inv} for i, (l, inv) in enumerate(LEVELS)],
                   "items": manifest}, f, indent=1)
        f.write("\n")
    by = {}
    for m in manifest:
        by[m["category"]] = by.get(m["category"], 0) + 1
    print(f"corpus: {len(manifest)} items", by)


if __name__ == "__main__":
    main()
