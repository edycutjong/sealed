#!/usr/bin/env python3
"""The 6 on-chain refusal kinds (spec: pool pull, duplicate, fake, invariant busy, delivery mismatch, expired award).

Fire (testnet, keys from ~/.config/near/sealed-testnet/, never printed) — each appends {kind, tx, signer, logs} to
corpus/refusals.json:
  refusals.py busy <bounty> <hunter> <invariant>        commit while another commit on that invariant is in flight
  refusals.py duplicate <bounty> <hunter> <invariant>   commit on an invariant that is already paid
  refusals.py pool-pull <bounty> <protocol>             protocol withdraw_pool(whole pool) while a claim is reserved
  refusals.py expire <bounty> <signer> <commit_id>      anyone voids an Awarded commit past its deliver_by
  refusals.py record <kind> <tx> <signer>               add a refusal fired elsewhere (fake / delivery mismatch tx)
Show (`make refusals`, no credentials):
  refusals.py                                           one line per kind: tx hash + the contract's log line

A busy / duplicate commit carries a random commit_hash and no secret row: the bounty refuses it before any worker
runs and refunds bond + deposit, so nothing about an exploit is needed."""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "day0"))
import near  # noqa: E402

OUT = os.path.join(ROOT, "corpus", "refusals.json")
KINDS = ["pool pull", "duplicate", "fake", "invariant busy", "delivery mismatch", "expired award"]
# The log line each kind must show (lib.rs): withdraw_pool / commit guards / on_verdict / deliver / expire.
MARK = {"pool pull": "REFUSED: claim pending", "duplicate": "invariant already paid",
        "fake": "no invariant broken", "invariant busy": "claim pending",
        "delivery mismatch": "delivery mismatch", "expired award": "EXPIRED"}
TESTNET = "https://testnet.nearblocks.io/txns/"


def load():
    return json.load(open(OUT)) if os.path.exists(OUT) else {"network": "testnet", "refusals": []}


def record(kind, tx, signer):
    txr = near.tx(tx, signer)
    logs = [l["log"] for l in near.logs(txr)]
    hit = [l for l in logs if MARK[kind] in l]
    d = load()
    d["refusals"].append({"kind": kind, "tx": tx, "signer": signer, "logs": logs, "matched": hit[0] if hit else None})
    json.dump(d, open(OUT, "w"), indent=1)
    print(f"{kind}: {tx} → {hit[0] if hit else 'NO MATCHING LOG: ' + '; '.join(logs)}")


def deposit_for(bounty, invariant):
    st = near.view(bounty, "view_state")
    inv = next(i for i in st["invariants"] if i["id"] == invariant)
    return int(inv["bond"]) + int(st["outlayer_deposit"])


def raw_commit(bounty, hunter, invariant):
    return near.call(hunter, bounty, "commit",
                     {"commit_hash": os.urandom(32).hex(), "invariant_id": invariant, "payout_to": hunter},
                     deposit=f"{deposit_for(bounty, invariant)} yoctonear", gas="300 Tgas")


def show():
    d = load()
    by = {}
    for r in d["refusals"]:
        if r["matched"]:
            by.setdefault(r["kind"], r)
    for k in KINDS:
        r = by.get(k)
        print(f"{'FIRED  ' if r else 'MISSING'} {k:<18} {TESTNET + r['tx'] if r else '-'}  {r['matched'] if r else ''}")
    print(f"refusals: {len(by)}/6 kinds on chain (log lines from corpus/refusals.json; "
          f"re-check any hash on the explorer)")
    return 0 if len(by) == 6 else 1


def main():
    a = sys.argv[1:]
    if not a:
        return show()
    if a[0] == "busy":
        record("invariant busy", raw_commit(a[1], a[2], a[3]), a[2])
    elif a[0] == "duplicate":
        record("duplicate", raw_commit(a[1], a[2], a[3]), a[2])
    elif a[0] == "pool-pull":
        pool = near.view(a[1], "view_state")["pool"]
        record("pool pull", near.call(a[2], a[1], "withdraw_pool", {"amount": pool}, gas="100 Tgas"), a[2])
    elif a[0] == "expire":
        record("expired award", near.call(a[2], a[1], "expire", {"commit_id": int(a[3])}, gas="100 Tgas"), a[2])
    elif a[0] == "record":
        record(a[1], a[2], a[3])
    else:
        sys.exit(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
