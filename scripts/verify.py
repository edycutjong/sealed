#!/usr/bin/env python3
"""`make verify`: prove each payout from chain data alone.

For every corpus/evidence/<label>.json, re-fetch the bundled txs from an archival RPC (default
`https://archival-rpc.testnet.fastnear.com`, `--rpc <url>` or NEAR_ARCHIVAL_RPC overrides; unreachable → read the
bundle, label `RECORDED`). Each commit yields one line with these checks:
  pinned   request_execution args pin WasmUrl.hash = the bounty's verifier_wasm_hash (`make replay` reruns
           those exact bytes, sha256-checked)
  worker   the verdict came back in a resolve tx for this request_id, sent TO the OutLayer contract the bounty
           calls (its live view_state), BY the operator OutLayer's get_config named at that block, signed by a
           FunctionCall key limited to the OutLayer contract whose method list includes resolve_execution. OutLayer documents registering worker keys after
           a TDX quote check (https://app.outlayer.ai/docs/tee-attestation); this script checks the key's scope, not
           the quote. On chain this shows the request pinned the hash and the operator's scoped worker key answered,
           NOT that the worker ran exactly those bytes (ARCHITECTURE.md §Limits).
  bundle   (online) the bundled verdict, request input, deliver args (enc + commit_id) and bounty / deliver logs
           equal the re-fetched chain values — so `make replay` and `make open`, which read only the bundle, are
           comparing against the chain
  verdict  the AWARDED/REFUSED the bounty logged agrees with the worker's submitted verdict (broken flag)
  h_enc    (paid) sha256(enc) from the deliver tx args = the award callback's h_enc = the verdict's h_enc
  paid     (paid) on_paid logged PAID for THIS commit id and the awarded amount
Then, online, per bounty: view_state paid_total = Σ bundled PAID amounts and escrow = Σ AWARDED/DELIVERED amounts
(a bundle cannot hide a payout by omitting its deliver tx).
The bundle set itself must equal the runs in corpus/results.json, each commit tx once (else FAIL before any check),
and online each bundled bounty's commit ids must be exactly 0..view_state.commits-1 (chain-anchored completeness).
Exit 0 only if ≥ 1 Paid line exists and every payout line is CHAIN-CHECKED (empty bundle → 1; offline or rate-limited → 2)."""
import argparse, base64, glob, hashlib, json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "day0"))
import near  # noqa: E402

RESOLVE_METHODS = ("resolve_execution", "submit_execution_output_and_resolve")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def reachable(url):
    try:
        return "result" in near.rpc("status", [], url)
    except Exception:
        return False


def tx_args(txr, method):
    for a in txr.get("transaction", {}).get("actions", []):
        fc = a.get("FunctionCall") if isinstance(a, dict) else None
        if fc and fc["method_name"] == method:
            return json.loads(base64.b64decode(fc["args"]))
    return None


def logs(txr, executor=None):
    out = []
    for ro in txr.get("receipts_outcome", []):
        if executor and ro["outcome"]["executor_id"] != executor:
            continue
        out += ro["outcome"]["logs"]
    return out


def verdict_output(res):
    """The verifier stdout the worker submitted, from the resolve tx args."""
    if not res or not res.get("args"):
        return None
    a = res["args"]
    out = (a.get("response") or {}).get("output") or a.get("output")
    if isinstance(out, dict):
        out = out.get("Text") or out.get("Json") or out.get("Bytes")
    return json.loads(out) if isinstance(out, str) else out


def req_id_of(ctx):
    """The OutLayer request_id this commit's request_execution produced (from the execution_requested event)."""
    for e in near.events({"result": ctx}, "execution_requested"):
        for d in e.get("data", []):
            rd = d.get("request_data")
            rd = json.loads(rd) if isinstance(rd, str) else rd
            if rd and "request_id" in rd:
                return int(rd["request_id"])
    return None


_STATE, _OPERATOR, _OP_FIXED, _KEY_FIXED = {}, {}, {}, {}
near.PACE_S = 0.35  # ~3 calls/s keeps FastNEAR's archival node from answering 429 (whose backoff dominated run time)


def live_state(bounty, url):
    """The bounty's view_state RIGHT NOW: the verifier hash it pins and the OutLayer contract it calls, so
    `pinned` and `worker` are independent of the bundle. An unusable answer is unchecked (→ RECORDED), never
    a silent fallback to the bundle's own values."""
    if bounty not in _STATE:
        try:
            _STATE[bounty] = near.view(bounty, "view_state", url=url)
        except RuntimeError as e:  # RPC answered without a result
            raise ConnectionError(f"view_state {bounty}: {e}") from e
    return _STATE[bounty]


def live_operator(outlayer, block_hash, url):
    """The worker operator account OutLayer's own config named at the resolve tx's block. When the operator is
    the same at the first and last resolve block of the run (`pin_operator`), that account is used for every block
    in between — one rotation away and back would need OutLayer's owner key."""
    if outlayer in _OP_FIXED:
        return _OP_FIXED[outlayer]
    if (outlayer, block_hash) not in _OPERATOR:
        try:
            cfg = near.view(outlayer, "get_config", url=url, block_id=block_hash)
        except RuntimeError as e:
            raise ConnectionError(f"{outlayer}.get_config at {block_hash}: {e}") from e
        # Today get_config returns [owner, operator]; accept an object with an `operator*` key too.
        op = cfg[1] if isinstance(cfg, list) and len(cfg) > 1 else next(
            (v for k, v in (cfg.items() if isinstance(cfg, dict) else []) if k.startswith("operator")), None)
        if not isinstance(op, str):
            raise ValueError(f"{outlayer}.get_config at {block_hash}: unrecognised shape {json.dumps(cfg)[:120]}")
        _OPERATOR[(outlayer, block_hash)] = op
    return _OPERATOR[(outlayer, block_hash)]


def access_key(account, public_key, block, url):
    """The access key as it stood at `block` (height or hash): None = no such key (a FAIL); an unusable answer
    (non-archival node, rate-limit body) raises → the row is unchecked, never a FAIL or a pass."""
    kr = near.rpc("query", {"request_type": "view_access_key", "block_id": block,
                            "account_id": account, "public_key": public_key}, url)
    key = kr.get("result")
    if key is None and "UNKNOWN_ACCESS_KEY" not in json.dumps(kr.get("error", {})):
        raise ConnectionError(f"view_access_key: {json.dumps(kr.get('error', kr))[:160]}")
    return key


def pin_keys(evs, url):
    """Same sampling for the worker key: per (signer, public key), read it at the earliest and latest bundled resolve
    block; if both reads return the same FunctionCall scope, that scope stands for every block between
    (the key was added before the first and still present after the last; deleting and re-adding the same key in
    between needs the operator's full-access key). Rows whose key differs query their own block."""
    by = {}
    for ev in evs:
        r = ev.get("resolve") or {}
        if r.get("signer") and r.get("public_key"):
            by.setdefault((r["signer"], r["public_key"]), []).append(r["block_height"])
    for (acct, pk), hs in by.items():
        lo, hi = access_key(acct, pk, min(hs), url), access_key(acct, pk, max(hs), url)
        scope = [{k: v for k, v in ((x or {}).get("permission", {}).get("FunctionCall") or {}).items() if k != "allowance"}
                 for x in (lo, hi)]  # the gas allowance shrinks with every resolve; the scope must not change
        if lo and hi and scope[0] and scope[0] == scope[1]:
            _KEY_FIXED[(acct, pk)] = {"permission": {"FunctionCall": scope[0]}}


def pin_operator(evs, url):
    """Read get_config at the earliest and latest bundled resolve block per OutLayer contract; if both name the same
    operator, pin it (2 calls instead of one per row). Otherwise every row queries its own block."""
    by = {}
    for ev in evs:
        if ev.get("resolve"):
            by.setdefault(live_state(ev["bounty"], url)["outlayer"], []).append(ev["resolve"]["block_height"])
    for outlayer, hs in by.items():
        lo, hi = live_operator(outlayer, min(hs), url), live_operator(outlayer, max(hs), url)
        if lo == hi:
            _OP_FIXED[outlayer] = lo


def amount_of(ev):
    aw = next((l for l in ev["bounty_logs"] if l.startswith("AWARDED ")), "")
    return int(aw.split("amount ")[1].split()[0]) if "amount " in aw else 0


def one(ev, online, url):
    """Re-fetch (online) or read from the bundle (offline), then run the checks for one commit."""
    inv_amount = None
    if online:
        ctx = near.tx(ev["commit_tx"], ev["hunter"], url)["result"]
        req = near.request_execution_args({"result": ctx})
        blog = logs(ctx, ev["bounty"])
        res = ev["resolve"]
        if res:
            rtx = near.tx(res["tx"], ev["operator"], url)["result"]
            res = {**res, "args": tx_args(rtx, res["method"]),
                   "signer": rtx["transaction"]["signer_id"], "public_key": rtx["transaction"]["public_key"],
                   "receiver": rtx["transaction"]["receiver_id"],
                   "block_hash": rtx["transaction_outcome"]["block_hash"]}
            # The bundle's `operator` only locates the tx; who counts as the worker comes from chain state:
            # the OutLayer contract this bounty calls, and the operator that contract named at that block.
            outlayer = live_state(ev["bounty"], url)["outlayer"]
            operator = live_operator(outlayer, res["block_hash"], url)
            # Scope the access-key lookup to the resolve tx's inclusion block: a later admin rotation/
            # revocation of the worker key must not fail a payout that was valid when the worker answered.
            key = _KEY_FIXED.get((res["signer"], res["public_key"])) or access_key(
                res["signer"], res["public_key"], res["block_hash"], url)
        else:
            key = None
        out = verdict_output(res)
        dtx = near.tx(ev["deliver_tx"], ev["hunter"], url)["result"] if ev.get("deliver_tx") else None
        dlog = logs(dtx, ev["bounty"]) if dtx else []
        denc = tx_args(dtx, "deliver") if dtx else None
    else:
        ctx, req, blog = ev["commit_tx_status"], ev["request_execution_args"], ev["bounty_logs"]
        outlayer, operator = ev["outlayer"], ev["operator"]  # bundle-only: these lines print RECORDED
        res, key, out = ev["resolve"], ev.get("worker_access_key"), ev.get("verdict_output")
        out = json.loads(out) if isinstance(out, str) else out
        dlog = ev.get("deliver_logs") or []
        denc = tx_args(ev["deliver_tx_status"], "deliver") if ev.get("deliver_tx_status") else None

    checks = []
    pinned = (req or {}).get("source", {}).get("WasmUrl", {}).get("hash")
    live_pin = live_state(ev["bounty"], url)["verifier_wasm_hash"] if online else ev["bounty_verifier_hash"]
    checks.append(("pinned", bool(pinned) and pinned == live_pin))
    answered = bool(res) and res.get("signer") == operator and res.get("receiver", outlayer) == outlayer
    # The resolve tx must be for THIS commit's request, not just any run the same worker key signed.
    rid_ok = bool(res) and int((res.get("args") or {}).get("request_id", -1)) == ev["request_id"] == req_id_of(ctx)
    perm = (key or {}).get("permission") or {}
    names = (perm.get("FunctionCall") or {}).get("method_names")
    key_ok = ("FunctionCall" in perm and perm["FunctionCall"].get("receiver_id") == outlayer
              and (names == [] or any(m in (names or []) for m in RESOLVE_METHODS)))  # [] = every method
    checks.append(("worker", answered and key_ok and rid_ok))
    if online:
        # Bind the bundle to the chain, so `make replay` (which reads only the bundle) compares against what
        # the chain says: the bundled verdict, request input and delivered enc must equal the re-fetched ones.
        b_out = ev.get("verdict_output")
        b_out = json.loads(b_out) if isinstance(b_out, str) else b_out
        b_enc = tx_args(ev["deliver_tx_status"], "deliver") if ev.get("deliver_tx_status") else None
        # …and so are the bundled bounty / deliver logs and the whole deliver args (enc AND commit_id), which
        # `make open` reads: a bundle cannot re-label which commit was delivered and paid.
        checks.append(("bundle", b_out == out
                       and ev["request_execution_args"].get("input_data") == (req or {}).get("input_data")
                       and b_enc == denc
                       and ev.get("bounty_logs") == blog and (ev.get("deliver_logs") or []) == dlog))
    awarded = any(l.startswith("AWARDED ") for l in blog)
    refused = any(l.startswith("REFUSED ") for l in blog)
    checks.append(("verdict", isinstance(out, dict) and bool(out.get("broken")) == awarded and (awarded or refused)))
    paid_logs = [l for l in dlog if l.startswith("PAID ")]
    delivered = any(l.startswith("DELIVERED ") for l in dlog)
    kind = "PAID" if paid_logs else ("REFUSED" if refused else ("DELIVERED" if delivered else "AWARDED"))
    if ev.get("expire_tx") and not paid_logs:
        # Awarded, never delivered, voided by `expire` after deliver_by: escrow back to the pool, bond slashed.
        elog = logs(near.tx(ev["expire_tx"], ev["expire_signer"], url)["result"], ev["bounty"]) if online else ev["expire_logs"]
        cid = next((l.split()[1] for l in blog if l.startswith("COMMIT ")), None)
        checks.append(("expired", cid is not None and any(l.startswith(f"EXPIRED {cid};") for l in elog)))
        kind = "VOIDED"
    if paid_logs:
        h_enc = sha(base64.b64decode(denc["enc"]))
        aw = next((l for l in blog if l.startswith("AWARDED ")), "")
        awarded_h = aw.split("h_enc ")[1] if "h_enc " in aw else ""
        awarded_amount = aw.split("amount ")[1].split(" ")[0] if "amount " in aw else None
        checks.append(("h_enc", h_enc == awarded_h == (out or {}).get("h_enc")))
        # PAID <commit_id> <amount>: THIS commit was paid, the amount the award logged.
        cid = next((l.split()[1] for l in blog if l.startswith("COMMIT ")), None)
        pw = paid_logs[-1].split()
        checks.append(("paid", cid is not None and len(pw) >= 3 and pw[1] == cid and aw.split()[1:2] == [cid]
                       and pw[2] == awarded_amount))
    fails = [n for n, g in checks if not g]
    return kind, checks, fails


def committed_code_hash():
    """base58(sha256(contracts/bounty.wasm)): the global code hash a judged bounty must run (README)."""
    d = hashlib.sha256(open(os.path.join(ROOT, "contracts", "bounty.wasm"), "rb").read()).digest()
    n, out = int.from_bytes(d, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(d) - len(d.lstrip(b"\0"))) + out


def bounty_integrity(bounty, online, url, require_keyless):
    """One line per bounty: access-key count + whether its code is the global-contract hash of the committed
    contracts/bounty.wasm. The production bounty is keyless on that hash (I6); the D3 throwaway is a keyed
    iteration account with its own code. INFO by default
    (not a payout check); `--require-keyless` turns a keyed bounty into a FAIL for the final judged run."""
    if not online:
        return f"bounty {bounty}: keys/code not re-checked (offline)", True
    try:
        kr = near.rpc("query", {"request_type": "view_access_key_list", "finality": "final", "account_id": bounty}, url)
        ar = near.rpc("query", {"request_type": "view_account", "finality": "final", "account_id": bounty}, url)
    except OSError as e:
        return f"bounty {bounty}: keys/code not re-checked (RPC error: {e})", None
    if "result" not in kr or "result" not in ar:  # an RPC error body must not read as "0 keys, own code"
        err = (kr if "result" not in kr else ar).get("error", {})
        return f"bounty {bounty}: keys/code not re-checked (RPC error: {json.dumps(err)[:160]})", None
    keys = kr["result"].get("keys", [])
    acct = ar["result"]
    glob, want = acct.get("global_contract_hash"), committed_code_hash()
    code = ("global code = committed contracts/bounty.wasm " + want[:8] + "…" if glob == want
            else f"global code {str(glob)[:8]}… ≠ committed contracts/bounty.wasm {want[:8]}…" if glob
            else "global code by account id" if acct.get("global_contract_account_id") else "own code")
    keyless = len(keys) == 0 and glob == want
    tag = f"{len(keys)} key(s), {code}"
    if keyless:  # "for life" (I6): it was also BORN keyless — the create tx added no key and set this code
        born = born_keyless(bounty, want, url)
        if born is None:
            return f"bounty {bounty}: {tag}; create tx not re-checked (RPC error or not in corpus/results.json)", None
        keyless, tag = born[0], f"{tag}; {born[1]}"
    ok = keyless if require_keyless else True
    return f"bounty {bounty}: {tag}" + ("" if ok else "  FAIL (--require-keyless)"), ok


def born_keyless(bounty, want, url):
    """The bounty's create tx (corpus/results.json) must be sent by its parent to it and hold only CreateAccount,
    Transfer, UseGlobalContract(code_hash = want) and FunctionCall `new` — no AddKey, no DeployContract — and
    succeed. With 0 keys from birth, nothing can sign for the account, and the bounty contract has no call that
    adds a key or changes code, so the code hash and the 0 keys hold for life. None = not checkable."""
    create = json.load(open(os.path.join(ROOT, "corpus", "results.json")))["bounties"].get(bounty, {}).get("create_tx")
    if not create:
        return None
    try:
        r = near.rpc("EXPERIMENTAL_tx_status", {"tx_hash": create, "sender_account_id": bounty.split(".", 1)[1],
                                                "wait_until": "FINAL"}, url)
    except OSError:
        return None
    if "result" not in r:
        return None
    t = r["result"].get("transaction", {})
    kinds = [a if isinstance(a, str) else next(iter(a)) for a in t.get("actions", [])]
    hashes = [a["UseGlobalContract"].get("code_hash") for a in t.get("actions", [])
              if isinstance(a, dict) and "UseGlobalContract" in a]
    calls = [a["FunctionCall"]["method_name"] for a in t.get("actions", []) if isinstance(a, dict) and "FunctionCall" in a]
    born = (t.get("signer_id") == bounty.split(".", 1)[1] and t.get("receiver_id") == bounty
            and "SuccessValue" in (r["result"].get("status") or {})
            and set(kinds) == {"CreateAccount", "Transfer", "UseGlobalContract", "FunctionCall"}
            and hashes == [want] and calls == ["new"])
    return born, (f"born keyless: create tx {create[:8]}… = {' · '.join(kinds)}, no AddKey" if born
                  else f"create tx {create[:8]}… is not a keyless global-code birth ({' · '.join(kinds)})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default=near.ARCHIVAL)
    ap.add_argument("--require-keyless", action="store_true",
                    help="fail if any bounty is keyed or its global code is not the committed contracts/bounty.wasm")
    ap.add_argument("--bounty", action="append", default=[],
                    help="only this bounty's bundles (repeatable); default: every bundle in corpus/evidence/")
    a = ap.parse_args()
    bundles = sorted(glob.glob(os.path.join(ROOT, "corpus", "evidence", "*.json")))
    if a.bounty:
        bundles = [b for b in bundles if json.load(open(b))["bounty"] in a.bounty]
    if not bundles:
        print("verify: empty bundle (no corpus/evidence/*.json)")
        return 1
    # Completeness: the checked set must be exactly the runs corpus/results.json reports (the numbers the README
    # quotes), each commit tx once — a copied bundle or a quietly deleted one changes the counts, so it FAILs.
    evs = [json.load(open(b)) for b in bundles]
    runs = json.load(open(os.path.join(ROOT, "corpus", "results.json")))["runs"]
    want = {r["label"] for r in runs if not a.bounty or r["bounty"] in a.bounty}
    have = [ev["label"] for ev in evs]
    dup = len({ev["commit_tx"] for ev in evs}) != len(evs)
    if dup or set(have) != want or len(have) != len(want):
        print(f"FAIL bundle set: {len(have)} bundles vs {len(want)} runs in corpus/results.json"
              + (" · duplicate commit_tx" if dup else "")
              + "".join(f" · missing {x}" for x in sorted(want - set(have))) + "".join(f" · extra {x}" for x in sorted(set(have) - want)))
        return 1
    online = reachable(a.rpc)
    n_pass = n_chain = n_rec = n_paid = n_unb = 0
    any_fail = False
    for bounty in sorted({json.load(open(b))["bounty"] for b in bundles}):
        line_s, ok = bounty_integrity(bounty, online, a.rpc, a.require_keyless)
        if ok is None:  # RPC error: unchecked, never a pass — under --require-keyless it forces exit 2
            print("RPC-ERROR " + line_s)
            n_unb += a.require_keyless
            continue
        print(("INFO " if ok else "FAIL ") + line_s)
        any_fail |= not ok
    if online:
        # Completeness against the chain, not just against corpus/results.json: each bundled bounty's commit ids
        # must be exactly 0..view_state.commits-1, so dropping a bundle (and its results.json row) still FAILs.
        for bounty in sorted({ev["bounty"] for ev in evs}):
            ids = sorted(next((int(l.split()[1]) for l in ev["bounty_logs"] if l.startswith("COMMIT ")), -1)
                         for ev in evs if ev["bounty"] == bounty)
            try:
                n = int(live_state(bounty, a.rpc)["commits"])
            except (OSError, KeyError, ValueError) as e:
                print(f"RPC-ERROR bounty {bounty}: commit count not re-checked ({e})")
                n_unb += 1
                continue
            ok = ids == list(range(n))
            print(("INFO " if ok else "FAIL ") + f"bounty {bounty}: {n} commits on chain, bundles cover "
                  + (f"all {n}" if ok else f"ids {ids}"))
            any_fail |= not ok
    kinds = {}
    if online:
        try:
            pin_operator(evs, a.rpc)
            pin_keys(evs, a.rpc)
        except OSError as e:
            print(f"RPC-ERROR operator pin: {e} — rows query their own block")
    for b in bundles:
        ev = json.load(open(b))
        row_online = online
        try:
            kind, checks, fails = one(ev, online, a.rpc)
        except OSError as e:  # HTTP 429/5xx or a timeout after near.rpc's retries: not a failed check
            print(f"RPC-ERROR {ev['label']}: {e} — checked from the bundle only")
            row_online = False
            kind, checks, fails = one(ev, False, a.rpc)
        except (KeyError, ValueError) as e:  # a definitive but unusable answer (unknown tx, unexpected shape): FAIL
            kind, checks, fails = "?", [], [f"unexpected chain data ({e})"]
        mark = ("CHAIN-CHECKED" if row_online else "RECORDED") if not fails else "FAIL"
        print(f"{mark} {ev['label']} [{kind}]: " + " · ".join(n for n, _ in checks)
              + ("" if not fails else " · FAILED: " + ",".join(fails)))
        ok = not fails
        n_pass += ok
        n_chain += ok and row_online
        n_rec += ok and not row_online
        n_paid += ok and kind == "PAID"
        any_fail |= not ok
        kinds.setdefault(ev["bounty"], []).append((kind, amount_of(ev)))
    if online:
        # Ledger: the bundle decides which proof it volunteers (a deliver tx, an expire tx); the chain decides what it
        # must prove. The bounty's own totals must equal the bundled lines: paid_total = Σ PAID amounts, escrow = Σ
        # AWARDED/DELIVERED amounts — so a payout hidden by dropping its deliver tx breaks the sum.
        for bounty in sorted(kinds):
            st = _STATE.get(bounty)
            if st is None:
                continue
            paid = sum(amt for k, amt in kinds[bounty] if k == "PAID")
            held = sum(amt for k, amt in kinds[bounty] if k in ("AWARDED", "DELIVERED"))
            ok = int(st["paid_total"]) == paid and int(st["escrow"]) == held
            print(("INFO " if ok else "FAIL ") + f"bounty {bounty}: paid_total {st['paid_total']} / escrow {st['escrow']} "
                  + ("= the bundled PAID / AWARDED lines" if ok else f"!= bundled PAID {paid} / AWARDED {held}"))
            any_fail |= not ok
    print(f"checks: {n_pass} PASS · {n_chain} CHAIN-CHECKED · {n_rec} RECORDED")
    if any_fail:
        return 1
    if n_rec or n_unb:
        print(f"exit 2: {n_rec} RECORDED line(s), {n_unb} bounty keyless check(s) unchecked — the archival RPC was unreachable or rate-limited, not a failed check; "
              "re-run later or pass RPC=<url>")
        return 2
    if n_paid < 1:
        print("exit 1: no Paid payout line")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
