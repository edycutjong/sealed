"""Unit tests for scripts/verify.py: a fake chain (near.rpc / near.tx / near.view) and synthetic evidence bundles under tmp_path."""
import base64
import glob
import hashlib
import json
import os
import runpy
import sys

import pytest

import near
import verify

BOUNTY = "corpus.sealed.testnet"
PARENT = "sealed.testnet"
OUTLAYER = "outlayer.testnet"
OPERATOR = "op.testnet"
PIN = "H" * 8
SCRIPT = os.path.join(os.path.dirname(verify.__file__), "verify.py")


def b64j(o):
    return base64.b64encode(json.dumps(o).encode()).decode()


def fc(method, args):
    return {"FunctionCall": {"method_name": method, "args": b64j(args)}}


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Chain:
    """Canned answers for near.rpc / near.tx / near.view."""

    def __init__(self):
        self.txs = {}
        self.state = {"outlayer": OUTLAYER, "verifier_wasm_hash": PIN, "commits": 0, "paid_total": "0", "escrow": "0"}
        self.config = [PARENT, OPERATOR]
        self.access = {"result": {"permission": {"FunctionCall": {
            "receiver_id": OUTLAYER, "method_names": [], "allowance": "5"}}}}
        self.keys = {"result": {"keys": []}}
        self.account = {"result": {}}
        self.create = {"result": {}}
        self.status = {"result": {}}
        self.rpc_error = None
        self.state_error = None
        self.config_error = None
        self.tx_error = None
        self.calls = []

    def rpc(self, method, params, url=None):
        self.calls.append((method, params))
        if self.rpc_error and method != "status":
            raise self.rpc_error
        if method == "status":
            return self.status
        if method == "EXPERIMENTAL_tx_status":
            return self.create
        rt = params["request_type"]
        return {"view_access_key": self.access, "view_access_key_list": self.keys, "view_account": self.account}[rt]

    def tx(self, h, sender, url=None):
        if self.tx_error:
            raise self.tx_error
        return {"result": self.txs[h]}

    def view(self, account, method, args=None, url=None, block_id=None):
        if method == "view_state":
            if self.state_error:
                raise self.state_error
            return self.state
        if self.config_error:
            raise self.config_error
        return self.config


@pytest.fixture
def chain(monkeypatch):
    c = Chain()
    monkeypatch.setattr(near, "rpc", c.rpc)
    monkeypatch.setattr(near, "tx", c.tx)
    monkeypatch.setattr(near, "view", c.view)
    for n in ("_STATE", "_OPERATOR", "_OP_FIXED", "_KEY_FIXED"):
        monkeypatch.setattr(verify, n, {})
    return c


def commit_tx(bounty_logs, req_id, input_data="IN"):
    req = {"source": {"WasmUrl": {"hash": PIN}}, "input_data": input_data}
    event = "EVENT_JSON:" + json.dumps({"event": "execution_requested",
                                        "data": [{"request_data": json.dumps({"request_id": req_id})}]})
    return {
        "transaction": {"actions": []},
        "receipts_outcome": [
            {"id": "r0", "outcome": {"executor_id": OUTLAYER, "logs": [event]}},
            {"id": "r1", "outcome": {"executor_id": BOUNTY, "logs": list(bounty_logs)}},
        ],
        "receipts": [{"receiver_id": OUTLAYER, "receipt": {"Action": {"actions": [fc("request_execution", req)]}}}],
    }, req


def build(chain, label, cid, req_id, block, kind):
    """Register a synthetic commit on `chain`; return its evidence bundle. kind: paid|refused|awarded|delivered|voided."""
    enc = b"enc-" + label.encode()
    h_enc = sha(enc)
    broken = kind != "refused"
    out = {"broken": broken, "h_enc": h_enc}
    blog = [f"COMMIT {cid} x"]
    blog.append(f"AWARDED {cid} amount 100 h_enc {h_enc}" if broken else f"REFUSED {cid} nope")
    dlog = {"paid": [f"PAID {cid} 100"], "delivered": [f"DELIVERED {cid}"]}.get(kind, [])
    ctx, req = commit_tx(blog, req_id)
    dargs = {"enc": base64.b64encode(enc).decode(), "commit_id": cid}
    dtx = None
    if kind in ("paid", "delivered"):
        dtx = {"transaction": {"actions": [fc("deliver", dargs)]},
               "receipts_outcome": [{"id": "d", "outcome": {"executor_id": BOUNTY, "logs": dlog}}]}
    rargs = {"request_id": req_id, "response": {"output": {"Text": json.dumps(out)}}}
    rtx = {"transaction": {"actions": [fc("resolve_execution", rargs)], "signer_id": OPERATOR,
                           "public_key": "ed25519:K", "receiver_id": OUTLAYER},
           "transaction_outcome": {"block_hash": f"bh{block}"}}
    chain.txs.update({f"C-{label}": ctx, f"R-{label}": rtx, f"D-{label}": dtx, f"E-{label}": {
        "transaction": {"actions": []},
        "receipts_outcome": [{"id": "e", "outcome": {"executor_id": BOUNTY, "logs": [f"EXPIRED {cid}; slashed"]}}]}})
    resolve = {"tx": f"R-{label}", "method": "resolve_execution", "block_height": block, "args": rargs,
               "signer": OPERATOR, "receiver": OUTLAYER, "public_key": "ed25519:K"}
    ev = {"label": label, "bounty": BOUNTY, "hunter": "hunter.testnet", "operator": OPERATOR,
          "commit_tx": f"C-{label}", "request_id": req_id, "resolve": resolve,
          "deliver_tx": f"D-{label}" if dtx else None, "bounty_logs": blog, "deliver_logs": dlog,
          "request_execution_args": req, "verdict_output": json.dumps(out), "deliver_tx_status": dtx,
          "commit_tx_status": ctx, "outlayer": OUTLAYER, "bounty_verifier_hash": PIN,
          "worker_access_key": chain.access["result"]}
    if kind == "voided":
        ev.update(expire_tx=f"E-{label}", expire_signer="x.testnet", expire_logs=[f"EXPIRED {cid}; slashed"])
    return ev


# ---------------------------------------------------------------- small helpers

def test_sha():
    assert verify.sha(b"abc") == hashlib.sha256(b"abc").hexdigest()


def test_reachable(chain):
    assert verify.reachable("u") is True
    chain.status = {"error": {}}
    assert verify.reachable("u") is False
    chain.rpc_error = None
    near_rpc = near.rpc

    def boom(*a, **k):
        raise OSError("down")
    near.rpc = boom
    try:
        assert verify.reachable("u") is False
    finally:
        near.rpc = near_rpc


def test_tx_args():
    txr = {"transaction": {"actions": ["CreateAccount", fc("other", {"a": 1}), fc("deliver", {"enc": "x"})]}}
    assert verify.tx_args(txr, "deliver") == {"enc": "x"}
    assert verify.tx_args(txr, "missing") is None
    assert verify.tx_args({}, "deliver") is None


def test_logs_filters_by_executor():
    txr = {"receipts_outcome": [{"outcome": {"executor_id": "a", "logs": ["1"]}},
                                {"outcome": {"executor_id": "b", "logs": ["2", "3"]}}]}
    assert verify.logs(txr) == ["1", "2", "3"]
    assert verify.logs(txr, "b") == ["2", "3"]
    assert verify.logs({}) == []


@pytest.mark.parametrize("res,expected", [
    (None, None),
    ({}, None),
    ({"args": {}}, None),
    ({"args": {"response": {"output": {"Text": '{"broken": true}'}}}}, {"broken": True}),
    ({"args": {"output": {"Json": {"broken": False}}}}, {"broken": False}),
    ({"args": {"output": {"Bytes": '{"x": 1}'}}}, {"x": 1}),
    ({"args": {"output": '{"y": 2}'}}, {"y": 2}),
    ({"args": {"output": {"Other": 1}}}, None),
])
def test_verdict_output(res, expected):
    assert verify.verdict_output(res) == expected


def test_req_id_of():
    def ctx(rd):
        ev = "EVENT_JSON:" + json.dumps({"event": "execution_requested", "data": [{"request_data": rd}, {}]})
        return {"receipts_outcome": [{"id": "x", "outcome": {"executor_id": "o", "logs": ["plain", ev]}}]}
    assert verify.req_id_of(ctx(json.dumps({"request_id": "9"}))) == 9
    assert verify.req_id_of(ctx({"request_id": 4})) == 4
    assert verify.req_id_of(ctx({"nope": 1})) is None
    assert verify.req_id_of({}) is None


def test_amount_of():
    assert verify.amount_of({"bounty_logs": ["COMMIT 1", "AWARDED 1 amount 250 h_enc z"]}) == 250
    assert verify.amount_of({"bounty_logs": ["AWARDED 1"]}) == 0
    assert verify.amount_of({"bounty_logs": ["REFUSED 1"]}) == 0


# ---------------------------------------------------------------- live chain state

def test_live_state_caches_and_wraps_errors(chain):
    chain.state_error = RuntimeError("no result")
    with pytest.raises(ConnectionError, match="view_state"):
        verify.live_state(BOUNTY, "u")
    chain.state_error = None
    chain.state["commits"] = 2
    first = verify.live_state(BOUNTY, "u")
    chain.state["commits"] = 99
    assert verify.live_state(BOUNTY, "u") is first and first["commits"] == 99  # same object, cached


def test_live_operator_shapes_and_cache(chain):
    assert verify.live_operator(OUTLAYER, "b1", "u") == OPERATOR
    chain.config = ["x"]  # cached for (outlayer, b1): not re-read
    assert verify.live_operator(OUTLAYER, "b1", "u") == OPERATOR
    chain.config = {"owner": "o", "operator_id": "dict-op"}
    assert verify.live_operator(OUTLAYER, "b2", "u") == "dict-op"
    chain.config = {"owner": "o"}
    with pytest.raises(ValueError, match="unrecognised shape"):
        verify.live_operator(OUTLAYER, "b3", "u")
    chain.config = "weird"
    with pytest.raises(ValueError):
        verify.live_operator(OUTLAYER, "b4", "u")
    chain.config_error = RuntimeError("boom")
    with pytest.raises(ConnectionError, match="get_config"):
        verify.live_operator(OUTLAYER, "b5", "u")
    verify._OP_FIXED[OUTLAYER] = "pinned"
    assert verify.live_operator(OUTLAYER, "b6", "u") == "pinned"


def test_access_key(chain):
    assert verify.access_key("a", "pk", 5, "u") == chain.access["result"]
    assert ("query", {"request_type": "view_access_key", "block_id": 5, "account_id": "a", "public_key": "pk"}) in chain.calls
    chain.access = {"error": {"cause": {"name": "UNKNOWN_ACCESS_KEY"}}}
    assert verify.access_key("a", "pk", 5, "u") is None
    chain.access = {"error": {"cause": {"name": "NOT_SYNCED"}}}
    with pytest.raises(ConnectionError, match="view_access_key"):
        verify.access_key("a", "pk", 5, "u")
    chain.access = {"unexpected": 1}
    with pytest.raises(ConnectionError):
        verify.access_key("a", "pk", 5, "u")


def test_pin_keys_pins_same_scope_ignoring_allowance(chain, monkeypatch):
    evs = [{"resolve": {"signer": "s", "public_key": "k", "block_height": h}} for h in (10, 20)] + [{"resolve": None}, {}]
    answers = iter([
        {"result": {"permission": {"FunctionCall": {"receiver_id": "o", "method_names": [], "allowance": "9"}}}},
        {"result": {"permission": {"FunctionCall": {"receiver_id": "o", "method_names": [], "allowance": "1"}}}},
    ])
    chain.rpc = lambda m, p, u=None: next(answers)
    monkeypatch.setattr(near, "rpc", chain.rpc)
    verify.pin_keys(evs, "u")
    assert verify._KEY_FIXED == {("s", "k"): {"permission": {"FunctionCall": {"receiver_id": "o", "method_names": []}}}}


def test_pin_keys_does_not_pin_changed_or_missing_scope(chain, monkeypatch):
    evs = [{"resolve": {"signer": "s", "public_key": "k", "block_height": h}} for h in (10, 20)]
    answers = iter([
        {"result": {"permission": {"FunctionCall": {"receiver_id": "o", "method_names": []}}}},
        {"result": {"permission": {"FunctionCall": {"receiver_id": "o", "method_names": ["x"]}}}},
    ])
    monkeypatch.setattr(near, "rpc", lambda m, p, u=None: next(answers))
    verify.pin_keys(evs, "u")
    assert verify._KEY_FIXED == {}
    unknown = {"error": {"cause": {"name": "UNKNOWN_ACCESS_KEY"}}}
    monkeypatch.setattr(near, "rpc", lambda m, p, u=None: unknown)
    verify.pin_keys(evs, "u")
    assert verify._KEY_FIXED == {}


def test_pin_operator(chain):
    chain.state["outlayer"] = OUTLAYER
    verify.pin_operator([{"bounty": BOUNTY, "resolve": {"block_height": 5}},
                         {"bounty": BOUNTY, "resolve": {"block_height": 9}},
                         {"bounty": BOUNTY, "resolve": None}], "u")
    assert verify._OP_FIXED == {OUTLAYER: OPERATOR}


def test_pin_operator_rotation_not_pinned(chain, monkeypatch):
    answers = iter(["op-a", "op-b"])
    chain.view = lambda account, method, args=None, url=None, block_id=None: (
        chain.state if method == "view_state" else [PARENT, next(answers)])
    monkeypatch.setattr(near, "view", chain.view)
    verify.pin_operator([{"bounty": BOUNTY, "resolve": {"block_height": 5}},
                         {"bounty": BOUNTY, "resolve": {"block_height": 9}}], "u")
    assert verify._OP_FIXED == {}


# ---------------------------------------------------------------- one()

@pytest.mark.parametrize("online", [True, False])
def test_one_paid_passes(chain, online):
    ev = build(chain, "p", 3, 5, 10, "paid")
    chain.state["commits"] = 4
    kind, checks, fails = verify.one(ev, online, "u")
    assert kind == "PAID" and fails == []
    names = [n for n, _ in checks]
    assert names == (["pinned", "worker", "bundle", "verdict", "h_enc", "paid"] if online
                     else ["pinned", "worker", "verdict", "h_enc", "paid"])


def test_one_uses_pinned_key_scope(chain):
    ev = build(chain, "p", 3, 5, 10, "paid")
    chain.access = {"error": {"cause": {"name": "UNKNOWN_ACCESS_KEY"}}}  # would FAIL if queried
    verify._KEY_FIXED[(OPERATOR, "ed25519:K")] = {"permission": {"FunctionCall": {
        "receiver_id": OUTLAYER, "method_names": ["resolve_execution"]}}}
    assert verify.one(ev, True, "u")[2] == []


def test_one_refused_delivered_awarded(chain):
    ref = build(chain, "r", 1, 6, 11, "refused")
    kind, _, fails = verify.one(ref, True, "u")
    assert (kind, fails) == ("REFUSED", [])
    dl = build(chain, "d", 2, 7, 12, "delivered")
    kind, checks, fails = verify.one(dl, False, "u")
    assert (kind, fails) == ("DELIVERED", [])
    aw = build(chain, "a", 2, 8, 13, "awarded")
    kind, _, fails = verify.one(aw, True, "u")
    assert (kind, fails) == ("AWARDED", [])


@pytest.mark.parametrize("online", [True, False])
def test_one_voided(chain, online):
    ev = build(chain, "v", 2, 9, 14, "voided")
    kind, checks, fails = verify.one(ev, online, "u")
    assert kind == "VOIDED" and fails == []
    assert ("expired", True) in checks


def test_one_voided_expire_log_mismatch_fails(chain):
    ev = build(chain, "v", 2, 9, 14, "voided")
    ev["expire_logs"] = ["EXPIRED 99; slashed"]
    assert verify.one(ev, False, "u")[2] == ["expired"]
    ev2 = build(chain, "v2", 2, 9, 14, "voided")
    ev2["bounty_logs"] = ["AWARDED 2 amount 1"]  # no COMMIT line -> cid None
    assert "expired" in verify.one(ev2, False, "u")[2]


def test_one_no_resolve_fails_worker_and_verdict(chain):
    ev = build(chain, "n", 3, 5, 10, "refused")
    ev["resolve"] = None
    ev["verdict_output"] = None
    ev["worker_access_key"] = None
    kind, checks, fails = verify.one(ev, False, "u")
    assert kind == "REFUSED" and fails == ["worker", "verdict"]
    chain.txs["C-n"], _ = commit_tx(ev["bounty_logs"], 5)
    ev_on = dict(ev, request_execution_args=ev["request_execution_args"])
    assert verify.one(ev_on, True, "u")[2] == ["worker", "verdict"]


def test_one_wrong_request_id_wrong_operator_bad_key(chain):
    ev = build(chain, "w", 3, 5, 10, "paid")
    ev["request_id"] = 77
    assert "worker" in verify.one(ev, False, "u")[2]
    ev = build(chain, "w", 3, 5, 10, "paid")
    ev["operator"] = "evil.testnet"
    assert "worker" in verify.one(ev, False, "u")[2]
    for perm in ({"FunctionCall": {"receiver_id": "other", "method_names": []}},
                 {"FunctionCall": {"receiver_id": OUTLAYER, "method_names": ["something"]}},
                 {"FunctionCall": {"receiver_id": OUTLAYER}}):
        ev = build(chain, "w", 3, 5, 10, "paid")
        ev["worker_access_key"] = {"permission": perm}
        assert "worker" in verify.one(ev, False, "u")[2]
    ev = build(chain, "w", 3, 5, 10, "paid")
    ev["worker_access_key"] = {"permission": {"FunctionCall": {"receiver_id": OUTLAYER,
                                                                "method_names": ["submit_execution_output_and_resolve"]}}}
    assert verify.one(ev, False, "u")[2] == []


def test_one_pin_and_h_enc_and_paid_failures(chain):
    ev = build(chain, "f", 3, 5, 10, "paid")
    ev["bounty_verifier_hash"] = "other"
    assert verify.one(ev, False, "u")[2] == ["pinned"]
    ev = build(chain, "f", 3, 5, 10, "paid")
    ev["request_execution_args"] = {}
    assert verify.one(ev, False, "u")[2] == ["pinned"]
    ev = build(chain, "f", 3, 5, 10, "paid")
    ev["verdict_output"] = json.dumps({"broken": True, "h_enc": "bad"})
    assert verify.one(ev, False, "u")[2] == ["h_enc"]
    ev = build(chain, "f", 3, 5, 10, "paid")
    ev["deliver_logs"] = ["PAID 4 100"]
    assert verify.one(ev, False, "u")[2] == ["paid"]
    ev = build(chain, "f", 3, 5, 10, "paid")
    ev["deliver_logs"] = ["PAID 3"]
    assert verify.one(ev, False, "u")[2] == ["paid"]
    ev = build(chain, "f", 3, 5, 10, "paid")
    ev["bounty_logs"] = ["AWARDED 3"]  # no COMMIT, no amount, no h_enc
    assert set(verify.one(ev, False, "u")[2]) == {"h_enc", "paid"}


def test_one_online_bundle_mismatch(chain):
    ev = build(chain, "b", 3, 5, 10, "paid")
    ev["bounty_logs"] = ev["bounty_logs"] + ["extra"]
    assert verify.one(ev, True, "u")[2] == ["bundle"]
    ev = build(chain, "b", 3, 5, 10, "paid")
    ev["verdict_output"] = {"broken": False, "h_enc": "x"}  # dict form, differs from the chain
    assert verify.one(ev, True, "u")[2] == ["bundle"]


def test_one_offline_verdict_output_dict_and_missing_deliver_fields(chain):
    ev = build(chain, "o", 1, 6, 11, "refused")
    ev["verdict_output"] = {"broken": False}
    ev["deliver_logs"] = None
    ev["deliver_tx_status"] = None
    assert verify.one(ev, False, "u")[0] == "REFUSED"
    ev.pop("deliver_logs"), ev.pop("verdict_output"), ev.pop("worker_access_key")
    assert set(verify.one(ev, False, "u")[2]) == {"worker", "verdict"}


def test_one_verdict_disagrees(chain):
    ev = build(chain, "x", 1, 6, 11, "refused")
    ev["verdict_output"] = json.dumps({"broken": True})
    assert verify.one(ev, False, "u")[2] == ["verdict"]


# ---------------------------------------------------------------- bounty integrity

@pytest.fixture
def tree(tmp_path, monkeypatch):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "bounty.wasm").write_bytes(b"\0asm-test-wasm")
    (tmp_path / "corpus" / "evidence").mkdir(parents=True)
    monkeypatch.setattr(verify, "ROOT", str(tmp_path))
    return tmp_path


def write_results(tree, runs, create_tx="CREATE1"):
    (tree / "corpus" / "results.json").write_text(json.dumps({
        "bounties": {BOUNTY: {"create_tx": create_tx}}, "runs": runs}))


def b58(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return out


def test_committed_code_hash(tree):
    want = b58(hashlib.sha256(b"\0asm-test-wasm").digest())
    assert verify.committed_code_hash() == want


def test_committed_code_hash_leading_zero_bytes(tree, monkeypatch):
    class FakeDigest:
        def digest(self):
            return b"\0\0\x01\x02"

    class FakeHashlib:
        @staticmethod
        def sha256(_b):
            return FakeDigest()
    monkeypatch.setattr(verify, "hashlib", FakeHashlib)
    assert verify.committed_code_hash() == "11" + b58(b"\x01\x02")


def birth_tx(want, **over):
    t = {"signer_id": PARENT, "receiver_id": BOUNTY, "actions": [
        "CreateAccount", {"Transfer": {"deposit": "1"}}, {"UseGlobalContract": {"code_hash": want}},
        fc("new", {})]}
    t.update(over)
    return {"result": {"transaction": t, "status": {"SuccessValue": ""}}}


def test_born_keyless_ok(tree, chain):
    write_results(tree, [])
    want = verify.committed_code_hash()
    chain.create = birth_tx(want)
    born, msg = verify.born_keyless(BOUNTY, want, "u")
    assert born is True and msg.startswith("born keyless: create tx CREATE1")
    assert "CreateAccount · Transfer · UseGlobalContract · FunctionCall" in msg and "no AddKey" in msg
    assert chain.calls[-1][1]["sender_account_id"] == PARENT


def test_born_keyless_rejects_keyed_or_wrong_birth(tree, chain):
    write_results(tree, [])
    want = verify.committed_code_hash()
    chain.create = birth_tx(want, actions=["CreateAccount", {"AddKey": {}}, {"UseGlobalContract": {"code_hash": want}},
                                           fc("new", {})])
    born, msg = verify.born_keyless(BOUNTY, want, "u")
    assert born is False and "is not a keyless global-code birth" in msg and "AddKey" in msg
    chain.create = birth_tx("wrong")
    assert verify.born_keyless(BOUNTY, want, "u")[0] is False
    chain.create = birth_tx(want, signer_id="someone.testnet")
    assert verify.born_keyless(BOUNTY, want, "u")[0] is False


def test_born_keyless_not_checkable(tree, chain):
    want = "w"
    write_results(tree, [], create_tx=None)
    assert verify.born_keyless(BOUNTY, want, "u") is None
    (tree / "corpus" / "results.json").write_text(json.dumps({"bounties": {}, "runs": []}))
    assert verify.born_keyless(BOUNTY, want, "u") is None
    write_results(tree, [])
    chain.rpc_error = OSError("net")
    assert verify.born_keyless(BOUNTY, want, "u") is None
    chain.rpc_error = None
    chain.create = {"error": {}}
    assert verify.born_keyless(BOUNTY, want, "u") is None


def test_bounty_integrity_offline(chain):
    line, ok = verify.bounty_integrity(BOUNTY, False, "u", True)
    assert ok is True and "not re-checked (offline)" in line


def test_bounty_integrity_rpc_failures(chain):
    chain.rpc_error = OSError("reset")
    line, ok = verify.bounty_integrity(BOUNTY, True, "u", False)
    assert ok is None and "RPC error: reset" in line
    chain.rpc_error = None
    chain.keys = {"error": {"name": "BAD"}}
    chain.account = {"result": {}}
    line, ok = verify.bounty_integrity(BOUNTY, True, "u", False)
    assert ok is None and "BAD" in line
    chain.keys = {"result": {"keys": []}}
    chain.account = {"error": {"name": "ACCT"}}
    line, ok = verify.bounty_integrity(BOUNTY, True, "u", False)
    assert ok is None and "ACCT" in line


def test_bounty_integrity_code_descriptions(tree, chain):
    write_results(tree, [])
    want = verify.committed_code_hash()
    chain.keys = {"result": {"keys": [{"k": 1}]}}
    chain.account = {"result": {"global_contract_hash": want}}
    line, ok = verify.bounty_integrity(BOUNTY, True, "u", False)
    assert ok is True and line == f"bounty {BOUNTY}: 1 key(s), global code = committed contracts/bounty.wasm {want[:8]}…"
    line, ok = verify.bounty_integrity(BOUNTY, True, "u", True)
    assert ok is False and line.endswith("FAIL (--require-keyless)")
    chain.account = {"result": {"global_contract_hash": "OtherHash123"}}
    line, _ = verify.bounty_integrity(BOUNTY, True, "u", False)
    assert "global code OtherHas… ≠ committed contracts/bounty.wasm" in line
    chain.account = {"result": {"global_contract_account_id": "g.testnet"}}
    assert "global code by account id" in verify.bounty_integrity(BOUNTY, True, "u", False)[0]
    chain.account = {"result": {}}
    assert "1 key(s), own code" in verify.bounty_integrity(BOUNTY, True, "u", False)[0]


def test_bounty_integrity_keyless_birth_paths(tree, chain):
    write_results(tree, [])
    want = verify.committed_code_hash()
    chain.account = {"result": {"global_contract_hash": want}}
    chain.create = birth_tx(want)
    line, ok = verify.bounty_integrity(BOUNTY, True, "u", True)
    assert ok is True and "0 key(s), global code = committed" in line and "born keyless" in line
    chain.create = birth_tx("wrong")
    line, ok = verify.bounty_integrity(BOUNTY, True, "u", True)
    assert ok is False and "FAIL (--require-keyless)" in line
    assert verify.bounty_integrity(BOUNTY, True, "u", False)[1] is True
    chain.create = {"error": {}}
    line, ok = verify.bounty_integrity(BOUNTY, True, "u", True)
    assert ok is None and "create tx not re-checked" in line


# ---------------------------------------------------------------- main()

def run_main(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["verify.py", *args])
    code = verify.main()
    return code, capsys.readouterr().out


def write_bundles(tree, evs, runs=None):
    for ev in evs:
        (tree / "corpus" / "evidence" / f"{ev['label']}.json").write_text(json.dumps(ev))
    write_results(tree, runs if runs is not None else [{"label": e["label"], "bounty": e["bounty"]} for e in evs])


def good_chain(chain, tree):
    """Online chain: one paid, one refused, one voided commit (ids 0..2) of one keyless, born-keyless bounty."""
    write_results(tree, [])
    want = verify.committed_code_hash()
    chain.account = {"result": {"global_contract_hash": want}}
    chain.create = birth_tx(want)
    chain.state.update(commits=3, paid_total="100", escrow="0")
    return [build(chain, "a-paid", 0, 5, 10, "paid"), build(chain, "b-refused", 1, 6, 11, "refused"),
            build(chain, "c-voided", 2, 7, 12, "voided")]


def test_main_empty_bundle(tree, chain, monkeypatch, capsys):
    write_results(tree, [])
    code, out = run_main(monkeypatch, capsys)
    assert code == 1 and "empty bundle" in out


def test_main_bundle_set_mismatch(tree, chain, monkeypatch, capsys):
    evs = [build(chain, "one", 0, 5, 10, "paid"), build(chain, "two", 1, 6, 11, "refused")]
    write_bundles(tree, evs, runs=[{"label": "one", "bounty": BOUNTY}, {"label": "ghost", "bounty": BOUNTY}])
    code, out = run_main(monkeypatch, capsys)
    assert code == 1
    assert "FAIL bundle set: 2 bundles vs 2 runs" in out and "missing ghost" in out and "extra two" in out
    # duplicate commit_tx
    evs[1]["commit_tx"] = evs[0]["commit_tx"]
    write_bundles(tree, evs)
    code, out = run_main(monkeypatch, capsys)
    assert code == 1 and "duplicate commit_tx" in out


def test_main_bounty_filter(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    other = build(chain, "z-other", 0, 9, 13, "refused")
    other["bounty"] = "other.sealed.testnet"
    write_bundles(tree, evs + [other], runs=[{"label": e["label"], "bounty": e["bounty"]} for e in evs + [other]])
    code, out = run_main(monkeypatch, capsys, "--bounty", BOUNTY)
    assert code == 0
    assert "z-other" not in out and "a-paid" in out
    code, out = run_main(monkeypatch, capsys, "--bounty", "nobody.testnet")
    assert code == 1 and "empty bundle" not in out and "FAIL bundle set: 0 bundles vs 0 runs" not in out or code == 1


def test_main_all_chain_checked(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    write_bundles(tree, evs)
    code, out = run_main(monkeypatch, capsys, "--require-keyless")
    assert code == 0, out
    assert f"INFO bounty {BOUNTY}: 0 key(s), global code = committed" in out
    assert f"INFO bounty {BOUNTY}: 3 commits on chain, bundles cover all 3" in out
    assert "CHAIN-CHECKED a-paid [PAID]: pinned · worker · bundle · verdict · h_enc · paid" in out
    assert "CHAIN-CHECKED b-refused [REFUSED]" in out and "CHAIN-CHECKED c-voided [VOIDED]" in out
    assert "paid_total 100 / escrow 0 = the bundled PAID / AWARDED lines" in out
    assert "checks: 3 PASS · 3 CHAIN-CHECKED · 0 RECORDED" in out
    assert verify._OP_FIXED == {OUTLAYER: OPERATOR}


def test_main_ledger_mismatch_and_commit_gap(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    write_bundles(tree, evs)
    chain.state.update(commits=4, paid_total="999", escrow="5")
    code, out = run_main(monkeypatch, capsys)
    assert code == 1
    assert "FAIL bounty " + BOUNTY + ": 4 commits on chain, bundles cover ids [0, 1, 2]" in out
    assert "FAIL bounty " + BOUNTY + ": paid_total 999 / escrow 5 != bundled PAID 100 / AWARDED 0" in out


def test_main_row_failure_marks_fail(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    evs[0]["bounty_logs"] = evs[0]["bounty_logs"] + ["tampered"]
    write_bundles(tree, evs)
    code, out = run_main(monkeypatch, capsys)
    assert code == 1
    assert "FAIL a-paid [PAID]: pinned · worker · bundle · verdict · h_enc · paid · FAILED: bundle" in out


def test_main_unexpected_chain_data_fails_row(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    del chain.txs["R-a-paid"]  # unknown tx -> KeyError from the fake
    write_bundles(tree, evs)
    code, out = run_main(monkeypatch, capsys)
    assert code == 1
    assert "FAIL a-paid [?]:  · FAILED: unexpected chain data" in out


def test_main_offline_is_recorded_exit_2(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    write_bundles(tree, evs)
    chain.status = {"error": {}}
    code, out = run_main(monkeypatch, capsys, "--rpc", "http://x")
    assert code == 2
    assert "not re-checked (offline)" in out
    assert "RECORDED a-paid [PAID]" in out
    assert "checks: 3 PASS · 0 CHAIN-CHECKED · 3 RECORDED" in out
    assert "exit 2: 3 RECORDED line(s), 0 bounty keyless check(s) unchecked" in out
    assert "paid_total" not in out  # ledger is online-only


def test_main_row_rpc_error_falls_back_to_bundle(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    write_bundles(tree, evs)
    chain.tx_error = OSError("HTTP 429")
    code, out = run_main(monkeypatch, capsys)
    assert code == 2
    assert "RPC-ERROR a-paid: HTTP 429 — checked from the bundle only" in out
    assert "RECORDED a-paid [PAID]" in out


def test_main_view_state_unavailable(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    write_bundles(tree, evs)
    chain.state_error = RuntimeError("no result")
    code, out = run_main(monkeypatch, capsys)
    assert code == 2
    assert f"RPC-ERROR bounty {BOUNTY}: commit count not re-checked (view_state {BOUNTY}: no result)" in out
    assert "RPC-ERROR operator pin:" in out
    assert "RECORDED a-paid [PAID]" in out
    assert "paid_total" not in out  # no live state -> no ledger line
    assert "3 RECORDED line(s), 1 bounty keyless check(s) unchecked" in out


def test_main_bounty_integrity_rpc_error(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    write_bundles(tree, evs)
    chain.keys = {"error": {"name": "X"}}
    code, out = run_main(monkeypatch, capsys, "--require-keyless")
    assert code == 2
    assert "RPC-ERROR bounty " + BOUNTY + ": keys/code not re-checked" in out
    assert "1 bounty keyless check(s) unchecked" in out
    # without --require-keyless the unchecked integrity line does not force exit 2
    code, out = run_main(monkeypatch, capsys)
    assert code == 0 and "RPC-ERROR bounty" in out


def test_main_require_keyless_fails_keyed_bounty(tree, chain, monkeypatch, capsys):
    evs = good_chain(chain, tree)
    write_bundles(tree, evs)
    chain.keys = {"result": {"keys": [{"public_key": "k"}]}}
    code, out = run_main(monkeypatch, capsys, "--require-keyless")
    assert code == 1 and "FAIL bounty " + BOUNTY + ": 1 key(s)" in out and "FAIL (--require-keyless)" in out
    code, out = run_main(monkeypatch, capsys)
    assert code == 0 and "INFO bounty " + BOUNTY + ": 1 key(s)" in out


def test_main_no_paid_line_exits_1(tree, chain, monkeypatch, capsys):
    good_chain(chain, tree)
    evs = [build(chain, "only-refused", 0, 5, 10, "refused")]
    write_bundles(tree, evs)
    chain.state.update(commits=1, paid_total="0", escrow="0")
    code, out = run_main(monkeypatch, capsys)
    assert code == 1 and "exit 1: no Paid payout line" in out


def test_module_main_guard(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["verify.py"])
    monkeypatch.setattr(glob, "glob", lambda *_a, **_k: [])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(SCRIPT, run_name="__main__")
    assert e.value.code == 1
    assert "empty bundle" in capsys.readouterr().out
