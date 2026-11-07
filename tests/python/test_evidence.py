"""Unit tests for scripts/evidence.py with the NEAR layer (day0/near.py) replaced by fakes."""
import base64
import builtins
import io
import json
import os
import runpy
import sys

import pytest

import evidence
import near

OP = "worker.outlayer.testnet"


def b64(d):
    return base64.b64encode(json.dumps(d).encode()).decode()


def test_operator(monkeypatch):
    monkeypatch.setattr(near, "view", lambda c, m: (None, OP))
    assert evidence.operator() == OP


def test_tx_full_ok_and_error(monkeypatch):
    monkeypatch.setattr(near, "tx", lambda h, s, u: {"result": {"h": h}})
    assert evidence.tx_full("abc", "me") == {"h": "abc"}
    monkeypatch.setattr(near, "tx", lambda h, s, u: {"error": "x" * 500})
    with pytest.raises(RuntimeError) as ei:
        evidence.tx_full("abc", "me")
    assert str(ei.value).startswith("tx abc: ")
    assert len(str(ei.value)) < 400


def test_request_id_variants(monkeypatch):
    evs = [
        {"data": [{"request_data": None}, {"request_data": json.dumps({"other": 1})}]},
        {},
        {"data": [{"request_data": json.dumps({"request_id": "7", "x": 1})}]},
    ]
    monkeypatch.setattr(near, "events", lambda r, n: evs)
    assert evidence.request_id({}) == (7, {"request_id": "7", "x": 1})
    monkeypatch.setattr(near, "events", lambda r, n: [{"data": [{"request_data": {"request_id": 3}}]}])
    assert evidence.request_id({}) == (3, {"request_id": 3})
    monkeypatch.setattr(near, "events", lambda r, n: [])
    assert evidence.request_id({}) == (None, None)


def test_outcome_block():
    txr = {"receipts_outcome": [
        {"block_hash": "b1", "outcome": {"logs": ["nothing"]}},
        {"block_hash": "b2", "outcome": {"logs": ["AWARDED 5"]}},
    ]}
    assert evidence.outcome_block(txr, "AWARDED ") == "b2"
    assert evidence.outcome_block(txr, "REFUSED ") is None


def _chain(monkeypatch, txs_by_height, heights_missing=()):
    def rpc(method, params, url=None):
        if method == "block":
            bid = params["block_id"]
            if bid == "cb":
                return {"result": {"header": {"height": 100}}}
            if bid in heights_missing:
                return {"error": "unknown"}
            return {"result": {"chunks": [{"chunk_hash": f"c{bid}"}]}}
        if method == "chunk":
            h = int(params["chunk_id"][1:])
            if h in txs_by_height:
                return {"result": {"transactions": txs_by_height[h]}}
            return {}
        raise AssertionError(method)
    monkeypatch.setattr(near, "rpc", rpc)


def test_find_resolve_found(monkeypatch):
    good = {"signer_id": OP, "receiver_id": near.OUTLAYER, "hash": "H", "public_key": "ed25519:K",
            "actions": [
                "Transfer",
                {"Other": {}},
                {"FunctionCall": {"method_name": "unrelated", "args": b64({"request_id": 9})}},
                {"FunctionCall": {"method_name": "resolve_execution", "args": b64({"request_id": 1})}},
                {"FunctionCall": {"method_name": "submit_execution_output_and_resolve",
                                  "args": b64({"request_id": 9})}},
            ]}
    wrong_signer = dict(good, signer_id="other")
    wrong_recv = dict(good, receiver_id="other")
    _chain(monkeypatch, {97: [wrong_signer, wrong_recv, good]}, heights_missing=(99,))
    r = evidence.find_resolve(9, "cb", OP)
    assert r == {"tx": "H", "signer": OP, "public_key": "ed25519:K",
                 "method": "submit_execution_output_and_resolve", "args": {"request_id": 9},
                 "block_height": 97}


def test_find_resolve_not_found(monkeypatch):
    _chain(monkeypatch, {})
    assert evidence.find_resolve(9, "cb", OP, back=3) is None


def test_access_key(monkeypatch):
    monkeypatch.setattr(near, "rpc", lambda m, p, u=None: {"result": {"nonce": 1}})
    assert evidence.access_key("a", "pk", 5) == {"nonce": 1}
    monkeypatch.setattr(near, "rpc", lambda m, p, u=None: {"error": {"cause": {"name": "UNKNOWN"}}})
    assert evidence.access_key("a", "pk", 5) == {"error": {"name": "UNKNOWN"}}


def test_verdict_output():
    assert evidence.verdict_output(None) is None
    assert evidence.verdict_output({"args": {"response": {"output": {"Text": "ok"}}}}) == "ok"
    assert evidence.verdict_output({"args": {"response": {"output": {"Json": {"a": 1}}}}}) == {"a": 1}
    assert evidence.verdict_output({"args": {"response": {"output": {"Bytes": [1]}}}}) == [1]
    assert evidence.verdict_output({"args": {"output": "plain"}}) == "plain"
    assert evidence.verdict_output({"args": {}}) is None


def _patch_bundle(monkeypatch, resolve=True, logs_marker="AWARDED "):
    ctx = {"receipts_outcome": [{"block_hash": "cb", "outcome": {"logs": [logs_marker + "x"]}}]}
    dtx = {"marker": "deliver"}
    monkeypatch.setattr(near, "view", lambda c, m: (None, OP) if m == "get_config"
                        else {"verifier_wasm_hash": "HASH"})
    monkeypatch.setattr(evidence, "tx_full", lambda h, s: ctx if h == "ctx" else dtx)
    monkeypatch.setattr(near, "events", lambda r, n: (
        [{"data": [{"request_data": json.dumps({"request_id": 4})}]}] if n == "execution_requested"
        else [{"done": True}]))
    monkeypatch.setattr(near, "request_execution_args", lambda r: {"wasm": "HASH"})
    monkeypatch.setattr(near, "logs", lambda r: [{"executor": "bounty.t", "log": "L1"},
                                                 {"executor": "zzz", "log": "L2"}])
    res = {"tx": "RT", "public_key": "pk", "block_height": 50, "args": {"output": "V"}}
    monkeypatch.setattr(evidence, "find_resolve", lambda rid, cb, op: res if resolve else None)
    monkeypatch.setattr(evidence, "access_key", lambda a, pk, h: {"perm": "FunctionCall"})
    return ctx, dtx, res


def test_bundle_full(monkeypatch):
    ctx, dtx, res = _patch_bundle(monkeypatch)
    ev = evidence.bundle("lbl", "bounty.t", "hunter.t", "ctx", "dtx")
    assert ev["request_id"] == 4 and ev["operator"] == OP
    assert ev["bounty_verifier_hash"] == "HASH"
    assert ev["resolve"] is res and ev["worker_access_key"] == {"perm": "FunctionCall"}
    assert ev["verdict_output"] == "V"
    assert ev["bounty_logs"] == ["L1"]
    assert ev["execution_completed"] == [{"done": True}]
    assert ev["deliver_tx"] == "dtx" and ev["deliver_logs"] == ["L1"] and ev["deliver_tx_status"] == dtx
    assert ev["commit_tx_status"] is ctx


def test_bundle_no_resolve_no_deliver(monkeypatch):
    _patch_bundle(monkeypatch, resolve=False, logs_marker="REFUSED ")
    ev = evidence.bundle("lbl", "bounty.t", "hunter.t", "ctx")
    assert ev["resolve"] is None and ev["worker_access_key"] is None and ev["verdict_output"] is None
    assert "deliver_tx" not in ev


def test_bundle_no_callback_block(monkeypatch):
    _patch_bundle(monkeypatch, logs_marker="nope ")
    ev = evidence.bundle("lbl", "bounty.t", "hunter.t", "ctx")
    assert ev["resolve"] is None


def _run_main(monkeypatch, argv, tmp_path):
    _patch_bundle(monkeypatch)
    monkeypatch.setattr(near, "tx", lambda h, s, u=None: {"result": {"receipts_outcome": [
        {"block_hash": "cb", "outcome": {"logs": ["AWARDED x"]}}]}})
    monkeypatch.setattr(near, "rpc", lambda m, p, u=None: {"result": {"header": {"height": 10}, "chunks": []}})
    made, files = [], {}
    monkeypatch.setattr(os, "makedirs", lambda p, exist_ok=False: made.append((p, exist_ok)))

    class Buf(io.StringIO):
        def close(self):
            pass

    real_open = builtins.open

    def fake_open(path, mode="r", *a, **k):
        if "w" in mode:
            files[str(path)] = Buf()
            return files[str(path)]
        return real_open(path, mode, *a, **k)
    monkeypatch.setattr(builtins, "open", fake_open)
    monkeypatch.setattr(sys, "argv", ["evidence.py"] + argv)
    runpy.run_path(evidence.__file__, run_name="__main__")
    return made, files


def test_main_with_deliver(monkeypatch, tmp_path, capsys):
    made, files = _run_main(monkeypatch, ["lbl", "bounty.t", "hunter.t", "ctx", "dtx"], tmp_path)
    assert made and made[0][0].endswith(os.path.join("corpus", "evidence")) and made[0][1] is True
    (path, buf), = files.items()
    assert path.endswith(os.path.join("corpus", "evidence", "lbl.json"))
    assert json.loads(buf.getvalue())["deliver_tx"] == "dtx"
    out = json.loads(capsys.readouterr().out)
    assert out == {"label": "lbl", "request_id": 4, "resolve": None}


def test_main_without_deliver(monkeypatch, tmp_path, capsys):
    _, files = _run_main(monkeypatch, ["lbl", "bounty.t", "hunter.t", "ctx"], tmp_path)
    (buf,) = files.values()
    assert "deliver_tx" not in json.loads(buf.getvalue())
