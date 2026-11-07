"""Unit tests for day0/near.py: RPC retry logic, view decoding, call parsing, tx/log/event helpers."""
import base64
import io
import json
import subprocess

import pytest

import near

HASH = "A" * 44


class FakeResp(io.BytesIO):
    pass


def _resp(obj):
    return FakeResp(json.dumps(obj).encode())


@pytest.fixture(autouse=True)
def _default_pace(monkeypatch):
    """scripts/verify.py sets near.PACE_S = 0.35 at import time; start every test here from the module default."""
    monkeypatch.setattr(near, "PACE_S", 0.0)


@pytest.fixture
def sleeps(monkeypatch):
    calls = []
    monkeypatch.setattr(near.time, "sleep", lambda s: calls.append(s))
    return calls


def test_rpc_success_and_request_shape(monkeypatch, sleeps):
    seen = {}

    def fake_open(req, timeout):
        seen["body"] = json.loads(req.data)
        seen["url"] = req.full_url
        seen["timeout"] = timeout
        return _resp({"result": 1})

    monkeypatch.setattr(near.urllib.request, "urlopen", fake_open)
    assert near.rpc("status", [], "http://x") == {"result": 1}
    assert seen["body"]["method"] == "status"
    assert seen["url"] == "http://x"
    assert seen["timeout"] == 60
    assert sleeps == []


def test_rpc_pace_sleeps(monkeypatch, sleeps):
    monkeypatch.setattr(near, "PACE_S", 0.5)
    monkeypatch.setattr(near.urllib.request, "urlopen", lambda r, timeout: _resp({"result": 1}))
    near.rpc("m", {})
    assert sleeps == [0.5]


def test_rpc_timeout_error_retries(monkeypatch, sleeps):
    answers = [{"error": {"cause": "timeout"}}, {"result": "ok"}]
    monkeypatch.setattr(near.urllib.request, "urlopen", lambda r, timeout: _resp(answers.pop(0)))
    assert near.rpc("m", {}) == {"result": "ok"}
    assert sleeps == [2]


def test_rpc_timeout_error_on_last_attempt_returned(monkeypatch, sleeps):
    err = {"error": "TIMEOUT"}
    monkeypatch.setattr(near.urllib.request, "urlopen", lambda r, timeout: _resp(err))
    assert near.rpc("m", {}) == err
    assert sleeps == [2] * 7


def test_rpc_non_timeout_error_returned(monkeypatch, sleeps):
    err = {"error": {"name": "HANDLER"}}
    monkeypatch.setattr(near.urllib.request, "urlopen", lambda r, timeout: _resp(err))
    assert near.rpc("m", {}) == err
    assert sleeps == []


def test_rpc_exception_backoff_then_success(monkeypatch, sleeps):
    class E429(Exception):
        code = 429

    seq = [E429(), E429(), RuntimeError("boom")]

    def fake_open(req, timeout):
        if seq:
            raise seq.pop(0)
        return _resp({"result": 2})

    monkeypatch.setattr(near.urllib.request, "urlopen", fake_open)
    assert near.rpc("m", {}) == {"result": 2}
    assert sleeps == [1, 2, 2]


def test_rpc_429_backoff_capped(monkeypatch, sleeps):
    class E429(Exception):
        code = 429

    n = {"i": 0}

    def fake_open(req, timeout):
        n["i"] += 1
        raise E429("rate")

    monkeypatch.setattr(near.urllib.request, "urlopen", fake_open)
    with pytest.raises(E429):
        near.rpc("m", {})
    assert n["i"] == 8
    assert sleeps == [1, 2, 4, 8, 16, 30, 30]


def test_view_decodes_result_and_encodes_args(monkeypatch):
    captured = {}

    def fake_rpc(method, params, url):
        captured.update(method=method, params=params, url=url)
        return {"result": {"result": list(json.dumps({"a": 1}).encode())}}

    monkeypatch.setattr(near, "rpc", fake_rpc)
    assert near.view("acc.testnet", "get", {"k": "v"}) == {"a": 1}
    p = captured["params"]
    assert captured["method"] == "query"
    assert p["finality"] == "final" and "block_id" not in p
    assert json.loads(base64.b64decode(p["args_base64"])) == {"k": "v"}
    assert p["account_id"] == "acc.testnet" and p["method_name"] == "get"
    assert captured["url"] == near.RPC


def test_view_block_id_and_default_args(monkeypatch):
    captured = {}

    def fake_rpc(method, params, url):
        captured.update(params=params, url=url)
        return {"result": {"result": list(b"[]")}}

    monkeypatch.setattr(near, "rpc", fake_rpc)
    assert near.view("a", "m", block_id=123, url="http://arch") == []
    assert captured["params"]["block_id"] == 123
    assert "finality" not in captured["params"]
    assert json.loads(base64.b64decode(captured["params"]["args_base64"])) == {}
    assert captured["url"] == "http://arch"


@pytest.mark.parametrize("resp", [{"error": "x"}, {"result": {"logs": []}}])
def test_view_raises_on_bad_response(monkeypatch, resp):
    monkeypatch.setattr(near, "rpc", lambda *a, **k: resp)
    with pytest.raises(RuntimeError, match="view acc.meth"):
        near.view("acc", "meth")


def test_keyfile():
    assert near.keyfile("bob.testnet") == near.os.path.join(near.KEYS, "bob.testnet.json")


def test_call_returns_tx_hash(monkeypatch):
    seen = {}

    def fake_run(cmd, capture_output, text):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr=f"Transaction ID: {HASH}\n")

    monkeypatch.setattr(near.subprocess, "run", fake_run)
    assert near.call("s.testnet", "r.testnet", "m", {"x": 1}, deposit="1 NEAR") == HASH
    cmd = seen["cmd"]
    assert cmd[0] == "near" and "r.testnet" in cmd and "m" in cmd
    assert cmd[cmd.index("json-args") + 1] == '{"x": 1}'
    assert cmd[cmd.index("attached-deposit") + 1] == "1 NEAR"
    assert cmd[cmd.index("prepaid-gas") + 1] == "300 Tgas"
    assert cmd[cmd.index("sign-with-access-key-file") + 1] == near.keyfile("s.testnet")


def test_call_failure_raises_with_tail(monkeypatch):
    monkeypatch.setattr(near.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 1, stdout="", stderr="bad key"))
    with pytest.raises(RuntimeError, match="call r.m failed:\nbad key"):
        near.call("s", "r", "m", {})


def test_tx_passes_params(monkeypatch):
    seen = {}

    def fake_rpc(method, params, url):
        seen.update(method=method, params=params, url=url)
        return {"result": {}}

    monkeypatch.setattr(near, "rpc", fake_rpc)
    near.tx("h", "me", "http://u")
    assert seen == {"method": "EXPERIMENTAL_tx_status",
                    "params": {"tx_hash": "h", "sender_account_id": "me", "wait_until": "FINAL"},
                    "url": "http://u"}


def _txr(*logs_per_receipt):
    return {"result": {"receipts_outcome": [
        {"id": f"r{i}", "outcome": {"executor_id": f"ex{i}", "logs": ls}}
        for i, ls in enumerate(logs_per_receipt)]}}


def test_logs_flattens_and_handles_empty():
    assert near.logs({}) == []
    assert near.logs(_txr(["a", "b"], [], ["c"])) == [
        {"receipt": "r0", "executor": "ex0", "log": "a"},
        {"receipt": "r0", "executor": "ex0", "log": "b"},
        {"receipt": "r2", "executor": "ex2", "log": "c"}]


def test_events_filters_by_name():
    e1 = {"event": "a", "n": 1}
    e2 = {"event": "b", "n": 2}
    txr = _txr(["plain", "EVENT_JSON:" + json.dumps(e1)], ["EVENT_JSON:" + json.dumps(e2)])
    assert near.events(txr) == [e1, e2]
    assert near.events(txr, "b") == [e2]
    assert near.events(txr, "zzz") == []


def test_request_execution_args():
    payload = {"code_source": "x", "n": 3}
    fc = {"FunctionCall": {"method_name": "request_execution",
                           "args": base64.b64encode(json.dumps(payload).encode()).decode()}}
    other = {"FunctionCall": {"method_name": "other", "args": ""}}
    txr = {"result": {"receipts": [
        {"receiver_id": "elsewhere.testnet", "receipt": {"Action": {"actions": [fc]}}},
        {"receiver_id": near.OUTLAYER, "receipt": {"Action": {"actions": [{"Transfer": {}}, other]}}},
        {"receiver_id": near.OUTLAYER, "receipt": {"Action": {"actions": [fc]}}},
    ]}}
    assert near.request_execution_args(txr) == payload


def test_request_execution_args_none():
    assert near.request_execution_args({}) is None
    txr = {"result": {"receipts": [{"receiver_id": near.OUTLAYER, "receipt": {"Data": {}}}]}}
    assert near.request_execution_args(txr) is None
