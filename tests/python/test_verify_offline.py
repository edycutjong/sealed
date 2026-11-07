"""Unit tests for scripts/verify_offline.py (wasmtime and filesystem mocked; no network)."""
import base64
import hashlib
import json
import runpy
import subprocess
import sys

import pytest

import verify_offline as vo

A = "0x" + "a" * 40
B = "0x" + "b" * 40
F = "0x" + "f" * 40
TRACE_OK = f"trace: call validateInstance({A},{B}) from {A} on factory {F} -> success 0x01"


def h(b):
    return hashlib.sha256(b).hexdigest()


def test_sha():
    assert vo.sha(b"abc") == h(b"abc")


def test_wasm_for(tmp_path, monkeypatch):
    head = tmp_path / "verifier.wasm"
    head.write_bytes(b"head")
    (tmp_path / "verifiers").mkdir()
    old = tmp_path / "verifiers" / f"{h(b'old')}.wasm"
    old.write_bytes(b"old")
    liar = tmp_path / "verifiers" / f"{h(b'x')}.wasm"
    liar.write_bytes(b"not x")
    monkeypatch.setattr(vo, "ROOT", str(tmp_path))
    monkeypatch.setattr(vo, "VERIFIER", str(head))
    assert vo.wasm_for(h(b"head")) == str(head)
    assert vo.wasm_for(h(b"old")) == str(old)
    assert vo.wasm_for(h(b"x")) is None
    assert vo.wasm_for("0" * 64) is None


def test_validate_call():
    assert vo.validate_call(["noise", TRACE_OK]) == \
        f"factory {F[:10]}….validateInstance({A[:10]}…, {B[:10]}…) → 1"
    rev = f"trace: call validateInstance({A},{B}) from {A} on factory {F} -> revert"
    assert vo.validate_call([rev]).endswith("→ revert")
    assert vo.validate_call(["nothing"]) is None


def test_strip_and_deliver_enc():
    assert vo.strip({"a": 1, "lim": 2}) == {"a": 1}
    enc = b"\x01\x02"
    args = base64.b64encode(json.dumps({"enc": base64.b64encode(enc).decode()}).encode()).decode()
    ev = {"deliver_tx_status": {"transaction": {"actions": [
        "Transfer", {"Other": {}}, {"FunctionCall": {"method_name": "deliver", "args": args}}]}}}
    assert vo.deliver_enc(ev) == enc
    assert vo.deliver_enc({}) is None
    skip = {"deliver_tx_status": {"transaction": {"actions": [
        {"FunctionCall": {"method_name": "other", "args": ""}}]}}}
    assert vo.deliver_enc(skip) is None


class Proc:
    def __init__(self, rc=0, out=b"{}", err=b""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def test_run_no_wasmtime(monkeypatch):
    monkeypatch.setattr(vo.shutil, "which", lambda _n: None)
    with pytest.raises(SystemExit) as e:
        vo.run({}, {})
    assert "wasmtime not on PATH" in str(e.value)


def test_run_failure_and_success(monkeypatch):
    monkeypatch.setattr(vo.shutil, "which", lambda _n: "/bin/wasmtime")
    seen = {}

    def fake(cmd, input, capture_output, env):
        seen.update(cmd=cmd, input=input, env=env)
        return Proc(1, b"", b"x" * 500 + b"boom")
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(RuntimeError) as e:
        vo.run({"a": 1}, {"EXPLOIT": "e"}, "w.wasm")
    assert str(e.value).endswith("boom") and len(str(e.value)) == 400
    assert seen["cmd"][-1] == "w.wasm" and seen["env"]["EXPLOIT"] == "e"
    assert seen["env"]["SEALED_TRACE"] == "1" and json.loads(seen["input"]) == {"a": 1}

    err = f"junk\nenc=abcd\n{TRACE_OK}\n".encode()
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Proc(0, b'{"broken": true}', err))
    v, enc, call = vo.run({}, {})
    assert v == {"broken": True} and enc == "abcd" and "→ 1" in call

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Proc(0, b"{}", b""))
    assert vo.run({}, {}) == ({}, None, None)


def test_judge_input_errors(tmp_path, capsys):
    assert vo.judge_input(str(tmp_path / "missing.json")) == 1
    assert "INPUT=" in capsys.readouterr().err
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert vo.judge_input(str(bad)) == 1
    shape = tmp_path / "shape.json"
    shape.write_text(json.dumps({"secrets": {"EXPLOIT": 5}}))
    assert vo.judge_input(str(shape)) == 1
    assert "expected" in capsys.readouterr().err
    shape.write_text("[1]")
    assert vo.judge_input(str(shape)) == 1


def test_judge_input_txs_and_vector(tmp_path, monkeypatch, capsys):
    calls = []

    def fake_run(inp, secrets, wasm=vo.VERIFIER):
        calls.append((inp, secrets))
        return {"broken": True, "lim": {"x": 1}}, None, (TRACE_OK and "CALL")
    monkeypatch.setattr(vo, "run", fake_run)
    f = tmp_path / "txs.json"
    txs = [{"to": A, "data": "0x", "value": "0"}]
    f.write_text(json.dumps({"target": 2, "invariant_id": "inv", "txs": txs}))
    assert vo.judge_input(str(f)) == 0
    out = capsys.readouterr()
    assert json.loads(out.out) == {"broken": True}
    assert "EVM CALL" in out.err
    inp, sec = calls[-1]
    assert sec["EXPLOIT"] == json.dumps(txs, separators=(",", ":"))
    assert inp["target"] == 2 and inp["invariant_id"] == "inv" and inp["hunter"] == "judge.testnet"
    assert inp["protocol_enc_pk"] == vo.DEMO_PK
    assert inp["commit_hash"] == h(sec["EXPLOIT"].encode() + b"judge.testnet" + bytes.fromhex(sec["SALT"]))

    v = tmp_path / "vec.json"
    v.write_text(json.dumps({"secrets": {"EXPLOIT": "raw-exploit"}}))
    monkeypatch.setattr(vo, "run", lambda *a, **k: ({"broken": False}, None, None))
    assert vo.judge_input(str(v)) == 0
    assert "no validateInstance call" in capsys.readouterr().err
    # defaults for target / invariant_id
    monkeypatch.setattr(vo, "run", lambda i, s, wasm=None: calls.append((i, s)) or ({}, None, None))
    vo.judge_input(str(v))
    assert calls[-1][0]["target"] == 0 and calls[-1][0]["invariant_id"] == "fallback-owner-drained"


def test_main_dispatch_to_judge(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["x", "file.json"])
    monkeypatch.setattr(vo, "judge_input", lambda p: 7 if p == "file.json" else -1)
    assert vo.main() == 7


def make_tree(tmp_path, monkeypatch, cases):
    """cases: list of dicts building (pub, evidence) pairs; returns nothing, patches ROOT."""
    (tmp_path / "corpus" / "published").mkdir(parents=True)
    (tmp_path / "corpus" / "evidence").mkdir(parents=True)
    (tmp_path / "verifiers").mkdir()
    head = tmp_path / "verifier.wasm"
    head.write_bytes(b"head")
    monkeypatch.setattr(vo, "ROOT", str(tmp_path))
    monkeypatch.setattr(vo, "VERIFIER", str(head))
    for label, pub, ev in cases:
        (tmp_path / "corpus" / "published" / f"{label}.json").write_text(json.dumps(pub))
        (tmp_path / "corpus" / "evidence" / f"{label}.json").write_text(json.dumps(ev))


def bundle(pinned, sent, verdict, enc=None, logs=None, str_verdict=True):
    ev = {"request_execution_args": {"source": {"WasmUrl": {"hash": pinned}},
                                     "input_data": json.dumps(sent)},
          "verdict_output": json.dumps(verdict) if str_verdict else verdict}
    if enc is not None:
        args = base64.b64encode(json.dumps({"enc": base64.b64encode(enc).decode()}).encode()).decode()
        ev["deliver_tx_status"] = {"transaction": {"actions": [
            {"FunctionCall": {"method_name": "deliver", "args": args}}]}}
    if logs:
        ev["deliver_logs"] = logs
    return ev


def test_main_no_published(tmp_path, monkeypatch, capsys):
    make_tree(tmp_path, monkeypatch, [])
    monkeypatch.setattr(sys, "argv", ["x"])
    assert vo.main() == 1
    assert "no published commits" in capsys.readouterr().out


def test_main_all_paths(tmp_path, monkeypatch, capsys):
    hh = h(b"head")
    enc = b"\x09\x08"
    sent = {"commit_hash": "c0ffee" * 10, "x": 1}
    good_v = {"broken": True, "h_exploit": sent["commit_hash"], "h_enc": h(enc), "err": "", "lim": {"a": 1}}
    cases = [
        ("a-ok", {"label": "a-ok", "input": sent, "secrets": {}},
         bundle(hh, sent, {**good_v, "lim": {"a": 2}}, enc=enc)),
        ("b-nowasm", {"label": "b-nowasm", "input": sent, "secrets": {}}, bundle("1" * 64, sent, good_v)),
        ("c-bad", {"label": "c-bad", "input": {"other": 1}, "secrets": {"bad": 1}},
         bundle(hh, sent, ["notadict"], enc=enc, logs=["PAID x"], str_verdict=False)),
        ("d-paid", {"label": "d-paid", "input": sent, "secrets": {}},
         bundle(hh, sent, good_v, logs=["PAID 1"])),
        ("e-enc", {"label": "e-enc", "input": sent, "secrets": {}}, bundle(hh, sent, good_v, enc=b"zz")),
        ("f-notbroken", {"label": "f-notbroken", "input": sent, "secrets": {"nb": 1}},
         bundle(hh, sent, {"broken": False, "h_exploit": "other", "h_enc": "", "err": "oops"})),
    ]
    make_tree(tmp_path, monkeypatch, cases)

    def fake_run(inp, secrets, wasm=None):
        if secrets.get("bad"):
            return {"broken": True, "h_exploit": "zzz", "h_enc": "q"}, "0908", None
        if secrets.get("nb"):
            return {"broken": False, "h_exploit": "other", "h_enc": "", "err": "oops"}, None, "CALL"
        return dict(good_v), "0908", "CALL"
    monkeypatch.setattr(vo, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["x"])
    rc = vo.main()
    out = capsys.readouterr().out
    assert rc == 1
    assert "REPLAY-OK a-ok: broken" in out and f"enc {len(enc)} B = h_enc" in out
    assert "    EVM CALL" in out
    assert "REPLAY-FAIL b-nowasm: no committed wasm hashes to the pinned 111111111111" in out
    assert "published input != input_data the bounty sent" in out
    assert "replayed verdict != on-chain worker verdict" in out
    assert "h_exploit != commit_hash" in out
    assert "paid commit without its deliver tx in the bundle" in out
    assert "REPLAY-FAIL e-enc" in out and "delivered enc != rebuilt enc / h_enc" in out
    assert "REPLAY-FAIL f-notbroken: not broken (" in out
    assert "replay: 1 OK · 5 FAIL" in out


def test_main_no_evm_call_all_ok(tmp_path, monkeypatch, capsys):
    hh = h(b"head")
    sent = {"commit_hash": "ab"}
    v = {"broken": False, "h_exploit": "ab", "h_enc": "", "err": ""}
    make_tree(tmp_path, monkeypatch,
              [("one", {"label": "one", "input": sent, "secrets": {}}, bundle(hh, sent, v, str_verdict=False))])
    monkeypatch.setattr(vo, "run", lambda i, s, w=None: (dict(v), None, None))
    monkeypatch.setattr(sys, "argv", ["x", ""])
    assert vo.main() == 0
    out = capsys.readouterr().out
    assert "not broken (no invariant broken)" in out
    assert "exploit rejected before the invariant check" in out
    assert "replay: 1 OK · 0 FAIL" in out


def test_dunder_main(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["verify_offline.py", "/nonexistent/x.json"])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(vo.__file__, run_name="__main__")
    assert e.value.code == 1
    assert "INPUT=" in capsys.readouterr().err
