"""Unit tests for scripts/hunter_agent.py: prompt building, trace parsing, extraction and the agent loop (all mocked)."""
import json
import os
import runpy
import subprocess
import sys

import pytest

import hunter_agent as h


class FakeProc:
    def __init__(self, rc=0, out=b"", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err.encode()


def patch_run(monkeypatch, verdict, err="", rc=0):
    seen = {}

    def fake(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        return FakeProc(rc, json.dumps(verdict).encode(), err)
    monkeypatch.setattr(h.subprocess, "run", fake)
    return seen


def test_with_history():
    assert h.with_history("T", []) == "T"
    out = h.with_history("T", [("a1", "f1"), ("a2", "f2")])
    assert out == ("T\n\n--- your previous answer ---\na1\n\n--- feedback ---\nf1"
                   "\n\n--- your previous answer ---\na2\n\n--- feedback ---\nf2")


def test_extract():
    assert h.extract("no block") is None
    assert h.extract("```json\n[{\"to\": null}]\n```") == [{"to": None}]
    assert h.extract("```json\n[1]\n``` then ```json\n[2]\n```") == [2]
    assert h.extract("```json\n{not json\n```") is None
    assert h.extract("```json\n{\"a\": 1}\n```") is None


def test_local_run_parses_trace(monkeypatch):
    err = "\n".join([
        "noise",
        "trace: tx call(0xabc) -> success 0x",
        "trace: tx create() -> revert 0x" + "ab" * 100,
        "trace: tx call(x) -> success",
        "trace: call validateInstance(0x1,0x2) -> success 0x0000000000000000000000000000000000000000000000000000000000000001",
    ])
    seen = patch_run(monkeypatch, {"broken": True, "err": "boom"}, err)
    broken, trace, ret = h.local_run("fallback", [{"to": None, "data": "0x", "value": "0"}])
    assert broken is True
    assert ret == "1"
    lines = trace.splitlines()
    assert lines[0] == "tx 1: success"
    assert lines[1].startswith("tx 2: revert data 0x") and len(lines[1]) == len("tx 2: revert data ") + 140
    assert lines[2] == "tx 3: success"
    assert lines[3] == "verifier: boom"
    assert seen["cmd"][:2] == ["wasmtime", "run"]
    assert seen["kw"]["env"]["SEALED_TRACE"] == "1"
    assert json.loads(seen["kw"]["env"]["EXPLOIT"]) == [{"to": None, "data": "0x", "value": "0"}]
    inp = json.loads(seen["kw"]["input"])
    assert inp["target"] == h.LEVELS["fallback"]["target"] and inp["hunter"] == h.vo.JUDGE


def test_local_run_non_success_validate_and_empty(monkeypatch):
    patch_run(monkeypatch, {"broken": False}, "trace: call validateInstance(a) -> revert 0x")
    assert h.local_run("fallback", []) == (False, "(no transactions ran)", "revert")
    patch_run(monkeypatch, {"broken": False}, "")
    assert h.local_run("fallback", [])[2].startswith("nothing")


def test_local_run_crash(monkeypatch):
    patch_run(monkeypatch, {}, "x" * 400 + "tail", rc=7)
    with pytest.raises(SystemExit) as e:
        h.local_run("fallback", [])
    assert "exit 7" in str(e.value) and "tail" in str(e.value)


def setup_main(monkeypatch, tmp_path, argv, replies, run_results=None):
    monkeypatch.setattr(h, "OUT", str(tmp_path / "out"))
    monkeypatch.setattr(h.time, "sleep", lambda s: None)
    prompts = []
    it = iter(replies)

    def call(prompt):
        prompts.append(prompt)
        r = next(it)
        if isinstance(r, Exception):
            raise r
        return r
    monkeypatch.setattr(h.baseline, "provider", lambda a: call)
    rr = iter(run_results or [])
    monkeypatch.setattr(h, "local_run", lambda level, txs: next(rr))
    monkeypatch.setattr(sys, "argv", ["hunter_agent.py"] + argv)
    return prompts


GOOD = "bug.\n```json\n[{\"to\": null, \"data\": \"0x00\", \"value\": \"0\"}]\n```"


def test_main_requires_model(monkeypatch, tmp_path):
    setup_main(monkeypatch, tmp_path, ["--level", "fallback"], [])
    with pytest.raises(SystemExit) as e:
        h.main()
    assert "--model is required" in str(e.value)


def test_main_win_first_turn(monkeypatch, tmp_path, capsys):
    setup_main(monkeypatch, tmp_path, ["--level", "fallback", "--model", "a/b c"], [GOOD], [(True, "tx 1: success", "1")])
    assert h.main() == 0
    out = capsys.readouterr()
    assert "BROKEN — transcript hunter-agent/fallback-a_b_c.md" in out.out
    assert "turn 1: broken=True" in out.err
    exploit = json.load(open(tmp_path / "out" / "fallback-a_b_c-exploit.json"))
    assert exploit == [{"to": None, "data": "0x00", "value": "0"}]
    md = (tmp_path / "out" / "fallback-a_b_c.md").read_text()
    assert "invariant broken on turn 1" in md and "scripts/hunter.py --bounty" in md and "validateInstance → 1" in md


def test_main_revise_then_win_and_cmd_provider(monkeypatch, tmp_path):
    prompts = setup_main(monkeypatch, tmp_path, ["--level", "telephone", "--provider", "cmd", "--cmd", "x"],
                         ["no json here", GOOD, GOOD],
                         [(False, "tx 1: revert", "revert"), (True, "tx 1: success", "1")])
    assert h.main() == 0
    assert len(prompts) == 3
    assert "your reply held no valid JSON transaction array" in prompts[1]
    assert "tx 1: revert" in prompts[2] and "validateInstance returned revert" in prompts[2]
    md = (tmp_path / "out" / "telephone-cmd.md").read_text()
    assert "No parseable" in md and "invariant broken on turn 3" in md


def test_main_not_broken(monkeypatch, tmp_path, capsys):
    setup_main(monkeypatch, tmp_path, ["--level", "fallback", "--model", "m", "--turns", "2"], [GOOD, GOOD],
               [(False, "t", "0"), (False, "t", "0")])
    assert h.main() == 1
    assert "NOT BROKEN" in capsys.readouterr().out
    assert "not broken in 2 turns" in (tmp_path / "out" / "fallback-m.md").read_text()
    assert not (tmp_path / "out" / "fallback-m-exploit.json").exists()


def test_main_provider_failure_retries(monkeypatch, tmp_path, capsys):
    err = ValueError("x" * 300)
    setup_main(monkeypatch, tmp_path, ["--level", "fallback", "--model", "m"], [err, err, err])
    assert h.main() == 2
    assert capsys.readouterr().out.startswith("ERROR")
    md = (tmp_path / "out" / "fallback-m.md").read_text()
    assert "Provider failed 3 times on turn 1: ValueError: " + "x" * 160 in md
    assert "PROVIDER ERROR on turn 1" in md


def test_main_provider_recovers(monkeypatch, tmp_path):
    setup_main(monkeypatch, tmp_path, ["--level", "fallback", "--model", "m"], [RuntimeError("flaky"), GOOD],
               [(True, "t", "1")])
    assert h.main() == 0


def test_dunder_main(monkeypatch, tmp_path):
    # run the file as a script with the provider and verifier stubbed at module level
    import baseline
    monkeypatch.setattr(baseline, "provider", lambda a: (lambda p: GOOD))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc(0, b'{"broken": true}', ""))
    monkeypatch.setattr(sys, "argv", ["hunter_agent.py", "--level", "fallback", "--model", "m"])
    path = os.path.join(h.ROOT, "scripts", "hunter_agent.py")
    # redirect output dir: script computes OUT from ROOT, so patch os.makedirs/open writes via a fake ROOT is not possible;
    # instead intercept the final file writes.
    written = {}
    real_open = open

    def fake_open(p, mode="r", *a, **k):
        if "w" in mode:
            written[str(p)] = True
            return real_open(os.devnull, mode)
        return real_open(p, mode, *a, **k)
    monkeypatch.setattr("builtins.open", fake_open)
    monkeypatch.setattr(os, "makedirs", lambda *a, **k: None)
    with pytest.raises(SystemExit) as e:
        runpy.run_path(path, run_name="__main__")
    assert e.value.code == 0
    assert any(p.endswith("fallback-m.md") for p in written)
