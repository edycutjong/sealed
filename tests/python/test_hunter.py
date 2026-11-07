"""Unit tests for scripts/hunter.py: every chain / CLI / wasmtime call is faked."""
import base64
import json
import os
import runpy
import subprocess
import types

import pytest

import hunter

BOUNTY = "bounty.testnet"
HUNTER = "sealed-alice-11010702.testnet"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Redirect ROOT and PRIVATE into tmp_path; stub sleep."""
    monkeypatch.setattr(hunter, "ROOT", str(tmp_path))
    monkeypatch.setattr(hunter, "PRIVATE", str(tmp_path / "private"))
    monkeypatch.setattr(hunter.time, "sleep", lambda s: None)
    return tmp_path


def test_status_name():
    assert hunter.status_name("Paid") == "Paid"
    assert hunter.status_name({"Refused": "why"}) == "Refused"


def test_local_run_parses_verdict_and_enc(monkeypatch):
    seen = {}

    def fake_run(cmd, input, capture_output, env):
        seen.update(cmd=cmd, input=input, env=env)
        out = json.dumps({"broken": True, "h_enc": "ab", "err": None}).encode()
        return types.SimpleNamespace(stdout=out, stderr=b"noise\nenc=QUJD\n")

    monkeypatch.setattr(hunter.subprocess, "run", fake_run)
    verdict, enc = hunter.local_run({"x": 1}, {"EXPLOIT": "[]"})
    assert verdict["broken"] is True
    assert enc == "QUJD"
    assert seen["cmd"][0] == "wasmtime"
    assert json.loads(seen["input"]) == {"x": 1}
    assert seen["env"]["SEALED_DEBUG_ENC"] == "1" and seen["env"]["EXPLOIT"] == "[]"


def test_local_run_no_enc_line(monkeypatch):
    monkeypatch.setattr(hunter.subprocess, "run", lambda *a, **k: types.SimpleNamespace(
        stdout=b'{"broken": false}', stderr=b"nothing"))
    assert hunter.local_run({}, {}) == ({"broken": False}, None)


def test_store_secrets_success_and_failure(monkeypatch):
    calls = []

    def fake_run(cmd, env, capture_output, text):
        calls.append((cmd, env))
        return types.SimpleNamespace(returncode=calls_rc[0])

    calls_rc = [0]
    monkeypatch.setattr(hunter.subprocess, "run", fake_run)
    monkeypatch.setenv("OUTLAYER_BIN", "/x/outlayer")
    assert hunter.store_secrets(HUNTER, BOUNTY, "wh", "c-1234", {"A": "b"}) is True
    cmd, e = calls[0]
    assert cmd[0] == "/x/outlayer" and "whitelist:" + HUNTER in cmd and BOUNTY in cmd
    assert e["OUTLAYER_HOME"].endswith("home-alice")
    assert e["OUTLAYER_NETWORK"] == "testnet"
    calls_rc[0] = 3
    with pytest.raises(SystemExit) as ei:
        hunter.store_secrets(HUNTER, BOUNTY, "wh", "c-1234", {"A": "b"})
    assert "exit 3" in str(ei.value)


def test_wait_commit_polls_until_done(monkeypatch):
    monkeypatch.setattr(hunter.time, "sleep", lambda s: None)
    seq = iter([None, {"status": "Pending"}, {"status": {"Awarded": 1}}])
    monkeypatch.setattr(hunter.near, "view", lambda *a: next(seq))
    c = hunter.wait_commit(BOUNTY, 7, lambda s: s == "Awarded")
    assert c["status"] == {"Awarded": 1}


def test_wait_commit_timeout(monkeypatch):
    with pytest.raises(SystemExit) as ei:
        hunter.wait_commit(BOUNTY, 7, lambda s: True, timeout=0)
    assert "did not settle in 0s" in str(ei.value)


def _ev(label, *a):
    return {"label": label, "args": list(a)}


def _fake_chain(monkeypatch, statuses, calls):
    """Fake near/evidence/local_run/store_secrets. statuses: iterator of commit dicts."""
    st = {"invariants": [{"id": "fallback-owner-drained", "target": "T", "bond": "5"},
                         {"id": "other-inv", "target": "T2", "bond": "7"}],
          "protocol_enc_pk": "pk", "verifier_wasm_hash": "wh", "outlayer_deposit": "10"}
    monkeypatch.setattr(hunter.near, "view",
                        lambda b, m, args=None: st if m == "view_state" else next(statuses))
    monkeypatch.setattr(hunter, "local_wasm_hash", lambda: st["verifier_wasm_hash"])

    def call(signer, contract, method, args, **kw):
        calls.append((method, args, kw))
        return f"tx-{method}-{len(calls)}"

    monkeypatch.setattr(hunter.near, "call", call)
    monkeypatch.setattr(hunter.near, "tx", lambda h, s: {"tx": h, "signer": s})
    monkeypatch.setattr(hunter.near, "logs", lambda ctx: [
        {"executor": "other", "log": "COMMIT 99 nope"},
        {"executor": BOUNTY, "log": "misc"},
        {"executor": BOUNTY, "log": "COMMIT 4 hash"}])
    monkeypatch.setattr(hunter, "local_run", lambda inp, sec: (
        {"broken": True, "h_enc": "f" * 40, "err": None}, bytes(3).hex()))
    stored = []
    monkeypatch.setattr(hunter, "store_secrets", lambda *a: stored.append(a) or True)
    monkeypatch.setattr(hunter.evidence, "bundle", lambda *a: _ev(*a))
    return st, stored


def _argv(monkeypatch, *args):
    monkeypatch.setattr(hunter.sys, "argv", ["hunter.py", *args])


def test_main_full_flow_wrong_first_then_paid(env, monkeypatch, capsys):
    calls = []
    statuses = iter([{"status": "AwaitingRegistration"}, {"status": "Awarded"},
                     {"status": "Paid"}])
    st, stored = _fake_chain(monkeypatch, statuses, calls)
    _argv(monkeypatch, "--bounty", BOUNTY, "--hunter", HUNTER, "--exploit", "fallback",
          "--label", "run1", "--deliver-wrong-first", "--payout-to", "payee.testnet")
    hunter.main()
    out = capsys.readouterr().out
    assert "local verdict broken=True" in out
    assert "stored the OutLayer row (3 keys)" in out
    assert "commit 4 tx tx-commit-1" in out
    assert "wrong deliver tx" in out and "→ Paid" in out
    methods = [c[0] for c in calls]
    assert methods == ["commit", "deliver", "deliver"]
    assert calls[0][1]["payout_to"] == "payee.testnet"
    assert calls[0][2]["deposit"] == "15 yoctonear"
    wrong = base64.b64decode(calls[1][1]["enc"])
    right = base64.b64decode(calls[2][1]["enc"])
    assert wrong == bytes(3) and right == bytes(3)
    assert stored and stored[0][2] == "wh"
    priv = json.load(open(env / "private" / "run1.json"))
    assert oct(os.stat(env / "private" / "run1.json").st_mode & 0o777) == "0o600"
    assert priv["final_status"] == "Paid" and priv["commit_id"] == 4
    assert "mismatch_tx" in priv and "deliver_tx" in priv and "store_secrets" in priv
    ev = json.load(open(env / "corpus" / "evidence" / "run1.json"))
    assert ev["label"] == "run1"
    pub = json.load(open(env / "corpus" / "published" / "run1.json"))
    assert pub["final_status"] == "Paid"
    assert set(pub["timing_s"]) == {"commit_to_verdict_s", "deliver_to_paid_s"}
    assert pub["secrets"] == priv["secrets"]


def test_main_no_deliver_skip_store_file_exploit(env, monkeypatch, capsys):
    calls = []
    statuses = iter([{"status": "Awarded"}])
    st, stored = _fake_chain(monkeypatch, statuses, calls)
    f = env / "x.json"
    f.write_text(json.dumps({"txs": [{"to": "a", "data": "0x", "value": "0"}]}))
    _argv(monkeypatch, "--bounty", BOUNTY, "--hunter", HUNTER, "--exploit", str(f),
          "--label", "run2", "--no-deliver", "--skip-store")
    hunter.main()
    assert stored == []
    assert [c[0] for c in calls] == ["commit"]
    assert calls[0][1]["payout_to"] == HUNTER
    priv = json.load(open(env / "private" / "run2.json"))
    assert priv["secrets"]["EXPLOIT"] == '[{"to":"a","data":"0x","value":"0"}]'
    assert "store_secrets" not in priv
    # Awarded is not terminal -> no published file
    assert not (env / "corpus" / "published").exists()
    assert (env / "corpus" / "evidence" / "run2.json").exists()


def test_main_refused_dict_status_noop(env, monkeypatch, capsys):
    calls = []
    statuses = iter([{"status": {"Refused": "bad"}}])
    _fake_chain(monkeypatch, statuses, calls)
    _argv(monkeypatch, "--bounty", BOUNTY, "--hunter", HUNTER, "--exploit", "noop",
          "--label", "run3")
    hunter.main()
    assert [c[0] for c in calls] == ["commit"]
    pub = json.load(open(env / "corpus" / "published" / "run3.json"))
    assert pub["final_status"] == {"Refused": "bad"}
    assert pub["timing_s"].keys() == {"commit_to_verdict_s"}


def test_main_awarded_deliver_without_wrong(env, monkeypatch):
    calls = []
    statuses = iter([{"status": "Awarded"}, {"status": "Voided"}])
    _fake_chain(monkeypatch, statuses, calls)
    _argv(monkeypatch, "--bounty", BOUNTY, "--hunter", HUNTER,
          "--exploit", "contribute-only", "--label", "run4")
    hunter.main()
    assert [c[0] for c in calls] == ["commit", "deliver"]
    assert "mismatch_tx" not in json.load(open(env / "private" / "run4.json"))


def _manifest(env, name="item1", inv="other-inv"):
    (env / "corpus").mkdir()
    (env / "corpus" / "manifest.json").write_text(json.dumps({"items": [
        {"name": "skip", "vector": "v0.json", "invariant_id": "zzz"},
        {"name": name, "vector": "v.json", "invariant_id": inv}]}))
    (env / "v.json").write_text(json.dumps({"secrets": {"EXPLOIT": "[RAW  ]"}}))


def test_main_corpus_default_invariant_overridden(env, monkeypatch):
    calls = []
    _fake_chain(monkeypatch, iter([{"status": "Refused"}]), calls)
    _manifest(env)
    _argv(monkeypatch, "--bounty", BOUNTY, "--hunter", HUNTER, "--exploit", "corpus:item1",
          "--label", "run5")
    hunter.main()
    assert calls[0][1]["invariant_id"] == "other-inv"
    run = json.load(open(env / "private" / "run5.json"))
    assert run["secrets"]["EXPLOIT"] == "[RAW  ]"  # verbatim, not re-serialized
    assert run["input"]["target"] == "T2"
    assert calls[0][2]["deposit"] == "17 yoctonear"


def test_main_corpus_explicit_invariant_kept(env, monkeypatch):
    calls = []
    _fake_chain(monkeypatch, iter([{"status": "Refused"}]), calls)
    _manifest(env, inv="fallback-owner-drained")
    _argv(monkeypatch, "--bounty", BOUNTY, "--hunter", HUNTER, "--exploit", "corpus:item1",
          "--label", "run6", "--invariant", "other-inv")
    hunter.main()
    assert calls[0][1]["invariant_id"] == "other-inv"


def test_main_finish_branch(env, monkeypatch):
    (env / "private").mkdir()
    run = {"label": "old", "bounty": BOUNTY, "hunter": HUNTER, "commit_tx": "ctx",
           "final_status": "Pending"}
    (env / "private" / "old.json").write_text(json.dumps(run))
    monkeypatch.setattr(hunter.evidence, "bundle", lambda *a: _ev(*a))
    _argv(monkeypatch, "--finish", "old")
    hunter.main()
    ev = json.load(open(env / "corpus" / "evidence" / "old.json"))
    assert ev["args"] == [BOUNTY, HUNTER, "ctx", None]


def test_finish_with_expire_tx(env, monkeypatch, capsys):
    monkeypatch.setattr(hunter.evidence, "bundle", lambda *a: _ev(*a))
    monkeypatch.setattr(hunter.near, "tx", lambda h, s: (h, s))
    monkeypatch.setattr(hunter.near, "logs", lambda ctx: [{"log": f"EXPIRE {ctx[0]}"}])
    run = {"label": "exp", "bounty": BOUNTY, "hunter": HUNTER, "commit_tx": "c",
           "deliver_tx": "d", "expire_tx": "e", "expire_signer": "bob.testnet",
           "final_status": "Voided", "commit_id": 2, "input": {"i": 1}, "secrets": {"s": 2},
           "exploit_name": "noop", "commit_to_verdict_s": 1.5}
    hunter.finish(run)
    ev = json.load(open(env / "corpus" / "evidence" / "exp.json"))
    assert ev["expire_tx"] == "e" and ev["expire_signer"] == "bob.testnet"
    assert ev["expire_logs"] == ["EXPIRE e"]
    assert ev["args"][3] == "d"
    pub = json.load(open(env / "corpus" / "published" / "exp.json"))
    assert pub["timing_s"] == {"commit_to_verdict_s": 1.5}
    assert "evidence → corpus/evidence/exp.json" in capsys.readouterr().out


def test_module_as_script_requires_args(monkeypatch):
    monkeypatch.setattr(hunter.sys, "argv", ["hunter.py"])
    with pytest.raises(SystemExit) as ei:
        runpy.run_path(hunter.__file__, run_name="__main__")
    assert ei.value.code == 2


def test_builtin_exploits_shape():
    assert hunter.EXPLOITS["noop"] == []
    assert len(hunter.EXPLOITS["fallback"]) == 3
    assert hunter.TERMINAL == ("Paid", "Refused", "Voided")
    assert subprocess  # module used for patch targets


def test_local_wasm_hash_is_the_committed_pin():
    want = open(os.path.join(os.path.dirname(hunter.VERIFIER), "verifier.wasm.sha256")).read().split()[0]
    assert hunter.local_wasm_hash() == want


def test_main_refuses_a_bounty_pinned_to_another_verifier(env, monkeypatch):
    calls = []
    _fake_chain(monkeypatch, iter([]), calls)
    monkeypatch.setattr(hunter, "local_wasm_hash", lambda: "ab" * 32)
    _argv(monkeypatch, "--bounty", BOUNTY, "--hunter", HUNTER, "--exploit", "noop", "--label", "pin")
    with pytest.raises(SystemExit) as ei:
        hunter.main()
    assert "pins verifier wh" in str(ei.value) and "would not match the worker" in str(ei.value)
    assert calls == [] and not (env / "private").exists()
