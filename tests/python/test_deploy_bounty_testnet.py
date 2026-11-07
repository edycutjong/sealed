"""Unit tests for scripts/deploy_bounty_testnet.py with every shell-out, RPC and key path faked."""
import json
import os
import runpy
import subprocess
import sys
import types

import pytest

import deploy_bounty_testnet as d

TXID = "A" * 44
OK_OUT = f"blah\nTransaction ID: {TXID}\n"


class Args(types.SimpleNamespace):
    pass


def make_args(**kw):
    base = dict(protocol="proto.testnet", protocol_enc_pk="ab" * 32, verifier_hash="vh", verifier_url="",
                snapshot_hash="snap", amount="10", bond="5", levels=None, deliver_ttl_s=2.0, timelock_s=3.0)
    base.update(kw)
    return Args(**base)


def test_sh_combines_stdout_stderr(monkeypatch):
    seen = {}

    def fake_run(cmd, capture_output, text):
        seen["cmd"] = cmd
        return types.SimpleNamespace(stdout="out", stderr="err")
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert d.sh(["x", "y"]) == "outerr"
    assert seen["cmd"] == ["x", "y"]


def test_sha(tmp_path):
    p = tmp_path / "f"
    p.write_bytes(b"abc")
    assert d.sha(str(p)) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_txid():
    assert d.txid(OK_OUT) == TXID
    assert d.txid("nothing") is None


def test_create_ok(monkeypatch):
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: types.SimpleNamespace(stdout="PK\n", stderr="")
                        if "keygen.py" in cmd[2] else None)
    monkeypatch.setattr(d, "sh", lambda cmd: calls.append(cmd) or OK_OUT)
    assert d.create("a.testnet", "p.testnet", 5) == TXID
    cmd = calls[0]
    assert "5 NEAR" in cmd and "PK" in cmd and "a.testnet" in cmd


def test_create_fail(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: types.SimpleNamespace(stdout="PK", stderr=""))
    monkeypatch.setattr(d, "sh", lambda cmd: "boom")
    with pytest.raises(SystemExit) as e:
        d.create("a.testnet", "p.testnet", 1)
    assert "create a.testnet failed" in str(e.value)


def test_deploy_ok_and_fail(monkeypatch):
    calls = []
    monkeypatch.setattr(d, "sh", lambda cmd: calls.append(cmd) or OK_OUT)
    assert d.deploy("a", "w.wasm", "new", {"k": 1}) == TXID
    assert json.dumps({"k": 1}) in calls[0]
    monkeypatch.setattr(d, "sh", lambda cmd: "nope")
    with pytest.raises(SystemExit) as e:
        d.deploy("a", "w.wasm", "new", {})
    assert "deploy a failed" in str(e.value)


def test_protocol_key_creates_then_reuses(monkeypatch, tmp_path):
    monkeypatch.setattr(os.path, "expanduser", lambda p: str(tmp_path / "cfg"))
    pk1 = d.protocol_key("b.testnet")
    path = tmp_path / "cfg" / "b.testnet.protocol.json"
    data = json.loads(path.read_text())
    assert data["pk"] == pk1 and data["bounty"] == "b.testnet" and len(pk1) == 64
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert d.protocol_key("b.testnet") == pk1  # reused, not regenerated


def test_snapshot_hash(monkeypatch):
    seen = []
    monkeypatch.setattr(d, "sha", lambda p: seen.append(p) or "H")
    assert d.snapshot_hash("king") == "H"
    assert seen[0].endswith(os.path.join("verifier", "snapshots", "king.json"))


def test_level_cfg(monkeypatch):
    monkeypatch.setattr(d, "snapshot_hash", lambda l: f"h-{l}")
    snaps, invs = d.level_cfg(make_args(levels="fallback,king"))
    assert snaps == ["h-fallback", "h-telephone", "h-delegation", "h-force", "h-king"]
    assert invs == [{"id": "fallback-owner-drained", "target": 0, "amount": "10", "bond": "5"},
                    {"id": "king-throne-locked", "target": 4, "amount": "10", "bond": "5"}]


def test_level_cfg_unknown_level(monkeypatch):
    monkeypatch.setattr(d, "snapshot_hash", lambda l: "h")
    with pytest.raises(AssertionError, match="unknown level"):
        d.level_cfg(make_args(levels="fallback,nope"))


def test_create_keyless(monkeypatch):
    calls = []
    monkeypatch.setattr(d, "sh", lambda cmd: calls.append(cmd) or OK_OUT)
    assert d.create_keyless("a", "p", 3, "GH", {"cfg": {}}) == TXID
    assert "use-global-hash" in calls[0] and "GH" in calls[0] and "add-key" not in " ".join(calls[0])
    monkeypatch.setattr(d, "sh", lambda cmd: "bad")
    with pytest.raises(SystemExit) as e:
        d.create_keyless("a", "p", 3, "GH", {})
    assert "keyless create a failed" in str(e.value)


def test_cfg_fallback_single_snapshot():
    c = d.cfg(make_args(), "tok")
    assert c["snapshot_hashes"] == ["snap"]
    assert c["invariants"] == [{"id": "fallback-owner-drained", "target": 0, "amount": "10", "bond": "5"}]
    assert c["token"] == "tok" and c["bond_floor"] == "5"
    assert c["deliver_ttl_ns"] == 2_000_000_000 and c["timelock_ns"] == 3_000_000_000
    assert c["verifier_wasm_url"] == f"{d.BLOB}/vh.wasm"


def test_cfg_levels_and_explicit_url(monkeypatch):
    monkeypatch.setattr(d, "snapshot_hash", lambda l: f"h-{l}")
    c = d.cfg(make_args(levels="force", verifier_url="http://u"), "tok")
    assert len(c["snapshot_hashes"]) == 5
    assert [i["id"] for i in c["invariants"]] == ["force-balance-nonzero"]
    assert c["verifier_wasm_url"] == "http://u"


class FakeNear:
    def __init__(self):
        self.calls = []

    def call(self, signer, receiver, method, args, deposit="0 NEAR", gas="300 Tgas"):
        self.calls.append((signer, receiver, method, args, deposit, gas))
        return f"tx-{method}-{args.get('account_id', 'x')}"

    def view(self, acct, method):
        return {"pool": "1", "reserved": "0", "verifier_wasm_hash": "vh", "verifier_wasm_url": "u", "extra": 1}

    def rpc(self, method, params):
        self.rpc_args = (method, params)
        return {"result": {"keys": []}}


@pytest.fixture
def env(monkeypatch, tmp_path):
    fake = FakeNear()
    for n in ("call", "view", "rpc"):
        monkeypatch.setattr(d.near, n, getattr(fake, n))
    wasm = tmp_path / "bounty.wasm"
    wasm.write_bytes(b"bounty-bytes")
    monkeypatch.setattr(d, "BOUNTY_WASM", str(wasm))
    monkeypatch.setattr(d, "TOKEN_WASM", str(wasm))
    monkeypatch.setattr(d, "VERIFIER", str(wasm))
    monkeypatch.setattr(d, "create", lambda acct, parent, n: f"create-{acct}")
    monkeypatch.setattr(d, "deploy", lambda acct, w, m, args: f"deploy-{acct}-{m}")
    monkeypatch.setattr(d, "create_keyless", lambda *a: "keyless-tx")
    monkeypatch.setattr(d, "protocol_key", lambda acct: "pk-" + acct)
    return fake, tmp_path


def run_main(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["deploy_bounty_testnet.py", *argv])
    d.main()


def test_main_keyed_full(monkeypatch, env, capsys):
    fake, tmp = env
    rec_path = tmp / "rec.json"
    run_main(monkeypatch, "--account", "d3.testnet", "--keyed", "--create", "5", "--token", "--fund", "100",
             "--register", "hunter.testnet", "--record", str(rec_path))
    out = capsys.readouterr().out
    assert "created d3.testnet create-d3.testnet" in out
    assert "token tusdc.d3.testnet deploy-tusdc.d3.testnet-new" in out
    assert "bounty d3.testnet deploy-d3.testnet-new" in out
    assert "funded 100 tx-ft_transfer_call" in out
    assert json.loads(out.strip().splitlines()[-1]) == {
        "pool": "1", "reserved": "0", "verifier_wasm_hash": "vh", "verifier_wasm_url": "u"}
    rec = json.loads(rec_path.read_text())
    assert rec["bounty_account"] == "d3.testnet" and rec["create_account_tx"] == "create-d3.testnet"
    assert rec["token_create_tx"] == "create-tusdc.d3.testnet"
    assert set(rec["register_txs"]) == {"d3.testnet", "hunter.testnet"}
    assert rec["config"]["protocol_enc_pk"] == "pk-d3.testnet"
    assert rec["fund_tx"].startswith("tx-ft_transfer_call")
    assert fake.calls[0][4] == "0.01 NEAR"


def test_main_keyed_minimal(monkeypatch, env, capsys):
    fake, _ = env
    run_main(monkeypatch, "--account", "k.testnet", "--keyed", "--protocol-enc-pk", "ff", "--verifier-hash", "vv")
    out = capsys.readouterr().out
    assert "created" not in out and "funded" not in out
    assert len(fake.calls) == 1


def test_main_keyless_requires_flags(monkeypatch, env):
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, "--account", "x.testnet")
    assert "keyless path needs" in str(e.value)


def test_main_keyless_ok(monkeypatch, env, capsys):
    import base58
    fake, tmp = env
    gh = base58.b58encode(bytes.fromhex(d.sha(d.BOUNTY_WASM))).decode()
    rec_path = tmp / "r.json"
    run_main(monkeypatch, "--account", "x.testnet", "--global-hash", gh, "--token-account", "tok.testnet",
             "--create", "3", "--record", str(rec_path))
    out = capsys.readouterr().out
    assert "keyless bounty x.testnet keyless-tx" in out
    rec = json.loads(rec_path.read_text())
    assert rec["keyless"] is True and rec["access_keys"] == [] and rec["global_hash"] == gh
    assert fake.rpc_args[1]["account_id"] == "x.testnet"
    assert rec["config"]["token"] == "tok.testnet"


def test_main_keyless_hash_mismatch(monkeypatch, env):
    with pytest.raises(AssertionError, match="global hash"):
        run_main(monkeypatch, "--account", "x.testnet", "--global-hash", "wrong", "--token-account", "t",
                 "--create", "1")


def test_dunder_main(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["deploy_bounty_testnet.py"])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(d.__file__, run_name="__main__")
    assert e.value.code == 2  # argparse: --account required
