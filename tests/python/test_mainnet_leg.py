"""Unit tests for scripts/mainnet_leg.py: all network, tool lookup and key material is faked."""
import argparse
import io
import json
import os
import runpy
import sys
import types
import urllib.error

import pytest

import mainnet_leg as m


class FakeResp:
    def __init__(self, status, payload):
        self.status, self._p = status, payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        return json.dumps(self._p).encode()


def test_b58():
    assert m.b58(b"") == ""
    assert m.b58(b"\0\0a") == "11" + m.b58(b"a")
    assert m.b58(b"a") == "2g"


def test_http_ok_and_body(monkeypatch):
    seen = {}

    def fake(req, timeout):
        seen["req"], seen["t"] = req, timeout
        return FakeResp(200, {"a": 1})
    monkeypatch.setattr(m.urllib.request, "urlopen", fake)
    assert m.http("http://x", {"k": 1}) == (200, {"a": 1})
    assert json.loads(seen["req"].data) == {"k": 1}
    assert m.http("http://x")[0] == 200
    assert seen["req"].data is None


def test_http_errors(monkeypatch):
    def herr(req, timeout):
        raise urllib.error.HTTPError("http://u", 429, "x", {}, io.BytesIO(b"slow down"))
    monkeypatch.setattr(m.urllib.request, "urlopen", herr)
    assert m.http("http://u") == (429, {"error": "slow down"})

    def boom(req, timeout):
        raise OSError("down")
    monkeypatch.setattr(m.urllib.request, "urlopen", boom)
    assert m.http("http://u") == (0, {"error": "OSError: down"})


def test_rpc_view(monkeypatch):
    calls = []

    def fake_http(url, body=None):
        calls.append(body)
        return 200, {"result": {"result": list(json.dumps({"symbol": "USDC"}).encode())}}
    monkeypatch.setattr(m, "http", fake_http)
    assert m.rpc_view("a.near", "ft_metadata", {}) == {"symbol": "USDC"}
    assert calls[0]["params"]["account_id"] == "a.near"
    monkeypatch.setattr(m, "http", lambda u, b=None: (200, {"error": {"m": 1}}))
    assert "error" in m.rpc_view("a", "b", {})
    monkeypatch.setattr(m, "http", lambda u, b=None: (200, {"result": {}}))
    assert "error" in m.rpc_view("a", "b", {})


def test_global_hash_deterministic():
    h = m.global_hash()
    assert h == m.global_hash() and len(h) > 40


def _check_env(monkeypatch, tools, code, cfg, meta, toks):
    monkeypatch.setattr(m.shutil, "which", lambda t: "/bin/" + t if t in tools else None)

    def fh(url, body=None):
        if url == m.RPC:
            return code, {}
        return 200, toks
    monkeypatch.setattr(m, "http", fh)
    monkeypatch.setattr(m, "rpc_view", lambda a, meth, args: cfg if a == m.OUTLAYER else meta)
    monkeypatch.setattr(m, "global_hash", lambda: "HASH")


def test_check_all_ok(monkeypatch, capsys):
    toks = [{"assetId": v} for v in m.CHAINS.values()]
    _check_env(monkeypatch, {"near", "outlayer", "wasmtime"}, 200, {"x": 1},
               {"symbol": "USDC", "decimals": 6}, toks)
    with pytest.raises(SystemExit) as e:
        m.check(None)
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert "MISS" not in out and "FAIL" not in out and "HASH" in out


def test_check_failures(monkeypatch, capsys):
    _check_env(monkeypatch, {"near"}, 500, {"error": "no"}, {}, {"nope": 1})
    with pytest.raises(SystemExit) as e:
        m.check(None)
    assert e.value.code == 1
    out = capsys.readouterr().out
    assert "MISS outlayer" in out and "FAIL mainnet RPC" in out and "FAIL native USDC" in out
    assert "MISS 1Click asset base" in out


def ns(**k):
    d = dict(live=False, refund_to=None, deadline_h=6, to="base", amount=5_000_000, recipient="0xabc")
    d.update(k)
    return argparse.Namespace(**d)


def test_quote_live_requires_refund():
    with pytest.raises(SystemExit) as e:
        m.quote(ns(live=True))
    assert "--refund-to" in str(e.value)


def test_quote_dry(monkeypatch, capsys):
    got = {}

    def fh(url, body=None):
        got.update(url=url, body=body)
        return 200, {"quote": {}}
    monkeypatch.setattr(m, "http", fh)
    with pytest.raises(SystemExit) as e:
        m.quote(ns())
    assert e.value.code == 0
    assert got["body"]["dry"] is True and got["body"]["refundTo"] == "example.near"
    assert got["body"]["destinationAsset"] == m.CHAINS["base"]
    assert got["url"].endswith("/v0/quote")
    assert "Use quote.depositAddress" not in capsys.readouterr().out


def test_quote_live_ok_and_fail(monkeypatch, capsys):
    monkeypatch.setattr(m, "http", lambda u, b=None: (201, {"depositAddress": "d"}))
    with pytest.raises(SystemExit) as e:
        m.quote(ns(live=True, refund_to="me.near"))
    assert e.value.code == 0
    assert "Use quote.depositAddress" in capsys.readouterr().out
    monkeypatch.setattr(m, "http", lambda u, b=None: (400, {"error": "bad"}))
    with pytest.raises(SystemExit) as e:
        m.quote(ns(live=True, refund_to="me.near"))
    assert e.value.code == 1


def test_status(monkeypatch, capsys):
    monkeypatch.setattr(m, "http", lambda u, b=None: (200, {"status": "SUCCESS", "u": u}))
    m.status(argparse.Namespace(deposit="dep1"))
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "SUCCESS" and out["u"].endswith("depositAddress=dep1")


def plan_ns(**k):
    d = dict(protocol="p.near", bounty="b.p.near", hunter="h.near", payout_to="dest.near", amount=5_000_000,
             bond="100", outlayer_deposit="200", bounty_funds="1", sign="sign-with-keychain",
             protocol_enc_pk=None, gen_key=False)
    d.update(k)
    return argparse.Namespace(**d)


def test_plan_without_key(capsys):
    m.plan(plan_ns(payout_to="0xdead"))
    out = capsys.readouterr().out
    assert "6–9. hunter commands" in out and "<PROTOCOL_ENC_PK_HEX>" in out
    assert "register b.p.near" in out and "register h.near" in out and "register 0xdead" not in out
    assert "5 USDC" in out


def test_plan_with_key_and_gen_key(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    fake_hunter = types.ModuleType("hunter")
    fake_hunter.EXPLOITS = {"fallback": {"op": "x"}}
    fake_hunter.local_run = lambda inp, secrets: ({"broken": True}, "abcd")
    fake_d = types.ModuleType("deploy_bounty_testnet")
    fake_d.protocol_key = lambda bounty: "ff" * 32
    monkeypatch.setitem(sys.modules, "hunter", fake_hunter)
    monkeypatch.setitem(sys.modules, "deploy_bounty_testnet", fake_d)
    m.plan(plan_ns(gen_key=True))
    out = capsys.readouterr().out
    assert "ff" * 32 in out and "9. 1Click" in out and "register dest.near" in out
    files = list((tmp_path / ".config" / "sealed").glob("mainnet-h.near-*.json"))
    assert len(files) == 1
    assert oct(files[0].stat().st_mode & 0o777) == "0o600"
    data = json.loads(files[0].read_text())
    assert data["enc_hex"] == "abcd" and set(data["secrets"]) == {"EXPLOIT", "SALT", "EPH_SK"}
    assert data["secrets"]["EXPLOIT"] not in out  # secrets are never printed


def test_plan_explicit_pk_broken_exploit(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    fake_hunter = types.ModuleType("hunter")
    fake_hunter.EXPLOITS = {"fallback": {}}
    fake_hunter.local_run = lambda inp, secrets: ({"broken": False}, "")
    monkeypatch.setitem(sys.modules, "hunter", fake_hunter)
    with pytest.raises(AssertionError):
        m.plan(plan_ns(protocol_enc_pk="aa"))


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["mainnet_leg.py"] + argv)
    m.main()


def test_main_dispatch(monkeypatch, capsys):
    monkeypatch.setattr(m, "http", lambda u, b=None: (200, {"s": 1}))
    _run_main(monkeypatch, ["status", "dep"])
    assert '"s": 1' in capsys.readouterr().out
    monkeypatch.setattr(m, "plan", lambda a: print("PLAN", a.protocol, a.amount, a.sign))
    _run_main(monkeypatch, ["plan", "--protocol", "p", "--bounty", "b", "--hunter", "h", "--payout-to", "x"])
    assert "PLAN p 5000000 sign-with-keychain" in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        _run_main(monkeypatch, ["quote", "--recipient", "0x1"])
    assert e.value.code == 0
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["check"])
    with pytest.raises(SystemExit) as e:
        _run_main(monkeypatch, [])
    assert e.value.code == 2


def test_dunder_main(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mainnet_leg.py", "status", "dep"])
    monkeypatch.setattr(m.urllib.request, "urlopen", lambda r, timeout: FakeResp(200, {"ok": True}))
    runpy.run_path(m.__file__, run_name="__main__")
    assert '"ok": true' in capsys.readouterr().out
    assert os.path.exists(m.__file__)
