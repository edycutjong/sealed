"""Unit tests for scripts/refusals.py: chain access is faked, output file is redirected to tmp_path."""
import json
import runpy
import os

import pytest

import refusals


@pytest.fixture
def out(tmp_path, monkeypatch):
    p = tmp_path / "refusals.json"
    monkeypatch.setattr(refusals, "OUT", str(p))
    return p


def fake_tx(monkeypatch, logs):
    monkeypatch.setattr(refusals.near, "tx", lambda tx, signer: {"tx": tx, "signer": signer})
    monkeypatch.setattr(refusals.near, "logs", lambda txr: [{"log": l} for l in logs])


def test_load_default_and_existing(out):
    assert refusals.load() == {"network": "testnet", "refusals": []}
    out.write_text('{"network": "x", "refusals": [1]}')
    assert refusals.load()["refusals"] == [1]


def test_record_match(out, monkeypatch, capsys):
    fake_tx(monkeypatch, ["noise", "REFUSED: claim pending for x"])
    refusals.record("pool pull", "TXH", "alice.testnet")
    d = json.loads(out.read_text())
    assert d["refusals"][0]["matched"] == "REFUSED: claim pending for x"
    assert d["refusals"][0]["logs"] == ["noise", "REFUSED: claim pending for x"]
    assert "pool pull: TXH → REFUSED: claim pending for x" in capsys.readouterr().out


def test_record_no_match_appends(out, monkeypatch, capsys):
    fake_tx(monkeypatch, ["a", "b"])
    refusals.record("duplicate", "T1", "s")
    refusals.record("fake", "T2", "s")
    d = json.loads(out.read_text())
    assert [r["tx"] for r in d["refusals"]] == ["T1", "T2"]
    assert d["refusals"][0]["matched"] is None
    assert "NO MATCHING LOG: a; b" in capsys.readouterr().out


STATE = {"invariants": [{"id": "i1", "bond": "5"}, {"id": "i2", "bond": "7"}], "outlayer_deposit": "100", "pool": "999"}


def test_deposit_for(monkeypatch):
    monkeypatch.setattr(refusals.near, "view", lambda b, m: STATE)
    assert refusals.deposit_for("b", "i2") == 107
    with pytest.raises(StopIteration):
        refusals.deposit_for("b", "nope")


def test_raw_commit(monkeypatch):
    seen = {}
    monkeypatch.setattr(refusals.near, "view", lambda b, m: STATE)

    def call(signer, contract, method, args, **kw):
        seen.update(signer=signer, contract=contract, method=method, args=args, kw=kw)
        return "HASH"
    monkeypatch.setattr(refusals.near, "call", call)
    assert refusals.raw_commit("bounty", "hunter", "i1") == "HASH"
    assert seen["method"] == "commit" and seen["contract"] == "bounty"
    assert seen["args"]["invariant_id"] == "i1" and seen["args"]["payout_to"] == "hunter"
    assert len(seen["args"]["commit_hash"]) == 64
    assert seen["kw"] == {"deposit": "105 yoctonear", "gas": "300 Tgas"}


def test_show_missing(out, capsys):
    assert refusals.show() == 1
    o = capsys.readouterr().out
    assert o.count("MISSING") == 6
    assert "refusals: 0/6" in o


def test_show_all_fired(out, capsys):
    rows = [{"kind": k, "tx": f"tx-{i}", "signer": "s", "logs": [], "matched": refusals.MARK[k]}
            for i, k in enumerate(refusals.KINDS)]
    rows.append({"kind": "fake", "tx": "zzdupzz", "signer": "s", "logs": [], "matched": "x"})
    rows.append({"kind": "fake", "tx": "unmatched", "signer": "s", "logs": [], "matched": None})
    out.write_text(json.dumps({"refusals": rows}))
    assert refusals.show() == 0
    o = capsys.readouterr().out
    assert o.count("FIRED") == 6 and "MISSING" not in o
    assert refusals.TESTNET + "tx-2" in o and "zzdupzz" not in o
    assert "refusals: 6/6" in o


@pytest.fixture
def rec(monkeypatch):
    calls = []
    monkeypatch.setattr(refusals, "record", lambda *a: calls.append(a))
    monkeypatch.setattr(refusals, "raw_commit", lambda *a: "RAW")
    monkeypatch.setattr(refusals.near, "view", lambda b, m: STATE)
    monkeypatch.setattr(refusals.near, "call", lambda *a, **k: ("CALL", a, k))
    return calls


def run(monkeypatch, *args):
    monkeypatch.setattr("sys.argv", ["refusals.py", *args])
    return refusals.main()


def test_main_no_args(out, monkeypatch, capsys):
    assert run(monkeypatch) == 1
    assert "refusals: 0/6" in capsys.readouterr().out


def test_main_busy_duplicate(rec, monkeypatch):
    assert run(monkeypatch, "busy", "b", "h", "i1") == 0
    assert run(monkeypatch, "duplicate", "b", "h", "i1") == 0
    assert rec == [("invariant busy", "RAW", "h"), ("duplicate", "RAW", "h")]


def test_main_pool_pull(rec, monkeypatch):
    assert run(monkeypatch, "pool-pull", "b", "proto") == 0
    kind, res, signer = rec[0]
    assert kind == "pool pull" and signer == "proto"
    assert res[1] == ("proto", "b", "withdraw_pool", {"amount": "999"})


def test_main_expire(rec, monkeypatch):
    assert run(monkeypatch, "expire", "b", "sig", "7") == 0
    kind, res, signer = rec[0]
    assert kind == "expired award" and res[1][3] == {"commit_id": 7} and signer == "sig"


def test_main_record(rec, monkeypatch):
    assert run(monkeypatch, "record", "fake", "TX", "sig") == 0
    assert rec == [("fake", "TX", "sig")]


def test_main_unknown(rec, monkeypatch):
    with pytest.raises(SystemExit) as e:
        run(monkeypatch, "bogus")
    assert "refusal kinds" in str(e.value.code)


def test_dunder_main(root, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("sys.argv", ["refusals.py"])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(os.path.join(root, "scripts", "refusals.py"), run_name="__main__")
    assert e.value.code in (0, 1)
    assert "refusals:" in capsys.readouterr().out
