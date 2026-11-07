"""Unit tests for scripts/open_deliveries.py: real crypto (PyNaCl) on synthetic bundles under tmp_path."""
import base64
import hashlib
import json
import os
import runpy

import pytest

nacl_public = pytest.importorskip("nacl.public")
import open_deliveries as od  # noqa: E402

PrivateKey, Box, SealedBox = nacl_public.PrivateKey, nacl_public.Box, nacl_public.SealedBox
SCRIPT = os.path.join(os.path.dirname(od.__file__), "open_deliveries.py")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def make_case(label="run1", bounty="b1.testnet", cid="7", tamper=None):
    """Return (pub, ev, proto_sk) with every binding consistent."""
    proto = PrivateKey.generate()
    eph = PrivateKey.generate()
    pk = bytes(proto.public_key)
    epk = bytes(eph.public_key)
    exploit, salt, hunter = "boom", "aabbcc", "hunter.testnet"
    commit = sha(exploit.encode() + hunter.encode() + bytes.fromhex(salt))
    pt = json.dumps({"exploit": base64.b64encode(exploit.encode()).decode(), "salt": salt, "hunter": hunter}).encode()
    nonce = hashlib.blake2b(epk + pk, digest_size=24).digest()
    enc = epk + Box(eph, proto.public_key).encrypt(pt, nonce).ciphertext
    h_enc = sha(enc)
    inp = {"invariant_id": "inv1", "commit_hash": commit, "protocol_enc_pk": pk.hex(), "hunter": hunter}
    pub = {"label": label, "bounty": bounty, "commit_id": cid, "final_status": "Paid", "input": inp,
           "secrets": {"EPH_SK": bytes(eph).hex(), "EXPLOIT": exploit, "SALT": salt}}
    args = {"commit_id": cid, "enc": base64.b64encode(enc).decode()}
    ev = {
        "verdict_output": json.dumps({"broken": True, "invariant_id": "inv1", "h_exploit": commit, "h_enc": h_enc}),
        "bounty_logs": [f"COMMIT {cid} x", f"AWARDED {cid} to a h_enc {h_enc}", f"PAID {cid} 10"],
        "deliver_logs": [f"DELIVERED {cid} {h_enc}"],
        "request_execution_args": {"input_data": json.dumps(inp)},
        "deliver_tx_status": {"transaction": {"actions": [
            "Transfer", {"Other": 1},
            {"FunctionCall": {"method_name": "other", "args": ""}},
            {"FunctionCall": {"method_name": "deliver", "args": base64.b64encode(json.dumps(args).encode()).decode()}},
        ]}},
    }
    if tamper:
        tamper(pub, ev)
    return pub, ev, proto


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(od, "ROOT", str(tmp_path))
    home = tmp_path / "home"
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(home), 1))
    for d in ("evidence", "published"):
        (tmp_path / "corpus" / d).mkdir(parents=True)
    return tmp_path


def write(env, pub, ev, results_status="Paid"):
    c = env / "corpus"
    (c / "evidence" / (pub["label"] + ".json")).write_text(json.dumps(ev))
    (c / "published" / (pub["label"] + ".json")).write_text(json.dumps(pub))


def write_results(env, runs):
    (env / "corpus" / "results.json").write_text(json.dumps({"runs": runs}))


def test_sha_and_deliver_helpers():
    assert od.sha(b"") == hashlib.sha256(b"").hexdigest()
    assert od.deliver_args({}) == {}
    assert od.deliver_args({"deliver_tx_status": None}) == {}
    assert od.deliver_enc({}) is None
    pub, ev, _ = make_case()
    assert od.deliver_args(ev)["commit_id"] == "7"
    assert od.deliver_enc(ev) is not None
    ev["deliver_tx_status"]["transaction"]["actions"] = [{"FunctionCall": {"method_name": "x", "args": ""}}]
    assert od.deliver_args(ev) == {}


def test_check_ok(env):
    pub, ev, _ = make_case()
    write(env, pub, ev)
    assert od.check(pub) == ([], None)


def test_check_missing_deliver(env):
    pub, ev, _ = make_case()
    ev["deliver_tx_status"] = {}
    write(env, pub, ev)
    assert od.check(pub) == (["deliver tx"], None)


def test_check_verdict_as_dict_and_bad_bindings(env):
    def t(pub, ev):
        ev["verdict_output"] = {"broken": False, "invariant_id": "zzz", "h_exploit": "no", "h_enc": "bad"}
        ev["bounty_logs"] = []
        ev["deliver_logs"] = []
        ev["request_execution_args"]["input_data"] = "{}"
    pub, ev, _ = make_case(tamper=t)
    write(env, pub, ev)
    fails, proto = od.check(pub)
    for name in ("published commit id = the COMMIT log", "published input = the request input", "verdict broken",
                 "verdict invariant", "verdict h_exploit = commit", "AWARDED log", "DELIVERED log", "PAID log",
                 "sha256(enc)=h_enc"):
        assert name in fails
    assert proto is None


def test_check_wrong_epk_and_open_failure(env):
    def t(pub, ev):
        pub["secrets"]["EPH_SK"] = bytes(PrivateKey.generate()).hex()
    pub, ev, _ = make_case(tamper=t)
    write(env, pub, ev)
    fails, proto = od.check(pub)
    assert fails[-2:] == ["epk", "open"] and proto is None


def test_check_plaintext_and_commit_mismatch(env):
    def t(pub, ev):
        pub["secrets"]["EXPLOIT"] = "other"
        pub["input"]["commit_hash"] = "00" * 32
    pub, ev, _ = make_case(tamper=t)
    write(env, pub, ev)
    fails, _ = od.check(pub)
    assert "plaintext=published" in fails and "commit" in fails


def test_check_protocol_key_matches(env):
    pub, ev, proto = make_case()
    write(env, pub, ev)
    keydir = env / "home" / ".config" / "sealed"
    keydir.mkdir(parents=True)
    (keydir / "b1.testnet.protocol.json").write_text(json.dumps({"sk": bytes(proto).hex()}))
    # the seal format is libsodium SealedBox-compatible, so the real protocol key opens the same plaintext
    assert od.check(pub) == ([], True)


def test_check_protocol_key_true_and_false(env, monkeypatch):
    pub, ev, proto = make_case()
    write(env, pub, ev)
    keydir = env / "home" / ".config" / "sealed"
    keydir.mkdir(parents=True)
    (keydir / "b1.testnet.protocol.json").write_text(json.dumps({"sk": bytes(proto).hex()}))
    pt_holder = {}

    class FakeSealed:
        def __init__(self, sk):
            pass

        def decrypt(self, enc):
            return pt_holder["pt"]

    monkeypatch.setattr(od, "SealedBox", FakeSealed)
    enc = od.deliver_enc(ev)
    inp = pub["input"]
    eph = PrivateKey(bytes.fromhex(pub["secrets"]["EPH_SK"]))
    nonce = hashlib.blake2b(enc[:32] + bytes.fromhex(inp["protocol_enc_pk"]), digest_size=24).digest()
    pt = Box(eph, nacl_public.PublicKey(bytes.fromhex(inp["protocol_enc_pk"]))).decrypt(enc[32:], nonce)
    pt_holder["pt"] = pt
    assert od.check(pub) == ([], True)
    pt_holder["pt"] = b"different"
    assert od.check(pub) == (["protocol key"], False)


def test_main_fail_paid_set(env, capsys):
    write_results(env, [{"label": "a", "final_status": "Rejected"}])
    assert od.main() == 1
    assert "FAIL paid set" in capsys.readouterr().out


def test_main_missing_evidence(env, capsys):
    write_results(env, [{"label": "run1", "final_status": "Paid"}])
    pub, ev, _ = make_case()
    (env / "corpus" / "published" / "run1.json").write_text(json.dumps(pub))
    (env / "corpus" / "published" / "other.json").write_text(json.dumps({"label": "o", "final_status": "Lost"}))
    assert od.main() == 1
    assert "no evidence bundle: ['run1']" in capsys.readouterr().out


def test_main_all_open(env, capsys):
    pub, ev, _ = make_case()
    write(env, pub, ev)
    write_results(env, [{"label": "run1", "final_status": "Paid"}, {"label": "x", "final_status": "Lost"}])
    assert od.main() == 0
    out = capsys.readouterr().out
    assert "OPENED run1 [b1]" in out and "protocol key opened" not in out
    assert "open: 1 of 1 paid runs" in out


def test_main_reports_protocol_key_and_failure(env, capsys, monkeypatch):
    pub, ev, _ = make_case()
    write(env, pub, ev)
    write_results(env, [{"label": "run1", "final_status": "Paid"}])
    monkeypatch.setattr(od, "check", lambda p: ([], True))
    assert od.main() == 0
    assert "protocol key opened the same plaintext" in capsys.readouterr().out
    monkeypatch.setattr(od, "check", lambda p: (["epk", "open"], None))
    assert od.main() == 1
    out = capsys.readouterr().out
    assert "FAIL run1: epk, open" in out and "open: 0 of 1" in out


def test_import_error_exits_2(monkeypatch, capsys):
    monkeypatch.setitem(__import__("sys").modules, "nacl.public", None)
    with pytest.raises(SystemExit) as e:
        runpy.run_path(SCRIPT, run_name="open_deliveries_noimport")
    assert e.value.code == 2
    assert "needs PyNaCl" in capsys.readouterr().err


def test_main_guard_exits_with_main_status(monkeypatch, tmp_path):
    monkeypatch.setattr(os.path, "expanduser", lambda p: p.replace("~", str(tmp_path), 1))
    with pytest.raises(SystemExit) as e:
        runpy.run_path(SCRIPT, run_name="__main__")
    assert e.value.code in (0, 1)
