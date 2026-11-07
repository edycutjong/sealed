"""Unit tests for scripts/mkcorpus.py: all file access is redirected into a fake tree under tmp_path."""
import hashlib
import json
import os

import pytest

import mkcorpus

FAKE_ADDR = {
    "fallback": "0x" + "f1" * 20,
    "telephone": "0x" + "a2" * 20,
    "delegation": "0x" + "d3" * 20,
    "force": "0x" + "e4" * 20,
    "king": "0x" + "b5" * 20,
}
DELEGATE = "0x" + "99" * 20
FACTORY = "0xfac0"


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    for level, addr in FAKE_ADDR.items():
        snap = {"instance": addr}
        if level == "delegation":
            snap["factory"] = FACTORY
            snap["accounts"] = {FACTORY: {"storage": {"0x1": "0x" + "00" * 12 + DELEGATE[2:]}}}
        write_json(str(tmp_path / "verifier" / "snapshots" / f"{level}.json"), snap)
    for c in ("TelephoneAttack", "ForceAttack", "KingAttack"):
        write_json(str(tmp_path / "levels" / "out" / "Attacks.sol" / f"{c}.json"),
                   {"bytecode": {"object": "60" + c[0].lower() * 2}})
    monkeypatch.setattr(mkcorpus, "ROOT", str(tmp_path))
    monkeypatch.setattr(mkcorpus, "VEC", str(tmp_path / "corpus" / "vectors"))
    return tmp_path


def test_word_pads_and_lowercases():
    assert mkcorpus.word("0xABCD") == "0" * 60 + "abcd"
    assert mkcorpus.word("ab") == "0" * 62 + "ab"


def test_compact_is_minimal_json():
    assert mkcorpus.compact([{"a": 1}, []]) == b'[{"a":1},[]]'


def test_levels_maps():
    assert mkcorpus.TARGET["fallback"] == 0 and mkcorpus.TARGET["king"] == 4
    assert mkcorpus.INVARIANT["force"] == "force-balance-nonzero"


def test_snap_and_initcode(tree):
    assert mkcorpus.snap("king") == {"instance": FAKE_ADDR["king"]}
    code = mkcorpus.initcode("ForceAttack", "0xAB", "0x01")
    assert code == "60ff" + "0" * 62 + "ab" + "0" * 63 + "1"


def test_envelope_commit_and_fields():
    ex = b"[]"
    env = mkcorpus.envelope("king", ex)
    k = mkcorpus.KEYS
    expect = hashlib.sha256(ex + k["hunter"].encode() + bytes.fromhex(k["salt"])).hexdigest()
    assert env["commit_hash"] == expect
    assert env["target"] == 4 and env["invariant_id"] == "king-throne-locked"
    assert env["secrets"] == {"EXPLOIT": "[]", "SALT": k["salt"], "EPH_SK": k["eph_sk"]}
    assert env["protocol_enc_pk"] == k["protocol_pk"]


def test_real_exploits(tree):
    real = mkcorpus.real_exploits()
    assert list(real) == ["fallback", "telephone", "delegation", "force", "king"]
    assert [t["data"] for t in real["fallback"]] == ["0xd7bb99ba", "0x", "0x3ccfd60b"]
    assert real["telephone"][0]["to"] is None
    assert real["telephone"][0]["data"].startswith("0x60tt")
    assert real["telephone"][0]["data"].endswith(mkcorpus.word(FAKE_ADDR["telephone"]) + mkcorpus.word(mkcorpus.PLAYER))
    assert real["delegation"] == [{"to": FAKE_ADDR["delegation"], "data": "0xdd365b8b", "value": "0"}]
    assert real["force"][0]["value"] == "1"
    assert real["king"][0]["value"] == "1000000000000000"


def test_near_misses(tree):
    nm = mkcorpus.near_misses()
    assert len(nm) == 5
    assert nm[("delegation", "nearmiss-delegation-wrong-contract")][0]["to"] == DELEGATE
    assert nm[("telephone", "nearmiss-telephone-direct")][0]["data"] == "0xa6f9dae1" + mkcorpus.word(mkcorpus.PLAYER)
    assert len(nm[("fallback", "nearmiss-fallback-no-receive")]) == 2
    assert nm[("force", "nearmiss-force-transfer")][0]["to"] == FAKE_ADDR["force"]
    assert nm[("king", "nearmiss-king-eoa")][0]["to"] == FAKE_ADDR["king"]


def test_items_categories(tree):
    its = mkcorpus.items()
    names = [i[0] for i in its]
    assert len(its) == 5 + 5 + 4 + 2 + 4
    assert len(set(names)) == len(names)
    cats = {}
    for _, cat, _, _, _ in its:
        cats[cat] = cats.get(cat, 0) + 1
    assert cats == {"real": 5, "near-miss": 9, "wrong-snapshot": 2, "malformed": 4}
    by = {i[0]: i for i in its}
    assert by["real-king"][4] == {"broken": True, "err": None}
    assert by["noop-force"][3] == b"[]"
    assert by["malformed-not-json"][4]["err"] == "exploit invalid: json"
    assert by["malformed-too-many-txs"][4]["err"] == "exploit invalid: too many txs"
    assert len(json.loads(by["malformed-too-many-txs"][3])) == 5
    assert by["wrong-snapshot-king-on-force"][2] == "force"


def test_llm_items(tree):
    d = tree / "corpus" / "llm"
    d.mkdir(parents=True)
    (d / "prompt.md").write_text("## Fallback\n```json\n[]\n```\n")
    (d / "modelx.md").write_text(
        "## Fallback exploit\nnotes\n```json\n[{\"to\": \"0x1\"}]\n```\n"
        "### **King** thing\n```json  \n[]\n```\n"
        "## Unknown\n```json\n[1]\n```\n")
    (d / "other.txt").write_text("ignored")
    out = mkcorpus.llm_items()
    assert out == [
        ("llm-modelx-fallback", "llm", "fallback", b'[{"to": "0x1"}]', None),
        ("llm-modelx-king", "llm", "king", b"[]", None),
    ]


def test_llm_items_empty(tree):
    assert mkcorpus.llm_items() == []


def test_main_writes_corpus(tree, capsys):
    vec = tree / "corpus" / "vectors"
    vec.mkdir(parents=True)
    (vec / "stale.json").write_text("{}")
    (tree / "corpus" / "llm").mkdir()
    (tree / "corpus" / "llm" / "m.md").write_text("## Force\n```json\n[]\n```\n")
    write_json(str(tree / "day0" / "abuse-big.json"), {})
    mkcorpus.main()
    assert not (vec / "stale.json").exists()
    man = json.loads((tree / "corpus" / "manifest.json").read_text())
    assert man["v"] == 1
    assert man["levels"][1] == {"target": 1, "level": "telephone", "invariant_id": "telephone-owner-taken"}
    assert len(man["items"]) == 20 + 1 + 1
    abuse = man["items"][-1]
    assert abuse == {"name": "abuse-big", "category": "abuse", "level": "fallback", "target": 0,
                     "invariant_id": "fallback-owner-drained", "vector": "day0/abuse-big.json",
                     "expect": {"broken": False}}
    llm = [m for m in man["items"] if m["category"] == "llm"][0]
    assert llm["expect"] is None and llm["target"] == 3
    f = vec / "real-king.json"
    assert f.read_text().endswith("}\n")
    assert json.loads(f.read_text())["target"] == 4
    assert len(list(vec.glob("*.json"))) == 21
    out = capsys.readouterr().out
    assert out.startswith("corpus: 22 items")
    assert "'abuse': 1" in out and "'real': 5" in out


def test_main_creates_vec_dir(tree, capsys):
    mkcorpus.main()
    assert (tree / "corpus" / "vectors" / "real-fallback.json").exists()
    assert "corpus: 20 items" in capsys.readouterr().out


def test_run_as_script(tree, capsys):
    """Execute the real source as __main__ with a fake __file__ so ROOT resolves to the fake tree."""
    import shutil
    src = mkcorpus.__file__
    real_root = os.path.dirname(os.path.dirname(src))
    (tree / "day0").mkdir(exist_ok=True)
    shutil.copy(os.path.join(real_root, "day0", "vectors.json"), tree / "day0" / "vectors.json")
    fake = str(tree / "scripts" / "mkcorpus.py")
    with open(src) as f:
        code = compile(f.read(), src, "exec")
    exec(code, {"__name__": "__main__", "__file__": fake})  # noqa: S102
    assert "corpus: 20 items" in capsys.readouterr().out
    assert (tree / "corpus" / "manifest.json").exists()
