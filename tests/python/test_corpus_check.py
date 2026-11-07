"""Unit tests for scripts/corpus_check.py: wasmtime is faked, fixtures live under tmp_path."""
import json
import os
import runpy
import subprocess

import pytest

import corpus_check

SCRIPT = os.path.join(os.path.dirname(corpus_check.__file__), "corpus_check.py")


def verdict(broken=True, err="", gas=1234, **extra):
    return {"broken": broken, "err": err, "gas_used": gas, **extra}


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """Fake repo root; returns add(name, category, got, golden, expect) and the list of wasmtime calls."""
    root = tmp_path
    golden = root / "verifier" / "tests" / "golden"
    (golden / "corpus").mkdir(parents=True)
    (root / "corpus").mkdir()
    monkeypatch.setattr(corpus_check, "ROOT", str(root))
    monkeypatch.setattr(corpus_check, "GOLDEN", str(golden))
    items, outputs, calls = [], {}, []

    def add(name, category, got, want, expect):
        vec = f"corpus/{name}.bin"
        (root / vec).write_bytes(name.encode())
        gdir = golden if category == "abuse" else golden / "corpus"
        (gdir / f"{name}.json").write_text(json.dumps(want))
        items.append({"name": name, "category": category, "vector": vec, "expect": expect})
        outputs[name.encode()] = got
        (root / "corpus" / "manifest.json").write_text(json.dumps({"items": items}))

    def fake_run(cmd, input=None, capture_output=None):
        calls.append((cmd, input, capture_output))
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(outputs[input]).encode(), stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return add, calls


def test_all_match_returns_zero(tree, capsys):
    add, calls = tree
    add("alpha", "hand", verdict(True, "", 99, lim={"x": 1}), verdict(True, "", 99), {"broken": True})
    add("beta", "abuse", verdict(False, "oom", 7), verdict(False, "oom", 7), {"broken": False, "err": "oom"})
    add("gamma", "real", verdict(True, "", 5), verdict(True, "", 5), None)
    assert corpus_check.main() == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("OK   hand") and "BROKEN" in out[0] and "gas     99" in out[0]
    assert "refused (oom)" in out[1] and out[1].startswith("OK   abuse")
    assert out[-1] == "corpus: 3 OK · 0 FAIL · 3 items under wasmtime"
    assert [c[0] for c in calls] == [["wasmtime", "run", os.path.join(corpus_check.ROOT, "verifier.wasm")]] * 3
    assert calls[0][1] == b"alpha" and calls[0][2] is True


def test_refused_without_error_text(tree, capsys):
    add, _ = tree
    add("quiet", "hand", verdict(False, ""), verdict(False, ""), None)
    assert corpus_check.main() == 0
    assert "refused (no invariant broken)" in capsys.readouterr().out


def test_golden_mismatch_fails(tree, capsys):
    add, _ = tree
    add("drift", "hand", verdict(True, "", 10), verdict(True, "", 11), None)
    assert corpus_check.main() == 1
    out = capsys.readouterr().out
    assert out.startswith("FAIL") and "verdict != golden" in out
    assert out.strip().endswith("corpus: 0 OK · 1 FAIL · 1 items under wasmtime")


def test_designed_broken_mismatch(tree, capsys):
    add, _ = tree
    v = verdict(True, "")
    add("wrongdesign", "hand", v, v, {"broken": False})
    assert corpus_check.main() == 1
    out = capsys.readouterr().out
    assert "designed {'broken': False}" in out and "verdict != golden" not in out


def test_designed_err_mismatch_and_both_failures(tree, capsys):
    add, _ = tree
    add("errdiff", "abuse", verdict(False, "oom"), verdict(False, "oom"), {"broken": False, "err": "fuel"})
    add("both", "hand", verdict(True, ""), verdict(False, ""), {"broken": False})
    assert corpus_check.main() == 1
    out = capsys.readouterr().out
    assert "designed {'broken': False, 'err': 'fuel'}" in out
    assert "verdict != golden; designed {'broken': False}" in out
    assert out.strip().endswith("corpus: 0 OK · 2 FAIL · 2 items under wasmtime")


def test_main_entrypoint_on_real_corpus(monkeypatch):
    """Run the script as __main__ against the committed corpus with wasmtime replaced by the golden verdicts."""
    root = corpus_check.ROOT
    gold_root = os.path.join(root, "verifier", "tests", "golden")
    items = json.load(open(os.path.join(root, "corpus", "manifest.json")))["items"]
    by_vec = {}
    for it in items:
        g = os.path.join(gold_root, "corpus" if it["category"] != "abuse" else "", it["name"] + ".json")
        by_vec[open(os.path.join(root, it["vector"]), "rb").read()] = json.dumps({**json.load(open(g)), "lim": {}})

    def fake_run(cmd, input=None, capture_output=None):
        return subprocess.CompletedProcess(cmd, 0, stdout=by_vec[input].encode(), stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SystemExit) as e:
        runpy.run_path(SCRIPT, run_name="__main__")
    assert e.value.code == 0
