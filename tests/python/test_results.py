"""Unit tests for scripts/results.py, run against a synthetic corpus tree under tmp_path."""
import json
import os
import runpy

import pytest

import results


def w(root, rel, obj):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        json.dump(obj, f)


def verdict(broken=False, err=None, gas=10, lim=None):
    return {"broken": broken, "err": err, "gas_used": gas, "lim": lim}


def evidence(chain, instr=100, time_ms=50, resolve=True):
    ev = {"commit_tx": "c", "request_id": 7, "deliver_tx": "d",
          "verdict_output": json.dumps(chain) if chain is not None and instr % 2 == 0 else chain}
    if resolve:
        ev["resolve"] = {"tx": "r"}
    if instr is not None:
        ev["execution_completed"] = [{"data": [{"resources_used": {"instructions": instr, "time_ms": time_ms}}]}]
    return ev


def pub(label, name, status="Paid", bounty="demo.x"):
    return {"label": label, "bounty": bounty, "exploit_name": "corpus:" + name, "input": {"invariant_id": "inv"},
            "final_status": status, "timing_s": 1.5}


@pytest.fixture
def tree(tmp_path, monkeypatch):
    r = str(tmp_path)
    monkeypatch.setattr(results, "ROOT", r)
    return r


def build_full(r):
    items = [
        {"name": "real1", "category": "real", "level": "L1", "expect": {"broken": True}},
        {"name": "fake1", "category": "fake", "level": "L2", "expect": {"broken": False}},
        {"name": "llm1", "category": "llm", "level": "L3", "expect": None},
        {"name": "llm2", "category": "llm", "level": "L3", "expect": None},
        {"name": "ab1", "category": "abuse", "level": "L4", "expect": None},
        {"name": "ab2", "category": "abuse", "level": "L4", "expect": None},
        {"name": "brk", "category": "d4", "level": "L5", "expect": None},
        {"name": "oth", "category": "d4", "level": "L5", "expect": None},
    ]
    w(r, "corpus/manifest.json", {"items": items})
    w(r, "corpus/published/a.json", pub("d5-real1", "real1"))
    w(r, "corpus/published/b.json", pub("d5-fake1", "fake1", {"Refused": "x"}, "other.y"))
    w(r, "corpus/published/c.json", pub("d5-llm1", "llm1", "Paid"))
    w(r, "corpus/published/d.json", pub("d3-unk", "unknown", "Paid"))
    w(r, "corpus/published/e.json", pub("d5-nochain", "oth", "Refused"))
    w(r, "corpus/evidence/d5-real1.json", evidence(verdict(True, "e", 5, {"mem": 1048576, "m": 4, "i": 1}), 100, 500))
    w(r, "corpus/evidence/d5-fake1.json", evidence(verdict(False, None, 3), 200, 100))
    w(r, "corpus/evidence/d5-llm1.json", evidence(verdict(False, None, 4), 50, 10))
    w(r, "corpus/evidence/d3-unk.json", evidence(verdict(False, None, 9), 7, 1, resolve=False))
    w(r, "corpus/evidence/d5-nochain.json", {"commit_tx": "c2"})
    # goldens: fake1 mismatches (gas 99), real1 matches via corpus/, ab1 via root dir
    w(r, "verifier/tests/golden/corpus/real1.json", {"broken": True, "err": "e", "gas_used": 5})
    w(r, "verifier/tests/golden/corpus/fake1.json", {"broken": False, "err": None, "gas_used": 99})
    w(r, "verifier/tests/golden/corpus/llm2.json", {"broken": True, "err": None, "gas_used": 1})
    w(r, "verifier/tests/golden/brk.json", {"broken": True, "err": None, "gas_used": 1})
    w(r, "day0/results/g6-ab1.json", {})
    w(r, "corpus/refusals.json", {"refusals": [{"kind": "a", "matched": True}, {"kind": "b", "matched": False},
                                                 {"kind": "a", "matched": True}]})
    cfg = {"max_instructions": 1000, "max_memory_mb": 4, "max_execution_seconds": 2,
           "invariants": [{"id": "i1"}], "deliver_ttl_ns": 5, "verifier_wasm_hash": "h"}
    w(r, "contracts/results/d5-one.json", {"bounty_account": "demo.x", "create_tx": "t", "global_hash": "g",
                                           "access_keys": [1, 2], "config": cfg})
    w(r, "contracts/results/d5-two.json", {"bounty_account": "demo.y", "config": cfg})


def test_helpers(tree):
    w(tree, "verifier/tests/golden/corpus/a.json", {"x": 1})
    w(tree, "verifier/tests/golden/b.json", {"x": 2})
    assert results.golden_of("a") == {"x": 1}
    assert results.golden_of("b") == {"x": 2}
    assert results.golden_of("zzz") is None
    assert results.load("verifier/tests/golden/b.json") == {"x": 2}
    assert results.status("Paid") == "Paid"
    assert results.status({"Refused": "why"}) == "Refused"


def test_main_full(tree, capsys):
    build_full(tree)
    assert results.main() == 1
    printed = json.loads(capsys.readouterr().out)
    out = json.load(open(os.path.join(tree, "corpus", "results.json")))
    assert out["summary"] == printed
    s = printed
    assert s["golden_mismatches"] == ["d5-fake1"]
    assert s["runs"] == 5
    assert s["real_paid_demo_bounty"] == "1 of 1"
    assert s["submitted_non_breaking_refused"] == "1 of 2"
    assert s["submitted_non_breaking_paid"] == "1 of 2"
    assert s["llm_written"] == 2
    assert s["llm_really_break_wasmtime"] == 1
    assert s["llm_submitted_on_chain"] == 1
    assert s["llm_paid_on_chain"] == 1
    assert s["refusal_kinds_on_chain"] == "1 of 6"
    assert s["requested_limits"] == {"max_instructions": 1000, "max_memory_mb": 4, "max_execution_seconds": 2}
    g = s["g5_heaviest_real"]
    assert g["run"] == "d5-real1" and g["instructions_pct_of_request"] == 10.0
    assert g["time_pct_of_request"] == 25.0
    assert g["verifier_peak_mem_bytes"] == 1048576 and g["mem_pct_of_enforced"] == 25.0
    assert s["g5_heaviest_fake"]["run"] == "d5-fake1"
    assert "verifier_peak_mem_bytes" not in s["g5_heaviest_fake"]
    assert s["corpus_items_on_chain"] == "4 of 8"
    assert set(out["bounties"]) == {"demo.x", "demo.y"}
    assert out["bounties"]["demo.x"]["access_keys"] == 2
    assert out["bounties"]["demo.y"]["access_keys"] == 0
    assert out["refusal_kinds"] == ["a"]
    rows = {r["label"]: r for r in out["runs"]}
    assert rows["d5-fake1"]["golden_mismatch"] is True
    assert rows["d5-real1"]["resolve_tx"] == "r"
    assert rows["d3-unk"]["category"] == "d3" and rows["d3-unk"]["resolve_tx"] is None
    assert rows["d5-nochain"]["chain_verdict"] is None
    assert rows["d5-nochain"]["instructions"] is None
    off = {o["item"]: o for o in out["off_chain"]}
    assert set(off) == {"fake1x", "llm2", "ab1", "ab2", "brk"} - {"fake1x"}
    assert "really breaks" in off["brk"]["reason"]
    assert "day0/results/g6-ab1.json" in off["ab1"]["reason"]
    assert off["ab2"]["reason"] == results.ABUSE_OFF_CHAIN
    assert "really breaks" in off["llm2"]["reason"]


def test_main_empty(tree, capsys):
    w(tree, "corpus/manifest.json", {"items": [{"name": "x", "category": "d4", "level": "L", "expect": None}]})
    os.makedirs(os.path.join(tree, "corpus", "published"))
    assert results.main() == 0
    s = json.loads(capsys.readouterr().out)
    assert s["runs"] == 0 and s["g5_heaviest_real"] is None and s["requested_limits"] is None
    out = json.load(open(os.path.join(tree, "corpus", "results.json")))
    assert out["refusals"] == []
    assert out["off_chain"][0]["reason"].startswith("not run on testnet")


def test_heaviest_without_limits(tree, capsys):
    w(tree, "corpus/manifest.json", {"items": [{"name": "r", "category": "real", "level": "L", "expect": None}]})
    w(tree, "corpus/published/a.json", pub("d5-r", "r"))
    w(tree, "corpus/evidence/d5-r.json", {"commit_tx": "c", "verdict_output": verdict(False, lim={"mem": 5})})
    assert results.main() == 0
    g = json.loads(capsys.readouterr().out)["g5_heaviest_real"]
    assert g == {"run": "d5-r", "instructions": None, "time_ms": None}


def test_main_guard(monkeypatch, capsys):
    import builtins
    real_open = builtins.open

    def safe_open(path, mode="r", *a, **k):  # never truncate the committed corpus/results.json
        return real_open(os.devnull if "w" in mode else path, mode, *a, **k)
    monkeypatch.setattr(builtins, "open", safe_open)
    dumped = []
    monkeypatch.setattr(json, "dump", lambda obj, f, **k: dumped.append(obj))
    with pytest.raises(SystemExit) as e:
        runpy.run_path(results.__file__, run_name="__main__")
    assert e.value.code in (0, 1)
    assert dumped and dumped[0]["v"] == 1
    assert json.loads(capsys.readouterr().out) == dumped[0]["summary"]
