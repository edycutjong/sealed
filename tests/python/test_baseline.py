"""Unit tests for scripts/baseline.py: prompt building, verdict parsing, providers, record and show."""
import json
import os
import runpy
import subprocess
import sys
import types

import pytest

import baseline


def manifest_items(root):
    return json.load(open(os.path.join(root, "corpus", "manifest.json")))["items"]


# ---------- parse_verdict ----------
@pytest.mark.parametrize("reply,want", [
    ("VERDICT: PAY\nREASON: ok", "PAY"),
    ("verdict: refuse\nREASON: no", "REFUSE"),
    ("no verdict here", None),
    ("VERDICT: PAY or REFUSE", None),
    ("VERDICT: REFUSE\nthinking...\nVERDICT: PAY", "PAY"),
    ("VERDICT: maybe", None),
])
def test_parse_verdict(reply, want):
    assert baseline.parse_verdict(reply) == want


# ---------- corpus loading ----------
def test_claims_keys_and_content(root):
    c = baseline.claims()
    assert c and all(k.startswith("llm-") for k in c)
    assert all(v.strip() and "```" not in v for v in c.values())


def test_load_items_matches_manifest(root):
    items = baseline.load_items()
    assert [i["name"] for i in items] == [m["name"] for m in manifest_items(root)]
    for i in items:
        assert isinstance(i["broken"], bool)
        assert i["invariant_id"] in baseline.GOAL
        assert i["level"] in baseline.SOURCE
    claimed = baseline.claims()
    assert all((i["claim"] == claimed.get(i["name"])) for i in items)


def test_build_prompt_with_and_without_claim(root):
    items = baseline.load_items()
    with_claim = next(i for i in items if i["claim"])
    p = baseline.build_prompt(with_claim)
    assert "Hunter's claim: " + with_claim["claim"] in p
    assert baseline.GOAL[with_claim["invariant_id"]] in p
    assert with_claim["exploit"] in p
    assert baseline.SOURCE[with_claim["level"]] in p
    no_claim = dict(with_claim, claim=None)
    p2 = baseline.build_prompt(no_claim)
    assert "Hunter's claim" not in p2
    assert "### Hunter's submission\nTransactions" in p2


# ---------- _openai / provider ----------
class FakeResp:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, *a):
        return json.dumps(self.payload).encode()


def test_openai_request(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["req"], seen["timeout"] = req, timeout
        return FakeResp({"choices": [{"message": {"content": "VERDICT: PAY"}}]})

    monkeypatch.setattr(baseline.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("EXTRA_BODY", '{"reasoning": false}')
    out = baseline._openai("http://x/v1/", "KEY", "m1", "hello")
    assert out == "VERDICT: PAY"
    req = seen["req"]
    assert req.full_url == "http://x/v1/chat/completions"
    assert req.get_header("Authorization") == "Bearer KEY"
    body = json.loads(req.data)
    assert body["model"] == "m1" and body["temperature"] == 0 and body["reasoning"] is False
    assert body["messages"] == [{"role": "user", "content": "hello"}]
    assert seen["timeout"] == 300
    monkeypatch.setenv("BASELINE_TIMEOUT", "900")
    baseline._openai("http://x", "k", "m", "p")
    assert seen["timeout"] == 900


def args(**kw):
    d = dict(provider="nearai", model="m", cmd=None, only=None, jobs=1)
    d.update(kw)
    return types.SimpleNamespace(**d)


def test_provider_nearai(monkeypatch, tmp_path):
    keyf = tmp_path / "api.key"
    keyf.write_text("  secret\n")
    monkeypatch.setattr(baseline.os.path, "expanduser", lambda p: str(keyf))
    calls = []
    monkeypatch.setattr(baseline, "_openai", lambda *a: calls.append(a) or "reply")
    assert baseline.provider(args())("P") == "reply"
    assert calls == [("https://cloud-api.near.ai/v1", "secret", "m", "P")]


def test_provider_openai_env(monkeypatch):
    monkeypatch.setenv("BASE_URL", "http://b")
    monkeypatch.setenv("API_KEY", "k")
    calls = []
    monkeypatch.setattr(baseline, "_openai", lambda *a: calls.append(a) or "r")
    assert baseline.provider(args(provider="openai"))("P") == "r"
    assert calls == [("http://b", "k", "m", "P")]


def test_provider_cmd(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        return subprocess.CompletedProcess(cmd, 0, stdout=b"VERDICT: REFUSE")

    monkeypatch.setattr(baseline.subprocess, "run", fake_run)
    out = baseline.provider(args(provider="cmd", cmd="mymodel"))("PROMPT")
    assert out == "VERDICT: REFUSE"
    assert seen["cmd"] == "mymodel" and seen["kw"]["input"] == b"PROMPT"
    assert seen["kw"]["shell"] is True and seen["kw"]["check"] is True


def test_provider_unknown():
    with pytest.raises(SystemExit) as e:
        baseline.provider(args(provider="bogus"))
    assert "unknown provider bogus" in str(e.value)


# ---------- tally ----------
def test_tally():
    run = {"models": {"m": {"verdicts": {"a": "PAY", "b": "REFUSE", "c": None, "d": "PAY"}}},
           "truth": {"a": {"broken": False}, "b": {"broken": True}, "c": {"broken": False},
                     "d": {"broken": True}}}
    fakes, real, pay, no_reply = baseline.tally(run, "m")
    assert fakes == ["a", "c"] and real == ["b", "d"]
    assert pay(fakes) == ["a"] and pay(real) == ["d"]
    assert no_reply == ["c"]


# ---------- show ----------
def make_world(tmp_path, monkeypatch, verdicts, transcripts, results_runs):
    out = tmp_path / "baseline"
    (out / "transcripts" / "mod").mkdir(parents=True)
    (tmp_path / "corpus").mkdir()
    (tmp_path / "corpus" / "results.json").write_text(json.dumps({"runs": results_runs}))
    truth = {"f1": {"category": "abuse", "broken": False}, "f2": {"category": "llm", "broken": False},
             "llm-x-a": {"category": "llm", "broken": False}, "r1": {"category": "seed", "broken": True},
             "f3": {"category": "d3", "broken": False}}
    run = {"v": 1, "models": {"mod": {"provider": "cmd", "recorded": "2026-01-01", "verdicts": verdicts}},
           "truth": truth}
    (out / "run.json").write_text(json.dumps(run))
    for n, txt in transcripts.items():
        (out / "transcripts" / "mod" / (n + ".txt")).write_text(txt)
    monkeypatch.setattr(baseline, "OUT", str(out))
    monkeypatch.setattr(baseline, "ROOT", str(tmp_path))


def test_show_missing_run(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline, "OUT", str(tmp_path))
    with pytest.raises(SystemExit) as e:
        baseline.show()
    assert "run.json missing" in str(e.value)


def test_show_synthetic_all_branches(tmp_path, monkeypatch, capsys):
    verdicts = {"f1": "PAY", "f2": None, "llm-x-a": "PAY", "r1": "REFUSE", "f3": None}
    transcripts = {"f1": "VERDICT: PAY", "f2": "[no reply after 3 tries: HTTPError: 403 forbidden]\n",
                   "llm-x-a": "VERDICT: PAY", "r1": "VERDICT: REFUSE", "f3": "rambling without verdict"}
    runs = [{"item": n, "category": truth_cat} for n, truth_cat in
            [("f1", "abuse"), ("f2", "llm"), ("llm-x-a", "llm"), ("f3", "d3")]]
    make_world(tmp_path, monkeypatch, verdicts, transcripts, runs)
    baseline.show()
    out = capsys.readouterr().out
    assert "integrity: 5/5 recorded verdicts" in out
    assert "MISMATCH" not in out
    assert "mod  [cmd, recorded 2026-01-01]" in out
    assert "would pay 2 of 3 fakes" in out
    assert "over all 4 non-breaking corpus items: pays 2; of the 1 submissions that really break a level it would pay 0 and refuse 1" in out
    assert "fakes paid by category: abuse 1, llm 1" in out
    assert "1 of the 3 fakes carry a hunter claim" in out
    assert "unanswered, counted as NOT paying (fake): f2 — [no reply after 3 tries: HTTPError: 403 forbidden]" in out
    assert "DashScope's free quota" in out
    assert "reply had no VERDICT line" in out
    assert "make replay" in out


def test_show_mismatch_and_only(tmp_path, monkeypatch, capsys):
    verdicts = {"f1": "PAY", "r1": None, "f2": "REFUSE"}
    transcripts = {"f1": "VERDICT: REFUSE", "r1": ""}  # f2 transcript missing; r1 empty transcript
    make_world(tmp_path, monkeypatch, verdicts, transcripts, [])
    baseline.show("mod")
    out = capsys.readouterr().out
    assert "integrity: 1/3" in out
    assert "MISMATCH: mod/f1, mod/f2" in out
    assert "fakes paid by category" in out
    assert "unanswered, counted as NOT paying (real exploit): r1 — reply had no VERDICT line" in out


def test_show_committed_run(root, capsys):
    baseline.show()
    out = capsys.readouterr().out
    assert "integrity:" in out and "MISMATCH" not in out
    assert "LLM-only triage" in out


# ---------- record ----------
def fake_items():
    return [{"name": n, "category": "abuse", "broken": b, "level": "Force", "invariant_id": "force-balance-nonzero",
             "instance": "0x1", "exploit": "[]", "claim": None} for n, b in [("a", False), ("b", True), ("c", False)]]


def rec_args(**kw):
    return args(provider="cmd", model="mod", only=None, jobs=2, **kw)


@pytest.fixture
def rec_env(tmp_path, monkeypatch):
    out = tmp_path / "baseline"
    out.mkdir()
    monkeypatch.setattr(baseline, "OUT", str(out))
    monkeypatch.setattr(baseline, "load_items", fake_items)
    monkeypatch.setattr(baseline, "build_prompt", lambda it: "P:" + it["name"])
    monkeypatch.setattr(baseline.time, "sleep", lambda s: None)
    shown = []
    monkeypatch.setattr(baseline, "show", lambda m=None: shown.append(m))
    return out, shown


def test_record_fresh_with_retry_and_failure(rec_env, monkeypatch, capsys):
    out, shown = rec_env
    attempts = {"a": 0, "c": 0}

    def call(p):
        n = p[2:]
        if n == "b":
            return "VERDICT: PAY\nREASON: x"
        if n == "a":
            attempts["a"] += 1
            if attempts["a"] < 2:
                raise ValueError("boom")
            return "VERDICT: REFUSE"
        attempts["c"] += 1
        raise RuntimeError("x" * 500)

    monkeypatch.setattr(baseline, "provider", lambda a: call)
    baseline.record(rec_args())
    assert attempts == {"a": 2, "c": 3}
    run = json.load(open(out / "run.json"))
    m = run["models"]["mod"]
    assert m["provider"] == "cmd" and m["verdicts"] == {"a": "REFUSE", "b": "PAY", "c": None}
    assert run["truth"]["b"] == {"category": "abuse", "broken": True}
    tdir = out / "transcripts" / "mod"
    assert (tdir / "b.txt").read_text() == "VERDICT: PAY\nREASON: x"
    c_txt = (tdir / "c.txt").read_text()
    assert c_txt.startswith("[no reply after 3 tries: RuntimeError: xxx") and len(c_txt) < 300
    assert "mod: 2/3 answered" in capsys.readouterr().err
    assert shown == ["mod"]


def test_record_only_merges_existing(rec_env, monkeypatch):
    out, shown = rec_env
    (out / "run.json").write_text(json.dumps(
        {"v": 1, "models": {"mod": {"provider": "cmd", "verdicts": {"a": "PAY", "z": "REFUSE"}}}}))
    monkeypatch.setattr(baseline, "provider", lambda a: (lambda p: "VERDICT: REFUSE"))
    baseline.record(args(provider="cmd", model="mod", only=["a"], jobs=1))
    run = json.load(open(out / "run.json"))
    assert run["models"]["mod"]["verdicts"] == {"a": "REFUSE", "z": "REFUSE"}
    assert not (out / "transcripts" / "mod" / "b.txt").exists()
    assert set(run["truth"]) == {"a", "b", "c"}


# ---------- main ----------
def run_main(monkeypatch, *argv):
    monkeypatch.setattr(sys, "argv", ["baseline.py", *argv])
    return baseline.main()


def test_main_show(monkeypatch):
    called = []
    monkeypatch.setattr(baseline, "show", lambda: called.append(1) or "shown")
    assert run_main(monkeypatch, "show") == "shown" and called


def test_main_prompt(monkeypatch, capsys, root):
    name = manifest_items(root)[0]["name"]
    run_main(monkeypatch, "prompt", name)
    out = capsys.readouterr().out
    assert "You are the triager" in out and out.rstrip().endswith("REASON: <at most 40 words>")


def test_main_prompt_unknown_item(monkeypatch):
    with pytest.raises(StopIteration):
        run_main(monkeypatch, "prompt", "no-such-item")


def test_main_record_requires_model(monkeypatch):
    with pytest.raises(SystemExit) as e:
        run_main(monkeypatch, "record")
    assert "record needs --model" in str(e.value)


def test_main_record_dispatch(monkeypatch):
    got = []
    monkeypatch.setattr(baseline, "record", got.append)
    run_main(monkeypatch, "record", "--model", "mm", "--provider", "cmd", "--cmd", "cat", "--only", "a", "b", "--jobs", "2")
    a = got[0]
    assert (a.model, a.provider, a.cmd, a.only, a.jobs) == ("mm", "cmd", "cat", ["a", "b"], 2)


def test_dunder_main(monkeypatch, capsys, root):
    name = manifest_items(root)[0]["name"]
    monkeypatch.setattr(sys, "argv", ["baseline.py", "prompt", name])
    runpy.run_path(os.path.join(root, "scripts", "baseline.py"), run_name="__main__")
    assert "You are the triager" in capsys.readouterr().out
