"""Tests for scripts/site_check.py: offline page checks, local ref resolution, and mocked --live fetches."""
import runpy
import sys
from pathlib import Path

import pytest

import site_check

JUDGE_BODY = " ".join(site_check.JUDGE_MUST)


def page(title="Title", body=""):
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>"


@pytest.fixture
def docs(tmp_path, monkeypatch):
    d = tmp_path / "docs"
    (d / "pitch").mkdir(parents=True)
    (d / "judge").mkdir()
    (d / "app.css").write_text("x")
    (d / "index.html").write_text(page(body='<a href="/pitch/">p</a><a href="/app.css">c</a>'))
    (d / "pitch" / "index.html").write_text(page(body='<a href="../app.css">c</a><a href="#top">t</a>'))
    (d / "judge" / "index.html").write_text(page(body=JUDGE_BODY))
    monkeypatch.setattr(site_check, "DOCS", d)
    return d


def run(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["site_check.py", *args])
    code = site_check.main()
    return code, capsys.readouterr().out


class FakeResp:
    def __init__(self, body, status=200):
        self._body, self.status = body, status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body.encode()


def test_local_refs_skips_external_and_resolves(docs):
    html = ('<a href="https://x.io/a"></a><a href="mailto:a@b"></a><img src="data:abc">'
            '<a href="//cdn/x"></a><a href="/app.css"></a><a href="../app.css?v=1"></a>'
            '<a href="/pitch/"></a><a href="sub"></a>')
    refs = dict(site_check.local_refs(docs / "pitch" / "index.html", html))
    assert refs["/app.css"] == (docs / "app.css").resolve()
    assert refs["../app.css"] == (docs / "app.css").resolve()
    assert refs["/pitch/"] == (docs / "pitch" / "index.html").resolve()
    assert "https://x.io/a" not in refs and "//cdn/x" not in refs and "mailto:a@b" not in refs
    assert refs["sub"] == (docs / "pitch" / "sub").resolve()


def test_local_refs_directory_target(docs):
    refs = dict(site_check.local_refs(docs / "index.html", '<a href="pitch"></a>'))
    assert refs["pitch"] == (docs / "pitch" / "index.html").resolve()


def test_offline_ok(docs, monkeypatch, capsys):
    code, out = run(monkeypatch, capsys)
    assert code == 0
    assert "OK   docs/index.html" in out and "OK   docs/judge/index.html" in out
    assert "site: 3 pages · 0 failures" in out


def test_offline_failures(docs, monkeypatch, capsys):
    (docs / "pitch" / "index.html").unlink()
    (docs / "index.html").write_text(page(title="", body='<a href="/nope.css"></a>'))
    (docs / "judge" / "index.html").write_text(page(body="nothing"))
    code, out = run(monkeypatch, capsys)
    assert code == 1
    assert "FAIL missing docs/pitch/index.html" in out
    assert "FAIL docs/index.html: no <title>" in out
    assert "FAIL docs/index.html: broken local ref /nope.css" in out
    assert "FAIL /judge: missing '5 of 5'" in out
    assert "failures" in out and "0 failures" not in out


def test_live_ok(docs, monkeypatch, capsys):
    urls = []

    def fake_urlopen(req, timeout):
        urls.append((req.full_url, req.get_header("User-agent"), timeout))
        return FakeResp(JUDGE_BODY)

    monkeypatch.setattr(site_check.urllib.request, "urlopen", fake_urlopen)
    code, out = run(monkeypatch, capsys, "--live", "https://site.test/")
    assert code == 0
    assert [u[0] for u in urls] == ["https://site.test/", "https://site.test/pitch/", "https://site.test/judge/"]
    assert urls[0][1] == "sealed-ci-site-check"
    assert "LIVE 200 https://site.test/judge/" in out


def test_live_failures(docs, monkeypatch, capsys):
    def fake_urlopen(req, timeout):
        if req.full_url.endswith("/pitch/"):
            raise OSError("boom")
        if req.full_url.endswith("/judge/"):
            return FakeResp("no claim")
        return FakeResp("ok", status=500)

    monkeypatch.setattr(site_check.urllib.request, "urlopen", fake_urlopen)
    code, out = run(monkeypatch, capsys, "--live", "https://site.test")
    assert code == 1
    assert "FAIL https://site.test/pitch/: boom" in out
    assert "FAIL https://site.test/judge/: status 200 or claim missing" in out
    assert "FAIL https://site.test/: status 500 or claim missing" in out


def test_real_docs_dir_constant():
    assert site_check.DOCS.name == "docs"
    assert isinstance(site_check.DOCS, Path)


def test_main_guard(docs, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["site_check.py"])
    monkeypatch.setattr(Path, "resolve", lambda self: self)
    with pytest.raises(SystemExit) as e:
        runpy.run_path(site_check.__file__, run_name="__main__")
    assert e.value.code in (0, 1)
