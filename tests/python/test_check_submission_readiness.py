"""Unit tests for scripts/check_submission_readiness.py (tmp-dir fixtures, git mocked)."""
import hashlib
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import check_submission_readiness as csr


def test_rel_inside_and_outside_root(tmp_path, monkeypatch):
    monkeypatch.setattr(csr, "ROOT", tmp_path)
    assert csr.rel(tmp_path / "a" / "b.md") == Path("a/b.md")
    other = Path("/somewhere/else.md")
    assert csr.rel(other) == other


def test_scan_flags_placeholders_and_dead_links(tmp_path, monkeypatch):
    monkeypatch.setattr(csr, "ROOT", tmp_path)
    (tmp_path / "real.md").write_text("x")
    f = tmp_path / "README.md"
    f.write_text(
        "clean line\n"
        "TODO fix this\n"
        "[ok](real.md) [dead](nope.md) [web](https://a.b) [anchor](#x)\n"
    )
    problems = []
    csr.scan(f, problems)
    assert problems == [
        "README.md:2: placeholder `TODO`",
        "README.md:3: dead relative link `nope.md`",
    ]


def test_scan_fenced_blocks(tmp_path, monkeypatch):
    monkeypatch.setattr(csr, "ROOT", tmp_path)
    f = tmp_path / "a.md"
    f.write_text(
        "```\n"
        "curl http://localhost:8080\n"      # flagged: exemption only matches a literal `https?://`
        "TBD in fence\n"                     # still flagged
        "[x](missing.md)\n"                  # links ignored in fence
        "```\n"
        "see http://localhost:1\n"           # flagged outside fence
    )
    problems = []
    csr.scan(f, problems)
    assert problems == [
        "a.md:2: placeholder `http://localhost`",
        "a.md:3: placeholder `TBD`",
        "a.md:6: placeholder `http://localhost`",
    ]


def test_scan_non_markdown_skips_links(tmp_path, monkeypatch):
    monkeypatch.setattr(csr, "ROOT", tmp_path)
    f = tmp_path / "note.txt"
    f.write_text("[x](missing.md)\n")
    problems = []
    csr.scan(f, problems)
    assert problems == []


@pytest.mark.parametrize("name,hit", [
    ("specs/a.md", True), ("x/audit/y", True), ("progress.md", True),
    ("HUMAN-TODO", True), ("CLAUDE.md", True), ("a/AGENTS.md", True),
    (".claude/x", True), ("prod.env", True), ("k.pem", True), ("s.key", True),
    ("src/lib.rs", False), ("README.md", False),
])
def test_kitchen_regex(name, hit):
    assert bool(csr.KITCHEN.search(name)) is hit


def _setup_root(tmp_path, monkeypatch, tracked, hash_ok=True, readme="ok\n"):
    monkeypatch.setattr(csr, "ROOT", tmp_path)
    (tmp_path / "verifier.wasm").write_bytes(b"wasm")
    digest = hashlib.sha256(b"wasm").hexdigest() if hash_ok else "a" * 64
    (tmp_path / "verifier.wasm.sha256").write_text(digest + "  verifier.wasm\n")
    if readme is not None:
        (tmp_path / "README.md").write_text(readme)
        (tmp_path / "DEMO.md").write_text("demo\n")
        (tmp_path / "ARCHITECTURE.md").write_text("arch\n")
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=tracked)
    )
    monkeypatch.setattr(sys, "argv", ["check_submission_readiness.py"])


def test_main_ok(tmp_path, monkeypatch, capsys):
    _setup_root(tmp_path, monkeypatch, "README.md\nsrc/a.rs\n")
    (tmp_path / "SECURITY.md").write_text("fine\n")  # optional prose exists
    assert csr.main() == 0
    assert capsys.readouterr().out == "readiness: OK (0 finding(s))\n"


def test_main_failures(tmp_path, monkeypatch, capsys):
    _setup_root(tmp_path, monkeypatch, "CLAUDE.md\nsrc/a.rs\n", hash_ok=False, readme=None)
    (tmp_path / "SECURITY.md").write_text("FIXME\n")
    extra = tmp_path / "extra.txt"
    extra.write_text("lorem ipsum\n")
    monkeypatch.setattr(sys, "argv", ["x", str(extra)])
    assert csr.main() == 1
    out = capsys.readouterr().out.splitlines()
    assert "README.md: missing" in out
    assert "DEMO.md: missing" in out
    assert "ARCHITECTURE.md: missing" in out
    assert "docs/DX-REPORT.md: missing" not in out
    assert "SECURITY.md:1: placeholder `FIXME`" in out
    assert "extra.txt:1: placeholder `lorem ipsum`" in out
    assert "CLAUDE.md: kitchen/secret-shaped file is tracked" in out
    assert f"verifier.wasm.sha256 {'a' * 12}… != committed verifier.wasm " \
           f"{hashlib.sha256(b'wasm').hexdigest()[:12]}…" in out
    assert out[-1] == "readiness: FAIL (7 finding(s))"


def test_script_entrypoint_exits_with_main_status(tmp_path, monkeypatch):
    # run_path re-executes the module with ROOT derived from its real location; mock git + argv.
    monkeypatch.setattr(sys, "argv", ["check_submission_readiness.py"])
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=""))
    script = Path(csr.__file__)
    with pytest.raises(SystemExit) as e:
        runpy.run_path(str(script), run_name="__main__")
    assert e.value.code in (0, 1)
