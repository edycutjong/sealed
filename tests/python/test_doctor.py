"""Unit tests for scripts/doctor.py (`make doctor`): every external probe is mocked."""
import hashlib
import runpy
import subprocess
import sys

import pytest

import doctor


@pytest.fixture
def fake_root(tmp_path, monkeypatch):
    wasm = b"\x00asm-fake"
    (tmp_path / "verifier.wasm").write_bytes(wasm)
    (tmp_path / "verifier.wasm.sha256").write_text(hashlib.sha256(wasm).hexdigest() + "  verifier.wasm\n")
    monkeypatch.setattr(doctor, "ROOT", str(tmp_path))
    return tmp_path


def _env(monkeypatch, wasmtime="/bin/wasmtime", cargo="/bin/cargo", rpc=None):
    def which(name):
        return {"wasmtime": wasmtime, "cargo": cargo}.get(name)
    monkeypatch.setattr(doctor.shutil, "which", which)
    monkeypatch.setattr(doctor.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="wasmtime 30.0\n"))
    if rpc is None:
        rpc = lambda m, p, url: {"result": {}}  # noqa: E731
    monkeypatch.setattr(doctor.near, "rpc", rpc)


def test_check_ok_and_miss(capsys):
    assert doctor.check(True, "a", "hint") is True
    assert doctor.check(False, "b", "do x") is False
    assert doctor.check(False, "c") is False
    out = capsys.readouterr().out.splitlines()
    assert out == ["OK   a", "MISS b — do x", "MISS c"]


def test_main_all_good(fake_root, monkeypatch, capsys):
    seen = []
    _env(monkeypatch, rpc=lambda m, p, url: seen.append((m, url)) or {"result": {}})
    monkeypatch.setattr(sys, "argv", ["doctor.py"])
    assert doctor.main() == 0
    out = capsys.readouterr().out
    assert "wasmtime on PATH (wasmtime 30.0)" in out
    assert "doctor: ready" in out
    assert seen == [("status", doctor.near.ARCHIVAL)]


def test_main_custom_rpc_arg(fake_root, monkeypatch, capsys):
    seen = []
    _env(monkeypatch, rpc=lambda m, p, url: seen.append(url) or {"result": 1})
    monkeypatch.setattr(sys, "argv", ["doctor.py", "http://x.test"])
    assert doctor.main() == 0
    assert seen == ["http://x.test"]
    assert "http://x.test" in capsys.readouterr().out


def test_main_everything_missing(fake_root, monkeypatch, capsys):
    (fake_root / "verifier.wasm").write_bytes(b"tampered")

    def boom(*a):
        raise OSError("down")
    _env(monkeypatch, wasmtime=None, cargo=None, rpc=boom)
    monkeypatch.setattr(sys, "argv", ["doctor.py", ""])
    assert doctor.main() == 1
    out = capsys.readouterr().out
    assert "MISS wasmtime on PATH (not found)" in out
    assert "MISS verifier.wasm sha256" in out
    assert "MISS archival RPC reachable" in out
    assert "MISS cargo" in out
    assert "doctor: fix the MISS lines above" in out


def test_main_rpc_without_result_is_miss(fake_root, monkeypatch, capsys):
    _env(monkeypatch, rpc=lambda m, p, url: {"error": "x"})
    monkeypatch.setattr(sys, "argv", ["doctor.py"])
    assert doctor.main() == 1
    assert "MISS archival RPC reachable" in capsys.readouterr().out


def test_cargo_missing_is_optional(fake_root, monkeypatch, capsys):
    _env(monkeypatch, cargo=None)
    monkeypatch.setattr(sys, "argv", ["doctor.py"])
    assert doctor.main() == 0
    assert "MISS cargo" in capsys.readouterr().out


def test_dunder_main_exits_with_main_code(monkeypatch, capsys):
    import near
    import shutil
    monkeypatch.setattr(shutil, "which", lambda n: None)
    monkeypatch.setattr(near, "rpc", lambda m, p, url: (_ for _ in ()).throw(OSError("no net")))
    monkeypatch.setattr(sys, "argv", ["doctor.py"])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(doctor.__file__, run_name="__main__")
    assert e.value.code in (0, 1)
    assert "archival RPC reachable" in capsys.readouterr().out
