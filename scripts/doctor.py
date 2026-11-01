#!/usr/bin/env python3
"""`make doctor`: check a fresh clone can run the judged targets. Needs nothing but python3 + wasmtime.

  replay / corpus   python3 ≥ 3.8 + wasmtime on PATH; verifier.wasm must hash to verifier.wasm.sha256
  verify / bench-chain   + a reachable archival RPC (no NEAR account, no keys — read-only JSON-RPC)
  refusals / results / bench / baseline   python3 only (read the committed evidence)
Rust (cargo, wasm32-wasip1) is only for `make verifier-check` / `make test`, never for replay or verify.
Exit 0 when replay + verify can run; 1 otherwise (each missing piece printed with its install line)."""
import hashlib, os, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "day0"))
import near  # noqa: E402


def check(ok, label, hint=""):
    print(f"{'OK  ' if ok else 'MISS'} {label}" + ("" if ok or not hint else f" — {hint}"))
    return ok


def main():
    rpc = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else near.ARCHIVAL
    good = check(sys.version_info >= (3, 8), f"python3 {sys.version.split()[0]} (≥ 3.8)", "install python ≥ 3.8")
    wt = shutil.which("wasmtime")
    ver = subprocess.run([wt, "--version"], capture_output=True, text=True).stdout.strip() if wt else ""
    good &= check(bool(wt), f"wasmtime on PATH ({ver or 'not found'})",
                  "`brew install wasmtime` or `curl https://wasmtime.dev/install.sh -sSf | bash`")
    want = open(os.path.join(ROOT, "verifier.wasm.sha256")).read().split()[0]
    got = hashlib.sha256(open(os.path.join(ROOT, "verifier.wasm"), "rb").read()).hexdigest()
    good &= check(got == want, f"verifier.wasm sha256 {got[:16]}… = verifier.wasm.sha256",
                  "the committed wasm was modified; `git checkout verifier.wasm`")
    try:
        net = "result" in near.rpc("status", [], rpc)
    except Exception:
        net = False
    good &= check(net, f"archival RPC reachable ({rpc})", "needed by `make verify` only; or pass RPC=<url>")
    check(bool(shutil.which("cargo")), "cargo (optional: only `make verifier-check` / `make test` rebuild from source)",
          "https://rustup.rs")
    print("no NEAR account or key is read by replay / verify / corpus / refusals / results / bench")
    print("doctor: ready" if good else "doctor: fix the MISS lines above")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
