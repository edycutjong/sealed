# Contributing

```bash
make doctor        # python3, wasmtime, pinned verifier hash, archival RPC
make replay        # re-run every published commit offline (wasmtime + python3)
make test          # Python unit + verifier golden + contract unit + near-workspaces (pip: pytest pytest-cov pynacl base58; Rust 1.97.1 and 1.85.0)
python3 scripts/check_submission_readiness.py
```

`verifier.wasm` is the pinned artifact: every bounty fixes its sha256. Change `verifier/` only together with
`make verifier-wasm`, the golden vectors (`UPDATE_GOLDEN=1`) and an updated `verifier.wasm.sha256`;
`make verifier-check` fails on any drift. Comment-only edits change the bytes too, so treat them the same way.
