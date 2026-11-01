# Demo

Everything here runs from a fresh clone with `python3` and `wasmtime`; no NEAR account or key. Testnet only.

## 1. One real exploit pays (offline, seconds)

```bash
make replay
```

Expect 29 `OK` rows. Each row re-runs a published commit under wasmtime from the committed verifier wasm its bounty pinned
and prints `factory.validateInstance(instance, player)`: `1` for a real exploit, `0` for a fake. The same verdict is on
chain.

The paid fallback exploit on the demo bounty, in order:
[commit](https://testnet.nearblocks.io/txns/FNbCUc53YNayqd6NBqaaxnZTeGAVGABHfPsoHz7Gkc2s) (14.6 s to verdict) →
[worker verdict](https://testnet.nearblocks.io/txns/2vdtrvQmZmpt4NGfAD2FyBQy9d5PjLR4dEJuQCF8MXTX) →
[deliver](https://testnet.nearblocks.io/txns/AodmFQ6tq4pBcxLreRDSCanKkZQY7m6nhM459NfPAg3s) (6.3 s to PAID). Timings are from
`corpus/results.json` (`timing_s`).

## 2. A fake is refused with a reason

[`fake`](https://testnet.nearblocks.io/txns/DUtubHScU3udGH58UxdTHWjwvDBjsHCsrupmBMxVYZiy): `REFUSED 2 no invariant broken`,
bond slashed. All six refusal kinds, each with its tx hash:

```bash
make refusals
```

## 3. Prove the payouts from chain data

```bash
make verify-demo   # 5 paid demo-bounty runs, ~25 archival RPC calls, ~1.5 min
make verify        # all 29 runs, ~80 calls; exit 2 = RPC unreachable, not a failed check
```

Per run it checks: the pinned verifier hash, the OutLayer worker key, the verdict, `h_enc`, and PAID for that commit id;
that every commit on chain is bundled; and that the bounty's paid and escrow totals match.

## 4. The numbers

```bash
make corpus     # 52 items vs golden verdicts: real exploits 5 of 5 paid, submitted fakes 0 of 21 paid
make bench      # request→verdict p50 7.27 s, p95 10.85 s (29 runs); heaviest fake 23.98% of the instruction limit
make baseline   # what LLM-only triage would pay (not NEAR AI Cloud models; see baseline/README.md)
```

LLM-only triage paid 1, 3 and 3 of the 21 fakes (muse-wonder-1.0, nemotron-3-ultra, qwen3.8-omni-flash). The verifier paid 0.

## Limits

Testnet only; the mainnet leg is prepared, not run. `make verify` trusts the archival RPC it queries and does not prove
the worker ran exactly the pinned bytes (`make replay` re-runs them locally). Full list: README "Honest limits" and
[ARCHITECTURE.md § Limits](ARCHITECTURE.md#limits).
