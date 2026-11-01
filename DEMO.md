# Demo

Everything here runs from a fresh clone with `python3` and `wasmtime` (`make open` also needs PyNaCl); no NEAR account
or key. Testnet only.

## 1. Re-run a real exploit offline, then check its recorded payout

```bash
make replay
```

Expect 29 `OK` rows. Each row re-runs a published commit under wasmtime from the committed verifier wasm its bounty pinned
and prints `factory.validateInstance(instance, player)`: `1` for a real exploit, `0` for a fake. The same verdict is on
chain.

The paid fallback exploit on the demo bounty, in order:
[commit](https://testnet.nearblocks.io/txns/FNbCUc53YNayqd6NBqaaxnZTeGAVGABHfPsoHz7Gkc2s) (14.6 s client wall-clock to verdict, 8.5 s on chain block time) →
[worker verdict](https://testnet.nearblocks.io/txns/2vdtrvQmZmpt4NGfAD2FyBQy9d5PjLR4dEJuQCF8MXTX) →
[deliver](https://testnet.nearblocks.io/txns/AodmFQ6tq4pBcxLreRDSCanKkZQY7m6nhM459NfPAg3s) (6.3 s client wall-clock to PAID, 1.8 s on chain). Wall-clock is `corpus/results.json` `timing_s` (3 s polling, approximate);
block time is `corpus/bench.json` `chain.rows`.

## 2. A fake is refused with a reason

[`fake`](https://testnet.nearblocks.io/txns/DUtubHScU3udGH58UxdTHWjwvDBjsHCsrupmBMxVYZiy): `REFUSED 2 no invariant broken`,
bond slashed. All six refusal kinds, each with its tx hash:

```bash
make refusals
```

## 3. Prove the payouts from chain data

```bash
make verify-demo   # 5 paid demo-bounty runs, about 25 archival RPC calls, about 1.5 min
make verify        # all 29 runs, about 80 calls; make prints Error 2 = RPC unreachable, Error 1 = a failed check
make open          # offline: all 6 paid deliveries open to the exploit `make replay` re-runs (needs PyNaCl)
```

Per run it checks: the pinned verifier hash, the operator's scoped OutLayer worker key, the verdict, `h_enc`, and PAID
for that commit id; that every commit on chain is bundled; and that the bounty's paid and escrow totals match.
`verify-demo` also fails unless the demo bounty has 0 access keys, runs the committed `contracts/bounty.wasm`, and its
create tx added no key. `make open` checks what the protocol received: for each paid run in `corpus/results.json`, the
verdict says broken for this commit, the bounty logged AWARDED, DELIVERED and PAID for it, and the delivered box (the
one the protocol opens with its own key) opens with the hunter's ephemeral key, published after payment, which gives
the same shared secret, to the replayed exploit, which hashes to the commit.

## 4. The numbers

```bash
make corpus     # 52 items re-run offline under wasmtime vs their golden verdicts: "corpus: 52 OK · 0 FAIL"
make bench      # request→verdict p50 7.27 s, p95 10.85 s (29 runs); heaviest fake 23.98% of the instruction limit
make baseline   # what LLM-only triage would pay (not NEAR AI Cloud models; see baseline/README.md)
```

LLM-only triage would pay 1, 3 and 3 of the 21 fakes (three text-only models, one run each, no code execution: muse-wonder-1.0,
nemotron-3-ultra, qwen3.8-omni-flash) and 12, 12 and 11 of the 15 real exploits. The executing verifier paid 0 of the 21 fakes and 5 of 5 real exploits on the demo bounty.

## Limits

Testnet only; the mainnet leg is prepared, not run. `make verify` trusts the archival RPC it queries and does not prove
the worker ran exactly the pinned bytes (`make replay` re-runs them locally). Full list: README "Honest limits" and
[ARCHITECTURE.md § Limits](ARCHITECTURE.md#limits).
