#!/usr/bin/env python3
"""Worst-case fakes for G5b (TEST VECTORS). Each must come back as a normal verdict, never a worker error.

abuse-loop.json    4 × CREATE whose initcode is `JUMPDEST PUSH0 JUMP` (burns the full 30 M gas each)
abuse-create.json  4 × CREATE of a self-replicating initcode (each level CODECOPYs itself and CREATEs a child)
abuse-mem.json     4 × CREATE whose initcode MSTOREs at a 1 KB-stepping offset until out of gas
abuse-sstore.json  4 × CREATE whose initcode writes fresh storage slots until out of gas
abuse-input.json   1 tx carrying exactly 24 KB of calldata to the instance
abuse-over.json    5 txs (over the tx cap) → `exploit invalid`
abuse-big.json     24 KB + 1 byte of calldata → `exploit invalid`
Added after the first NEAR-mode run (instructions per gas measured with wasmtime fuel, see results/g5b.json):
abuse-keccak.json  4 × CREATE looping KECCAK256 over 1 KB (the worst opcode: ~865 wasm instructions per gas)
abuse-mulmod.json  4 × CREATE looping MULMOD on 256-bit operands
abuse-jumpdest.json 4 × CREATE looping 1000 JUMPDESTs (the cheapest opcode per gas)
abuse-callself.json 4 × CREATE whose initcode CALLs itself in a loop (frame setup per 100 gas)
abuse-blake2f.json 4 × CREATE calling the BLAKE2F precompile with 16 M rounds (1 gas per round) — the verifier
                   EVM has no precompiles, so this is a call to an empty account"""
import os
from mkinput import envelope, write, INST

LOOP = "0x5b5f56"                       # JUMPDEST PUSH0 JUMP
# CODESIZE PUSH0 PUSH0 CODECOPY ; CODESIZE PUSH0 PUSH0 CREATE ; PUSH0 JUMP(loop to 0 → JUMPDEST needed)
CREATE = "0x5b385f5f39385f5ff0505f56"   # JUMPDEST CODESIZE PUSH0 PUSH0 CODECOPY CODESIZE PUSH0 PUSH0 CREATE POP PUSH0 JUMP
MEM = "0x5f5b808052610400016001" + "56"  # PUSH0; loop: JUMPDEST DUP1 DUP1 MSTORE PUSH2 0x0400 ADD PUSH1 1 JUMP
SSTORE = "0x5f5b8080556001016001" + "56"  # PUSH0; loop: JUMPDEST DUP1 DUP1 SSTORE PUSH1 1 ADD PUSH1 1 JUMP

KECCAK = "0x5b6104005f20505f56"         # JUMPDEST PUSH2 0x400 PUSH0 KECCAK256 POP PUSH0 JUMP
BIG = "7f" + "f" * 63 + "e"
MULMOD = "0x" + BIG + "5b" + "8080800950" * 100 + "602156"  # [DUP1 DUP1 DUP1 MULMOD POP]x100, JUMP 0x21
JUMPDEST = "0x" + "5b" * 1000 + "5f56"
CALLSELF = "0x5b5f5f5f5f5f305af1505f56"  # JUMPDEST 5xPUSH0 ADDRESS GAS CALL POP PUSH0 JUMP
BLAKE2F = "0x6300ffffff60e01b5f52" + "60405f60d55f60095afa00"  # rounds=0xffffff, STATICCALL(GAS, 0x09, 0, 213, 0, 64)

def creates(code, n=4):
    return [{"to": None, "data": code, "value": "0"} for _ in range(n)]

if __name__ == "__main__":
    inv = "fallback-owner-drained"
    write("abuse-loop.json", envelope(creates(LOOP), inv))
    write("abuse-create.json", envelope(creates(CREATE), inv))
    write("abuse-mem.json", envelope(creates(MEM), inv))
    write("abuse-sstore.json", envelope(creates(SSTORE), inv))
    write("abuse-input.json", envelope([{"to": INST, "data": "0x" + "ab" * (24 * 1024), "value": "0"}], inv))
    write("abuse-over.json", envelope([{"to": INST, "data": "0x", "value": "0"}] * 5, inv))
    write("abuse-keccak.json", envelope(creates(KECCAK), inv))
    write("abuse-mulmod.json", envelope(creates(MULMOD), inv))
    write("abuse-jumpdest.json", envelope(creates(JUMPDEST), inv))
    write("abuse-callself.json", envelope(creates(CALLSELF), inv))
    write("abuse-blake2f.json", envelope(creates(BLAKE2F), inv))
    write("abuse-big.json", envelope([{"to": INST, "data": "0x" + "ab" * (24 * 1024 + 1), "value": "0"}], inv))
