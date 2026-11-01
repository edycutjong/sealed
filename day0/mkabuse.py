#!/usr/bin/env python3
"""Worst-case fakes for G5b (TEST VECTORS). Each must come back as a normal verdict, never a worker error.

abuse-loop.json    4 × CREATE whose initcode is `JUMPDEST PUSH0 JUMP` (burns the full 30 M gas each)
abuse-create.json  4 × CREATE of a self-replicating initcode (each level CODECOPYs itself and CREATEs a child)
abuse-mem.json     4 × CREATE whose initcode MSTOREs at a 1 KB-stepping offset until out of gas
abuse-sstore.json  4 × CREATE whose initcode writes fresh storage slots until out of gas
abuse-input.json   1 tx carrying exactly 24 KB of calldata to the instance
abuse-over.json    5 txs (over the tx cap) → `exploit invalid`
abuse-big.json     24 KB + 1 byte of calldata → `exploit invalid`"""
import os
from mkinput import envelope, write, INST

LOOP = "0x5b5f56"                       # JUMPDEST PUSH0 JUMP
# CODESIZE PUSH0 PUSH0 CODECOPY ; CODESIZE PUSH0 PUSH0 CREATE ; PUSH0 JUMP(loop to 0 → JUMPDEST needed)
CREATE = "0x5b385f5f39385f5ff0505f56"   # JUMPDEST CODESIZE PUSH0 PUSH0 CODECOPY CODESIZE PUSH0 PUSH0 CREATE POP PUSH0 JUMP
MEM = "0x5f5b808052610400016001" + "56"  # PUSH0; loop: JUMPDEST DUP1 DUP1 MSTORE PUSH2 0x0400 ADD PUSH1 1 JUMP
SSTORE = "0x5f5b8080556001016001" + "56"  # PUSH0; loop: JUMPDEST DUP1 DUP1 SSTORE PUSH1 1 ADD PUSH1 1 JUMP

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
    write("abuse-big.json", envelope([{"to": INST, "data": "0x" + "ab" * (24 * 1024 + 1), "value": "0"}], inv))
