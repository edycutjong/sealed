# levels

Target contracts the verifier runs exploits against.

- `src/ethernaut/` — level files from [OpenZeppelin/ethernaut](https://github.com/OpenZeppelin/ethernaut) at commit
  `d05643a40aa98c45d66247c69ffceab8f44dd8cb`, unmodified. Each file carries `SPDX-License-Identifier: MIT`
  (the Ethernaut repository as a whole is AGPL-3.0; only these SPDX-MIT files are copied).
- `lib/openzeppelin-contracts-08/` — `Ownable.sol` and `Context.sol` from OpenZeppelin Contracts v4.9.6 (MIT), the
  `openzeppelin-contracts-08` import the levels expect.

Build: `forge build` (solc pinned in `foundry.toml`, metadata hash off so bytecode is reproducible).
