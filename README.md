# Recur Permissioned-Pull Standard (RIP-001 → ERC-A / ERC-B)

This repo contains the split specs:
- **ERC-A — Permissioned Authorization (PPO)**: the EIP-712 consent object.
- **ERC-B — Pull Execution Interface**: how executors validate & consume PPOs.

Goal: make **consented flow** a native capability across AA wallets and modules (4337 / 6900 / 7579), not an external payment app.

## Quick links
- [`erc-a-permissioned-authorization.md`](./erc-a-permissioned-authorization.md)
- [`erc-b-pull-execution.md`](./erc-b-pull-execution.md)
- [`aa-alignment.md`](./aa-alignment.md)
- [`security.md`](./security.md)
- [`vectors.md`](./vectors.md)
- Minimal refs: [`src/PPORegistry.sol`](./src/PPORegistry.sol), [`src/PullSafeMinimal.sol`](./src/PullSafeMinimal.sol)

## Status
Field-tested on Sepolia ↔ Base Sepolia with one signed PPO verified across chains.

