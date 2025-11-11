

- **4337**: PPO shown as a first-class operation: grant/revoke as userOps; `pull()` as a pay-to-pull op verified in the account’s policy (module) before execution.
- **6900 / 7579**: expose grant/revoke & pull in modules; wallets surface PPO creation UIs. No core changes required.
- **Safe**: a module can validate PPO digests and call `pull()`; policy layer can enforce per-token caps/windows.
