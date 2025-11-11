

- **Domain binding**: signatures are per-executor via `domainSeparator()`.
- **Replay**: single-use nonce; MUST be consumed before external calls.
- **Windows**: enforce timestamps pre-recovery to avoid griefing.
- **Cross-network**: same struct/signature works wherever the executor’s domain matches; otherwise rejected.
- **Revocation**: registry/wallet lists MUST be checked at execution time.
