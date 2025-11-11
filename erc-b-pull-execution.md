# ERC-B: Pull Execution Interface
**Category:** Standards Track · ERC  
**Author:** Mats Julner (“Recur Labs”)  
**Status:** Draft  
**Depends on:** ERC-A, EIP-712

## Abstract
Defines how an executor validates a PPO and performs a pull transfer, with canonical errors/events and domain separation.

## Interface

~~~
pragma solidity ^0.8.20;

interface IERCBPullExecutor {
  struct Authorization {
    address grantor;
    address grantee;
    address token;
    uint256 maxPerPull;
    uint256 validAfter;
    uint256 validBefore;
    bytes32 nonce;
  }

  // Views
  function domainSeparator() external view returns (bytes32);
  function isNonceUsed(address grantor, bytes32 nonce) external view returns (bool);
  function isNonceCanceled(address grantor, bytes32 nonce) external view returns (bool);

  // Mutations
  function pull(uint256 amount, Authorization calldata auth, bytes calldata signature) external;
  function cancel(bytes32 nonce) external; // grantor-only local revoke

  // Events
  event PullExecuted(address indexed grantor, address indexed grantee, address indexed token, uint256 amount, bytes32 structHash);
  event NonceUsed(address indexed grantor, bytes32 indexed nonce);
  event NonceCanceled(address indexed grantor, bytes32 indexed nonce);

  // Errors
  error BadSignature();
  error NotYetValid();
  error Expired();
  error OverCap();
  error NonceAlreadyUsed();
  error Revoked();
  error WrongGrantee();
  error ZeroAddress();
  error ZeroAmount();
  error TransferFailed();
}
~~~

## Execution rules (normative)

An implementation **MUST:**

1. Compute `structHash` per ERC-A, then `digest = keccak256(0x1901 || domainSeparator() || structHash)`.

2. `ecrecover(digest, signature) == auth.grantor`, else **revert** `BadSignature()`.

3. `msg.sender == auth.grantee`, else **revert** `WrongGrantee()`.

4. Enforce time window (`validAfter ≤ now < validBefore`) → `NotYetValid()` / `Expired()`.

5. Enforce cap (`amount ≤ maxPerPull`) → `OverCap()`.
6. Revocation: if `isNonceCanceled(grantor, nonce)` **or** (if configured) `registry.isRevoked(grantor, nonce)` → `Revoked()`.

7. Ensure `!isNonceUsed(grantor, nonce)`; then **mark used** and emit `NonceUsed`.

8. Transfer `amount` of `auth.token` from grantor to grantee; **revert** `TransferFailed()` on failure.

9. Emit `PullExecuted(grantor, grantee, token, amount, structHash)`.

## Domain separation

The executor MUST expose a stable `domainSeparator()`; signatures are bound to the executor to prevent cross-executor replay. Portability across chains is achieved when the **same executor domain** exists on multiple networks.

## Partial fills & batching (optional)

Implementations MAY support:

- `pullMany(…Authorization[], …)` with per-item validation.

- No cumulative limits are mandated; higher layers can implement metering.

## Security considerations

- Nonce marking MUST be before external calls (checks-effects-interactions).

- Token transfers MUST use safe patterns and reentrancy guards.

- Consider chain forks: windowed validity + replay maps help safety.
- Signatures MUST enforce low-s and `v ∈ {27,28}` to prevent malleability.
