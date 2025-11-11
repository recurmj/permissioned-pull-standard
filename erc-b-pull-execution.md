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

  /// EIP-712
  function domainSeparator() external view returns (bytes32);

  /// Execute a single pull.
  function pull(
    uint256 amount,
    Authorization calldata auth,
    bytes calldata signature
  ) external;

  /// View whether a nonce is consumed/revoked for a grantor.
  function isNonceUsed(address grantor, bytes32 nonce) external view returns (bool);

  /// Emitted on success.
  event PullExecuted(address indexed grantor, address indexed grantee, address indexed token, uint256 amount, bytes32 authHash);
  event NonceUsed(address indexed grantor, bytes32 indexed nonce);

  /// Canonical errors
  error BadSignature();
  error NotYetValid();
  error Expired();
  error OverCap();
  error NonceAlreadyUsed();
  error WrongGrantee();
  error WrongToken();
}
~~~

## Execution rules (normative)

An implementation **MUST:**

1. Compute `structHash` per ERC-A, then `digest = keccak256(0x1901 || domainSeparator() || structHash)`.

2. `ecrecover(digest, signature) == auth.grantor`, else **revert** `BadSignature()`.

3. `msg.sender == auth.grantee`, else **revert** `WrongGrantee()`.

4. `block.timestamp >= validAfter` (else `NotYetValid()`), `< validBefore` (else `Expired()`).

5. `amount <= maxPerPull` (else `OverCap()`).

6. `!isNonceUsed(grantor, nonce)` (else `NonceAlreadyUsed()`); then **mark used** and emit `NonceUsed`.

7. Transfer `amount` of `auth.token` **from grantor to grantee** (implementation-specific: allowance, vault, or AA policy).

8. Emit `PullExecuted(grantor, grantee, token, amount, authHash) where authHash = keccak256(abi.encode(auth))` including typehash.

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
