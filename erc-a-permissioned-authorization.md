# ERC-A: Permissioned Authorization (PPO)
**Category:** Standards Track · ERC  
**Author:** Mats Julner (“Recur Labs”)  
**Status:** Draft  
**Depends on:** EIP-712

## Abstract
Defines a chain-agnostic, revocable EIP-712 **Authorization** struct (a “permission to pull”) with replay protection and time windows. It is portable across networks and can be verified by any compliant executor.

## Motivation
ERC-20 + ERC-2612 don’t define a general, safe primitive for **retrieving** value by consent. PPO standardizes that consent as a signed object that wallets / AA stacks can expose, revoke, and track.

## Specification

### EIP-712 type

~~~
Authorization(
address grantor,
address grantee,
address token,
uint256 maxPerPull,
uint256 validAfter,
uint256 validBefore,
bytes32 nonce
)
~~~

- **grantor**: owner providing consent.  
- **grantee**: executor allowed to pull.  
- **token**: ERC-20 (MUST), MAY extend to native via wrapper.  
- **maxPerPull**: per-execution cap (not cumulative).  
- **validAfter / validBefore**: unix seconds (half-open window).  
- **nonce**: unique per-grantor (RECOMMENDED global per grantor). MUST be consumed on first valid execution.

**TYPEHASH** (normative):
`keccak256("Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)")`

### Events (RECOMMENDED from registries/wallets)

~~~
event AuthorizationGranted(address indexed grantor, address indexed grantee, address indexed token, bytes32 nonce);
event AuthorizationRevoked(address indexed grantor, bytes32 indexed nonce);
~~~


### Revocation
Grantor MUST be able to revoke by nonce (or range) off-chain (new signature invalidation list) or on-chain (registry). Executions MUST reject revoked nonces.

### Rationale
- **bytes32 nonce**: opaque, wallet-owned; works for per-relationship or global schemes.
- **Per-pull cap** keeps execution stateless across chains; cumulative caps can be built at higher layers.

## Reference hashing

~~~
bytes32 constant AUTH_TYPEHASH = keccak256(
  "Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
);

function _authStructHash(Authorization memory a) internal pure returns (bytes32) {
  return keccak256(abi.encode(
    AUTH_TYPEHASH, a.grantor, a.grantee, a.token,
    a.maxPerPull, a.validAfter, a.validBefore, a.nonce
  ));
}
~~~

### Security Considerations

- Nonce MUST be single-use.

- Windows MUST be enforced before signature recovery.

- Domain binding lives in ERC-B (executor’s `domainSeparator()`), preventing cross-executor replay.

- Revocation lists MUST be race-safe (check at execution time).

### Backwards compatibility

Plays nicely with 2612; PPO is orthogonal (pull vs permit-approve).

