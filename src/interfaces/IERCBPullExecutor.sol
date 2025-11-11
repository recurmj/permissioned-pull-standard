// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @notice Canonical ERC-B executor interface (spec-minimal).
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

  // ---- Views ----
  function domainSeparator() external view returns (bytes32);
  function isNonceUsed(address grantor, bytes32 nonce) external view returns (bool);
  function isNonceCanceled(address grantor, bytes32 nonce) external view returns (bool);

  // ---- Mutations ----
  /// @notice Execute a single pull per ERC-B rules.
  function pull(uint256 amount, Authorization calldata auth, bytes calldata signature) external;

  /// @notice Grantor-only local revocation of an unused nonce.
  function cancel(bytes32 nonce) external;

  // ---- Events ----
  event PullExecuted(
    address indexed grantor,
    address indexed grantee,
    address indexed token,
    uint256 amount,
    bytes32 structHash
  );
  event NonceUsed(address indexed grantor, bytes32 indexed nonce);
  event NonceCanceled(address indexed grantor, bytes32 indexed nonce);

  // ---- Canonical errors ----
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
