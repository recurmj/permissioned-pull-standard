// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

interface IPPORegistry {
  /// @notice Returns true if (grantor, nonce) is revoked.
  function isRevoked(address grantor, bytes32 nonce) external view returns (bool);

  /// @notice Revoke a single nonce. Callable only by the grantor.
  function revoke(bytes32 nonce) external;

  /// @notice Batch revoke multiple nonces. Callable only by the grantor.
  function revokeMany(bytes32[] calldata nonces) external;

  event Revoked(address indexed grantor, bytes32 indexed nonce);
  event RevokedMany(address indexed grantor, uint256 count);
}
