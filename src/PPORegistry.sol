// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IPPORegistry} from "./interfaces/IPPORegistry.sol";

/// @title PPORegistry
/// @notice Global, grantor-controlled revocation registry for Permissioned Pull Authorizations (PPO).
/// @dev Executors MAY consult this registry at execution time. Grantors can revoke any *unused* nonce.
///      Idempotent: re-revoking the same nonce is a no-op but still emits events for observability.
contract PPORegistry is IPPORegistry {
  /// @dev Mapping: grantor => nonce => revoked?
  mapping(address => mapping(bytes32 => bool)) private _revoked;

  /// @inheritdoc IPPORegistry
  function isRevoked(address grantor, bytes32 nonce) external view override returns (bool) {
    return _revoked[grantor][nonce];
  }

  /// @inheritdoc IPPORegistry
  function revoke(bytes32 nonce) external override {
    if (!_revoked[msg.sender][nonce]) {
      _revoked[msg.sender][nonce] = true;
      emit Revoked(msg.sender, nonce);
    } else {
      // already revoked; still surface an event for traceability if desired
      emit Revoked(msg.sender, nonce);
    }
  }

  /// @inheritdoc IPPORegistry
  function revokeMany(bytes32[] calldata nonces) external override {
    uint256 n = nonces.length;
    for (uint256 i = 0; i < n; i++) {
      bytes32 nonce = nonces[i];
      if (!_revoked[msg.sender][nonce]) {
        _revoked[msg.sender][nonce] = true;
        emit Revoked(msg.sender, nonce);
      } else {
        // idempotent: emit again for consistent indexing/UX
        emit Revoked(msg.sender, nonce);
      }
    }
    emit RevokedMany(msg.sender, n);
  }
}
