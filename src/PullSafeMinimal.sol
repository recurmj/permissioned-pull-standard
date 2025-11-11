// SPDX-License-Identifier: Apache-2.0
// Author: Mats Julner (@recurmj · Recur Labs)
pragma solidity ^0.8.20;

import "./interfaces/IERC20.sol";
import "./interfaces/IPPORegistry.sol";
import "./interfaces/IERCBPullExecutor.sol";

contract PullSafeMinimal is IERCBPullExecutor {
  // --- EIP-712 Domain (name, version, chainId, verifyingContract)
  string public constant NAME    = "PullSafe";
  string public constant VERSION = "1";
  bytes32 private constant EIP712DOMAIN_TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
  bytes32 public immutable override domainSeparator;

  // --- Nonces
  mapping(address => mapping(bytes32 => bool)) private _used;
  mapping(address => mapping(bytes32 => bool)) private _canceled;

  // --- Reentrancy guard
  uint256 private _locked = 1;

  // --- Low-s check
  bytes32 private constant SECP256K1N_HALF =
    0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

  // --- Optional global registry (can be address(0))
  IPPORegistry public immutable registry;

  // --- Typehash (public for tests/vectors)
  bytes32 public constant AUTH_TYPEHASH = keccak256(
    "Authorization(address grantor,address grantee,address token,uint256 maxPerPull,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
  );

  // --- Events (from interface)
  event PullExecuted(address indexed grantor, address indexed grantee, address indexed token, uint256 amount, bytes32 structHash);
  event NonceUsed(address indexed grantor, bytes32 indexed nonce);
  event NonceCanceled(address indexed grantor, bytes32 indexed nonce);

  // --- Errors (from interface)
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

  constructor(address registry_) {
    registry = IPPORegistry(registry_);
    uint256 chainId;
    assembly { chainId := chainid() }
    domainSeparator = keccak256(
      abi.encode(
        EIP712DOMAIN_TYPEHASH,
        keccak256(bytes(NAME)),
        keccak256(bytes(VERSION)),
        chainId,
        address(this)
      )
    );
  }

  // --- Views required by interface
  function isNonceUsed(address grantor, bytes32 nonce) public view override returns (bool) {
    return _used[grantor][nonce];
  }
  function isNonceCanceled(address grantor, bytes32 nonce) public view override returns (bool) {
    return _canceled[grantor][nonce];
  }

  // --- Grantor-only local revocation
  function cancel(bytes32 nonce) external override {
    _canceled[msg.sender][nonce] = true;
    emit NonceCanceled(msg.sender, nonce);
  }

  // --- Core pull
  function pull(
    uint256 amount,
    Authorization calldata a,
    bytes calldata sig
  ) external override {
    if (msg.sender != a.grantee) revert WrongGrantee();
    if (a.token == address(0) || a.grantee == address(0) || a.grantor == address(0)) revert ZeroAddress();
    if (amount == 0) revert ZeroAmount();
    if (block.timestamp < a.validAfter) revert NotYetValid();
    if (block.timestamp >= a.validBefore) revert Expired();
    if (amount > a.maxPerPull) revert OverCap();
    if (isNonceCanceled(a.grantor, a.nonce)) revert Revoked();
    if (address(registry) != address(0) && registry.isRevoked(a.grantor, a.nonce)) revert Revoked();
    if (isNonceUsed(a.grantor, a.nonce)) revert NonceAlreadyUsed();

    // Compute structHash & digest
    bytes32 structHash = keccak256(abi.encode(
      AUTH_TYPEHASH,
      a.grantor, a.grantee, a.token,
      a.maxPerPull, a.validAfter, a.validBefore, a.nonce
    ));
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

    // Recover with low-s & v∈{27,28}
    address recovered = _recover(digest, sig);
    if (recovered != a.grantor) revert BadSignature();

    // Effects
    _used[a.grantor][a.nonce] = true;
    emit NonceUsed(a.grantor, a.nonce);

    // Interaction (nonReentrant)
    _enter();
    bool ok = IERC20(a.token).transferFrom(a.grantor, a.grantee, amount);
    _exit();
    if (!ok) revert TransferFailed();

    emit PullExecuted(a.grantor, a.grantee, a.token, amount, structHash);
  }

  // --- Internal utils
  function _recover(bytes32 digest, bytes memory sig) private pure returns (address) {
    if (sig.length != 65) revert BadSignature();
    bytes32 r; bytes32 s; uint8 v;
    assembly {
      r := mload(add(sig, 32))
      s := mload(add(sig, 64))
      v := byte(0, mload(add(sig, 96)))
    }
    if (v < 27) v += 27;
    if (v != 27 && v != 28) revert BadSignature();
    if (uint256(s) > uint256(SECP256K1N_HALF)) revert BadSignature();
    address signer = ecrecover(digest, v, r, s);
    if (signer == address(0)) revert BadSignature();
    return signer;
  }

  function _enter() private {
    if (_locked != 1) revert();
    _locked = 2;
  }
  function _exit() private {
    _locked = 1;
  }
}
