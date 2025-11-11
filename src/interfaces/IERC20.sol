// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @notice Minimal ERC-20 surface needed by PullSafeMinimal.
interface IERC20 {
  function transferFrom(address from, address to, uint256 value) external returns (bool);
  function allowance(address owner, address spender) external view returns (uint256);
  function balanceOf(address owner) external view returns (uint256);
  function approve(address spender, uint256 value) external returns (bool);
  function decimals() external view returns (uint8);
}
