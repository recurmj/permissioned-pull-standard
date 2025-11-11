// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/PullSafeMinimal.sol";
import "../src/PPORegistry.sol";
import "../src/interfaces/IERC20.sol";

contract MockERC20 is IERC20 {
  string public name = "Mock";
  string public symbol = "MCK";
  uint8 public override decimals = 18;
  mapping(address => uint256) public override balanceOf;
  mapping(address => mapping(address => uint256)) public override allowance;

  function mint(address to, uint256 amt) external {
    balanceOf[to] += amt;
  }

  function approve(address spender, uint256 value) external override returns (bool) {
    allowance[msg.sender][spender] = value;
    return true;
  }

  function transferFrom(address from, address to, uint256 value) external override returns (bool) {
    uint256 a = allowance[from][msg.sender];
    require(a >= value, "allowance");
    allowance[from][msg.sender] = a - value;
    require(balanceOf[from] >= value, "balance");
    balanceOf[from] -= value;
    balanceOf[to] += value;
    return true;
  }
}

contract PullSafeMinimalTest is Test {
  PullSafeMinimal exec;
  PPORegistry registry;
  MockERC20 token;

  // Test keys
  uint256 grantorPK = 0xabc1;
  address grantor;
  address grantee;

  function setUp() public {
    grantor = vm.addr(grantorPK);
    grantee = address(0xBEEF);

    registry = new PPORegistry();
    exec = new PullSafeMinimal(address(registry));
    token = new MockERC20();

    // fund grantor and approve executor
    token.mint(grantor, 1_000 ether);
    vm.prank(grantor);
    token.approve(address(exec), type(uint256).max);
  }

  function _auth(
    uint256 maxPerPull,
    uint256 validAfter,
    uint256 validBefore,
    bytes32 nonce
  ) internal view returns (PullSafeMinimal.Authorization memory a) {
    a = PullSafeMinimal.Authorization({
      grantor: grantor,
      grantee: grantee,
      token: address(token),
      maxPerPull: maxPerPull,
      validAfter: validAfter,
      validBefore: validBefore,
      nonce: nonce
    });
  }

  function _sign(bytes32 digest) internal view returns (bytes memory sig) {
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(grantorPK, digest);
    sig = abi.encodePacked(r, s, v);
  }

  function test_DomainSeparator_NotZero() public view {
    bytes32 ds = exec.domainSeparator();
    assertTrue(ds != bytes32(0));
  }

  function test_Pull_Succeeds_WithValidSig() public {
    // Build auth
    uint256 nowTs = block.timestamp;
    bytes32 nonce = keccak256("n1");
    PullSafeMinimal.Authorization memory a = _auth(10 ether, nowTs - 1, nowTs + 3600, nonce);

    // Compute structHash and digest
    bytes32 typehash = exec.AUTH_TYPEHASH();
    bytes32 structHash = keccak256(abi.encode(
      typehash,
      a.grantor, a.grantee, a.token,
      a.maxPerPull, a.validAfter, a.validBefore, a.nonce
    ));
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", exec.domainSeparator(), structHash));
    bytes memory sig = _sign(digest);

    // Grantee calls pull
    vm.prank(grantee);
    exec.pull(5 ether, a, sig);

    assertEq(token.balanceOf(grantee), 5 ether);
    assertTrue(exec.isNonceUsed(grantor, nonce));
  }

  function test_Cancel_BlocksPull() public {
    uint256 nowTs = block.timestamp;
    bytes32 nonce = keccak256("n2");
    PullSafeMinimal.Authorization memory a = _auth(10 ether, nowTs - 1, nowTs + 3600, nonce);

    // cancel locally (grantor-only)
    vm.prank(grantor);
    exec.cancel(nonce);
    assertTrue(exec.isNonceCanceled(grantor, nonce));

    // Sign after cancel (still same digest)
    bytes32 structHash = keccak256(abi.encode(
      exec.AUTH_TYPEHASH(),
      a.grantor, a.grantee, a.token,
      a.maxPerPull, a.validAfter, a.validBefore, a.nonce
    ));
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", exec.domainSeparator(), structHash));
    bytes memory sig = _sign(digest);

    vm.prank(grantee);
    vm.expectRevert(PullSafeMinimal.Revoked.selector);
    exec.pull(1 ether, a, sig);
  }

  function test_RegistryRevocation_BlocksPull() public {
    uint256 nowTs = block.timestamp;
    bytes32 nonce = keccak256("n3");
    PullSafeMinimal.Authorization memory a = _auth(10 ether, nowTs - 1, nowTs + 3600, nonce);

    // grantor revokes in registry
    vm.prank(grantor);
    registry.revoke(nonce);
    assertTrue(registry.isRevoked(grantor, nonce));

    bytes32 structHash = keccak256(abi.encode(
      exec.AUTH_TYPEHASH(),
      a.grantor, a.grantee, a.token,
      a.maxPerPull, a.validAfter, a.validBefore, a.nonce
    ));
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", exec.domainSeparator(), structHash));
    bytes memory sig = _sign(digest);

    vm.prank(grantee);
    vm.expectRevert(PullSafeMinimal.Revoked.selector);
    exec.pull(1 ether, a, sig);
  }
}
