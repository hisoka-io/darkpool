// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IDarkPoolSettlement} from "../interfaces/IDarkPoolSettlement.sol";

/// @notice Test-only settlement module controller: forwards any proof to the pool with no gate of its own.
contract SettlementControllerHarness {
    IDarkPoolSettlement public immutable POOL;

    constructor(IDarkPoolSettlement pool) {
        POOL = pool;
    }

    function settle(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        POOL.settle(proof, publicInputs);
    }
}

/// @notice Test-only verifier that rejects by returning false rather than reverting.
contract FalseVerifier {
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        return false;
    }
}

/**
 * @notice Test-only verifier that reduces every public input mod the BN254 scalar field before comparing it to
 *         one accepted statement, as a verifier for a different proving system might. It accepts `w` and
 *         `w + p` alike, which is the aliasing DarkPool's canonical-field check must stop.
 */
contract ReducingStubVerifier {
    uint256 private constant BN254_FR =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 public acceptedStatement;

    function accept(bytes32[] calldata publicInputs) external {
        acceptedStatement = _reducedHash(publicInputs);
    }

    function verify(
        bytes calldata,
        bytes32[] calldata publicInputs
    ) external view returns (bool) {
        return _reducedHash(publicInputs) == acceptedStatement;
    }

    function _reducedHash(
        bytes32[] calldata publicInputs
    ) private pure returns (bytes32) {
        bytes32[] memory reduced = new bytes32[](publicInputs.length);
        for (uint256 i; i < publicInputs.length; ++i) {
            reduced[i] = bytes32(uint256(publicInputs[i]) % BN254_FR);
        }
        return keccak256(abi.encodePacked(reduced));
    }
}

/**
 * @notice Test-only token whose `transferFrom` calls a settlement controller, so a deposit's token pull
 *         re-enters the pool through `settle` while the deposit holds the reentrancy lock.
 */
contract SettleReentrantToken {
    SettlementControllerHarness public immutable CONTROLLER;
    bytes32[] private _publicInputs;

    constructor(SettlementControllerHarness controller) {
        CONTROLLER = controller;
    }

    function setPublicInputs(bytes32[] calldata publicInputs) external {
        _publicInputs = publicInputs;
    }

    function balanceOf(address) external pure returns (uint256) {
        return 0;
    }

    function transferFrom(address, address, uint256) external returns (bool) {
        CONTROLLER.settle("", _publicInputs);
        return true;
    }
}
