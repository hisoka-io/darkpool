// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {KageRegistry} from "../kage/KageRegistry.sol";

/// @notice Test-only ERC-1271 solver wallet: approves a digest iff `OWNER` signed it with ECDSA.
contract Erc1271SolverWallet is IERC1271 {
    address public immutable OWNER;

    constructor(address owner) {
        OWNER = owner;
    }

    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(
            hash,
            signature
        );
        if (err == ECDSA.RecoverError.NoError && recovered == OWNER) {
            return IERC1271.isValidSignature.selector;
        }
        return 0xffffffff;
    }
}

/// @notice Test-only storage-preserving upgrade target: adds only a pure view.
/// @custom:oz-upgrades-unsafe-allow missing-initializer
contract KageRegistryV2Mock is KageRegistry {
    function version() external pure returns (uint256) {
        return 2;
    }
}
