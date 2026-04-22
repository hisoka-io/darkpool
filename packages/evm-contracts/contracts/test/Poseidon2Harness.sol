// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Field} from "../Poseidon/Field.sol";
import {Poseidon2Lib} from "../Poseidon/Poseidon2Lib.sol";

/// Test harness that exercises the inlined `Poseidon2Lib` API, the
/// same path used by DarkPool.sol, MerkleTreeLib.sol, and UniswapAdaptor.sol
contract Poseidon2Harness {
    function hashArray(uint256[] calldata input) external pure returns (uint256) {
        Field.Type[] memory f = new Field.Type[](input.length);
        for (uint256 i; i < input.length; ++i) {
            f[i] = Field.Type.wrap(input[i]);
        }
        return Field.Type.unwrap(Poseidon2Lib.hash(f, input.length, false));
    }

    function hashFixed(uint256[] calldata input) external pure returns (uint256) {
        Field.Type[] memory f = new Field.Type[](input.length);
        for (uint256 i; i < input.length; ++i) {
            f[i] = Field.Type.wrap(input[i]);
        }
        return Field.Type.unwrap(Poseidon2Lib.hash(f, input.length, false));
    }

    function hashVariable(uint256[] calldata input) external pure returns (uint256) {
        Field.Type[] memory f = new Field.Type[](input.length);
        for (uint256 i; i < input.length; ++i) {
            f[i] = Field.Type.wrap(input[i]);
        }
        return Field.Type.unwrap(Poseidon2Lib.hash(f, input.length, true));
    }
}
