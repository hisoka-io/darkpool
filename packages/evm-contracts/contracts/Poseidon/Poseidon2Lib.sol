// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import {Field} from "./Field.sol";
import {LibPoseidon2Yul} from "./LibPoseidon2Yul.sol";

// Poseidon2 hash function
// Thin sponge shell over the Yul-optimized permutation in `LibPoseidon2Yul`.
// Permutation source: https://github.com/zemse/poseidon2-evm (MIT)
library Poseidon2Lib {
    using Field for *;

    uint256 private constant RATE = 3;

    function hash_1(Field.Type m) internal pure returns (Field.Type) {
        return Field.Type.wrap(LibPoseidon2Yul.hash_1(Field.Type.unwrap(m)));
    }

    function hash_2(
        Field.Type m1,
        Field.Type m2
    ) internal pure returns (Field.Type) {
        return
            Field.Type.wrap(
                LibPoseidon2Yul.hash_2(
                    Field.Type.unwrap(m1),
                    Field.Type.unwrap(m2)
                )
            );
    }

    function hash_3(
        Field.Type m1,
        Field.Type m2,
        Field.Type m3
    ) internal pure returns (Field.Type) {
        return
            Field.Type.wrap(
                LibPoseidon2Yul.hash_3(
                    Field.Type.unwrap(m1),
                    Field.Type.unwrap(m2),
                    Field.Type.unwrap(m3)
                )
            );
    }

    function hash(
        Field.Type[] memory inputs,
        uint256 std_input_length,
        bool is_variable_length
    ) internal pure returns (Field.Type) {
        return _spongeHash(inputs, std_input_length, is_variable_length);
    }

    function _spongeHash(
        Field.Type[] memory input,
        uint256 std_input_length,
        bool is_variable_length
    ) private pure returns (Field.Type) {
        uint256 len = input.length;
        // iv := len << 64, initial state := [0, 0, 0, iv]
        uint256 s0 = 0;
        uint256 s1 = 0;
        uint256 s2 = 0;
        uint256 s3 = len << 64;

        uint256 c0 = 0;
        uint256 c1 = 0;
        uint256 c2 = 0;
        uint256 cacheSize = 0;

        for (uint256 i; i < len; ++i) {
            if (i >= std_input_length) continue;
            uint256 v = Field.Type.unwrap(input[i]);
            if (cacheSize == RATE) {
                (s0, s1, s2, s3) = _duplex(s0, s1, s2, s3, c0, c1, c2);
                c0 = v;
                c1 = 0;
                c2 = 0;
                cacheSize = 1;
            } else if (cacheSize == 0) {
                c0 = v;
                cacheSize = 1;
            } else if (cacheSize == 1) {
                c1 = v;
                cacheSize = 2;
            } else {
                c2 = v;
                cacheSize = 3;
            }
        }

        // Append the variable-length domain separator `1` after the standard
        // payload, identical to the reference sponge implementation.
        if (is_variable_length) {
            if (cacheSize == RATE) {
                (s0, s1, s2, s3) = _duplex(s0, s1, s2, s3, c0, c1, c2);
                c0 = 1;
                c1 = 0;
                c2 = 0;
                cacheSize = 1;
            } else if (cacheSize == 0) {
                c0 = 1;
                cacheSize = 1;
            } else if (cacheSize == 1) {
                c1 = 1;
                cacheSize = 2;
            } else {
                c2 = 1;
                cacheSize = 3;
            }
        }

        // Final duplex to transition from absorb to squeeze, then pop cache[0].
        (uint256 out0, , , ) = _duplex(s0, s1, s2, s3, c0, c1, c2);
        return Field.Type.wrap(out0);
    }

    /// state[0..2] += cache[0..2] (mod PRIME) then apply the permutation.
    function _duplex(
        uint256 s0,
        uint256 s1,
        uint256 s2,
        uint256 s3,
        uint256 c0,
        uint256 c1,
        uint256 c2
    )
        private
        pure
        returns (uint256 o0, uint256 o1, uint256 o2, uint256 o3)
    {
        uint256 prime = LibPoseidon2Yul.PRIME;
        assembly {
            s0 := addmod(s0, c0, prime)
            s1 := addmod(s1, c1, prime)
            s2 := addmod(s2, c2, prime)
        }
        (o0, o1, o2, o3) = LibPoseidon2Yul.permutation(s0, s1, s2, s3);
    }
}
