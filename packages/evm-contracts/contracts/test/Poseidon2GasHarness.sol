// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Field} from "../Poseidon/Field.sol";
import {Poseidon2Lib} from "../Poseidon/Poseidon2Lib.sol";
import {Poseidon2LibOld} from "./Poseidon2LibOld.sol";

/// Gas snapshot harness for Poseidon2 entry points (new Yul vs old pure-Solidity sponge). 
interface IPoseidon2 {
    function hash_1(uint256 x) external pure returns (uint256);
    function hash_2(uint256 x, uint256 y) external pure returns (uint256);
    function hash_3(uint256 x, uint256 y, uint256 z) external pure returns (uint256);
}

contract Poseidon2GasHarness {
    address public poseidon2YulContract;

    function setPoseidon2YulContract(address _addr) external {
        poseidon2YulContract = _addr;
    }

    // deployed Yul contract (STATICCALL)
    function gas_hash_1_yulCall(uint256 x) external view returns (uint256 gasUsed) {
        IPoseidon2 c = IPoseidon2(poseidon2YulContract);
        uint256 start = gasleft();
        c.hash_1(x);
        gasUsed = start - gasleft();
    }

    function gas_hash_2_yulCall(uint256 x, uint256 y) external view returns (uint256 gasUsed) {
        IPoseidon2 c = IPoseidon2(poseidon2YulContract);
        uint256 start = gasleft();
        c.hash_2(x, y);
        gasUsed = start - gasleft();
    }

    function gas_hash_3_yulCall(uint256 x, uint256 y, uint256 z) external view returns (uint256 gasUsed) {
        IPoseidon2 c = IPoseidon2(poseidon2YulContract);
        uint256 start = gasleft();
        c.hash_3(x, y, z);
        gasUsed = start - gasleft();
    }

    // new Yul-backed implementation
    function gas_hash_1(uint256 x) external view returns (uint256 gasUsed) {
        uint256 start = gasleft();
        Poseidon2Lib.hash_1(Field.Type.wrap(x));
        gasUsed = start - gasleft();
    }

    function gas_hash_2(uint256 x, uint256 y) external view returns (uint256 gasUsed) {
        uint256 start = gasleft();
        Poseidon2Lib.hash_2(Field.Type.wrap(x), Field.Type.wrap(y));
        gasUsed = start - gasleft();
    }

    function gas_hash_3(uint256 x, uint256 y, uint256 z) external view returns (uint256 gasUsed) {
        uint256 start = gasleft();
        Poseidon2Lib.hash_3(
            Field.Type.wrap(x),
            Field.Type.wrap(y),
            Field.Type.wrap(z)
        );
        gasUsed = start - gasleft();
    }

    function gas_hashArray(uint256[] calldata input) external view returns (uint256 gasUsed) {
        Field.Type[] memory f = new Field.Type[](input.length);
        for (uint256 i; i < input.length; ++i) {
            f[i] = Field.Type.wrap(input[i]);
        }
        uint256 start = gasleft();
        Poseidon2Lib.hash(f, input.length, false);
        gasUsed = start - gasleft();
    }

    //  old pure-Solidity sponge (baseline, kept only for the gas-snapshot test)
    function gas_hash_1_old(uint256 x) external view returns (uint256 gasUsed) {
        uint256 start = gasleft();
        Poseidon2LibOld.hash_1(Field.Type.wrap(x));
        gasUsed = start - gasleft();
    }

    function gas_hash_2_old(uint256 x, uint256 y) external view returns (uint256 gasUsed) {
        uint256 start = gasleft();
        Poseidon2LibOld.hash_2(Field.Type.wrap(x), Field.Type.wrap(y));
        gasUsed = start - gasleft();
    }

    function gas_hash_3_old(uint256 x, uint256 y, uint256 z) external view returns (uint256 gasUsed) {
        uint256 start = gasleft();
        Poseidon2LibOld.hash_3(
            Field.Type.wrap(x),
            Field.Type.wrap(y),
            Field.Type.wrap(z)
        );
        gasUsed = start - gasleft();
    }

    function gas_hashArray_old(uint256[] calldata input) external view returns (uint256 gasUsed) {
        Field.Type[] memory f = new Field.Type[](input.length);
        for (uint256 i; i < input.length; ++i) {
            f[i] = Field.Type.wrap(input[i]);
        }
        uint256 start = gasleft();
        Poseidon2LibOld.hash(f, input.length, false);
        gasUsed = start - gasleft();
    }
}
