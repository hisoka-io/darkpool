// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/// @dev Test-only verifier that unconditionally accepts.
contract StubVerifier {
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        return true;
    }
}
