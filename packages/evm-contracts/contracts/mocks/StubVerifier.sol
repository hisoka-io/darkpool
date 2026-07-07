// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/// @dev Test-only verifier that unconditionally accepts. Never deployed on-chain; exercises the routing
/// paths where a real proof is unavailable (e.g. FROST-multisig entrypoints in unit tests).
contract StubVerifier {
    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        return true;
    }
}
