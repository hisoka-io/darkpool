// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

/**
 * @title IProofVerifier
 * @notice What DarkPool requires of a verifier, independent of the proving system behind it.
 * @dev `proof` is opaque bytes. `publicInputs` is the circuit's public-input vector in protocol order, one
 *      BN254 scalar-field element per word; DarkPool rejects any word at or above the field order before it
 *      calls `verify`, so an implementation never receives a non-canonical word. An implementation MUST be
 *      `view` and MUST return false or revert for every pair it does not accept. A verifier with a different
 *      ABI (for example a Groth16 `verifyProof`) is installed behind an adapter that implements this function.
 */
interface IProofVerifier {
    function verify(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external view returns (bool);
}
