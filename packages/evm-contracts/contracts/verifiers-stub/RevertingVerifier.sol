// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {IProofVerifier} from "../interfaces/IProofVerifier.sol";

/**
 * @title RevertingVerifier
 * @notice Holds a DarkPool verifier slot whose real verifier is not live yet. Every call reverts, so the circuit
 *         behind the slot accepts nothing until the Timelock installs its verifier with `setVerifier`.
 * @dev Lives outside `contracts/verifiers/`, which holds only generated verifiers pinned by the VK identity check.
 */
contract RevertingVerifier is IProofVerifier {
    error VerifierNotConfigured();

    function verify(
        bytes calldata,
        bytes32[] calldata
    ) external pure returns (bool) {
        revert VerifierNotConfigured();
    }
}
