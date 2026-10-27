// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {IDarkPoolSettlement} from "../interfaces/IDarkPoolSettlement.sol";
import {IKageRegistry} from "./IKageRegistry.sol";

/**
 * @title KageSettlement
 * @notice DarkPool settlement module for private in-pool swaps. A registered solver approves one swap_settle
 *         public-input vector with an EIP-712 signature; anyone may then submit it. DarkPool verifies the proof
 *         with the verifier it holds for this module, so this contract only gates and forwards.
 * @dev Stateless and not upgradeable: a fix is a new instance registered as a new module. Replay protection is
 *      DarkPool's nullifier set, so no nonce is stored. The proof is not signed: the vector alone fixes every
 *      effect, and many valid proofs exist for one vector.
 */
contract KageSettlement is EIP712 {
    bytes32 public constant SETTLEMENT_TYPEHASH =
        keccak256(
            "KageSettlement(address pool,uint256 solverId,bytes32 publicInputsHash,uint256 deadline)"
        );

    // Public-input positions of the swap_settle vector (k = 2 nullifiers, m = 4 outputs, no module words).
    uint256 private constant TAKER_NULLIFIER = 3;
    uint256 private constant MAKER_NULLIFIER = 4;

    IDarkPoolSettlement public immutable DARK_POOL;
    IKageRegistry public immutable REGISTRY;

    event KageSwapSettled(
        uint256 indexed solverId,
        bytes32 takerNullifier,
        bytes32 makerNullifier
    );

    error ZeroAddress();
    error PoolHasNoCode();
    error RegistryHasNoCode();
    error SettlementExpired(uint256 deadline);
    error SolverNotActive(uint256 solverId);
    error InvalidSolverSignature(uint256 solverId);

    constructor(
        IDarkPoolSettlement pool,
        IKageRegistry registry
    ) EIP712("HisokaKageSettlement", "1") {
        if (address(pool) == address(0) || address(registry) == address(0))
            revert ZeroAddress();
        if (address(pool).code.length == 0) revert PoolHasNoCode();
        if (address(registry).code.length == 0) revert RegistryHasNoCode();
        DARK_POOL = pool;
        REGISTRY = registry;
    }

    /// @notice Settle a swap approved by `solverId`'s current signer. EOA signers sign with ECDSA (high-s
    ///         rejected); contract signers answer ERC-1271. Every registry rule is read at execution time.
    function settleSwap(
        uint256 solverId,
        uint256 deadline,
        bytes calldata solverSignature,
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external {
        if (block.timestamp > deadline) revert SettlementExpired(deadline);
        address signer = REGISTRY.settlementSigner(solverId);
        if (signer == address(0)) revert SolverNotActive(solverId);
        if (
            !SignatureChecker.isValidSignatureNowCalldata(
                signer,
                settlementDigest(solverId, deadline, publicInputs),
                solverSignature
            )
        ) revert InvalidSolverSignature(solverId);

        DARK_POOL.settle(proof, publicInputs);

        // DarkPool enforced this module's registered vector length, so both indices are in range.
        emit KageSwapSettled(
            solverId,
            publicInputs[TAKER_NULLIFIER],
            publicInputs[MAKER_NULLIFIER]
        );
    }

    /// @notice The EIP-712 digest a solver signs: pool, solver id, keccak256 of the packed public inputs (equal to
    ///         EIP-712's encoding of a bytes32[]) and deadline, under this contract's domain and chain id.
    function settlementDigest(
        uint256 solverId,
        uint256 deadline,
        bytes32[] calldata publicInputs
    ) public view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        SETTLEMENT_TYPEHASH,
                        address(DARK_POOL),
                        solverId,
                        keccak256(abi.encodePacked(publicInputs)),
                        deadline
                    )
                )
            );
    }
}
