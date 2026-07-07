// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ComplianceRegistry
 * @notice Social (event-log) audit trail for the threshold-compliance committee. A registered committee
 *         member BROADCASTS the compliance action it took (requested / evaluated / signed / decrypted)
 *         against a target as an on-chain event. There is deliberately NO on-chain proof and NO signature
 *         verification: the committee key is a known registered set held off-chain, so the auditability
 *         layer is an attestation log, not a cryptographic gate (a threshold-Schnorr or per-member EIP-712
 *         verify can be added later if attribution ever needs to be trust-minimized).
 * @dev The committee `(t, n)` shape is recorded for auditors; the actual threshold decryption happens
 *      off-chain. Only a member (MEMBER_ROLE) may record an action; membership is managed by an admin.
 */
contract ComplianceRegistry is AccessControl {
    bytes32 public constant COMMITTEE_ADMIN_ROLE =
        keccak256("COMMITTEE_ADMIN_ROLE");
    bytes32 public constant MEMBER_ROLE = keccak256("MEMBER_ROLE");

    /// @dev The compliance action a member attests to; mirrors the off-chain committee workflow stages.
    enum Action {
        Requested,
        Evaluated,
        Signed,
        Decrypted
    }

    uint256 public immutable threshold;
    uint256 public immutable committeeSize;

    /// @dev metadata is free-form (jurisdictions / threshold targets); empty string = not registered.
    mapping(address => string) public memberMetadata;
    mapping(address => bool) public isMember;

    error ZeroAdmin();
    error ThresholdZero();
    error CommitteeSizeZero();
    error ThresholdExceedsCommittee(uint256 threshold, uint256 committeeSize);
    error ZeroMember();
    error MemberAlreadyRegistered(address member);
    error MemberNotRegistered(address member);
    error CallerNotRegisteredMember(address caller);

    event MemberRegistered(address indexed member, string metadata);
    event MemberDeregistered(address indexed member);
    event ComplianceAction(
        address indexed member,
        Action indexed action,
        bytes32 indexed targetTag,
        uint256 timestamp,
        string status
    );

    /**
     * @param admin The committee administrator (grants/revokes membership). Must be non-zero.
     * @param t The decryption threshold `t`. Must be non-zero and at most `n`.
     * @param n The committee size `n`. Must be non-zero.
     */
    constructor(address admin, uint256 t, uint256 n) {
        if (admin == address(0)) revert ZeroAdmin();
        if (t == 0) revert ThresholdZero();
        if (n == 0) revert CommitteeSizeZero();
        if (t > n) revert ThresholdExceedsCommittee(t, n);
        threshold = t;
        committeeSize = n;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(COMMITTEE_ADMIN_ROLE, admin);
    }

    /// @notice Register a committee member so it can record compliance actions.
    function registerMember(
        address member,
        string calldata metadata
    ) external onlyRole(COMMITTEE_ADMIN_ROLE) {
        if (member == address(0)) revert ZeroMember();
        if (isMember[member]) revert MemberAlreadyRegistered(member);
        isMember[member] = true;
        memberMetadata[member] = metadata;
        _grantRole(MEMBER_ROLE, member);
        emit MemberRegistered(member, metadata);
    }

    /// @notice Remove a committee member.
    function deregisterMember(
        address member
    ) external onlyRole(COMMITTEE_ADMIN_ROLE) {
        if (!isMember[member]) revert MemberNotRegistered(member);
        isMember[member] = false;
        delete memberMetadata[member];
        _revokeRole(MEMBER_ROLE, member);
        emit MemberDeregistered(member);
    }

    /**
     * @notice Record a compliance action against a target. Emits an attestation only; no verification.
     * @param action The workflow stage (requested / evaluated / signed / decrypted).
     * @param targetTag An opaque tag identifying what was acted on (e.g. a note discovery tag or memo id).
     * @param status Free-form human-readable status/notes.
     */
    function recordAction(
        Action action,
        bytes32 targetTag,
        string calldata status
    ) external {
        if (!isMember[msg.sender]) revert CallerNotRegisteredMember(msg.sender);
        emit ComplianceAction(
            msg.sender,
            action,
            targetTag,
            block.timestamp,
            status
        );
    }
}
