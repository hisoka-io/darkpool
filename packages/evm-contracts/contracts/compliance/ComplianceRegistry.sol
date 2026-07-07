// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title ComplianceRegistry
 * @notice Event-log audit trail for the threshold-compliance committee: a registered member broadcasts each
 *         action (requested / evaluated / signed / decrypted) as an event. No on-chain proof or signature
 *         check -- this is an attestation log, not a cryptographic gate; the committee key lives off-chain.
 */
contract ComplianceRegistry is AccessControl {
    bytes32 public constant COMMITTEE_ADMIN_ROLE =
        keccak256("COMMITTEE_ADMIN_ROLE");
    bytes32 public constant MEMBER_ROLE = keccak256("MEMBER_ROLE");

    enum Action {
        Requested,
        Evaluated,
        Signed,
        Decrypted
    }

    uint256 public immutable threshold;
    uint256 public immutable committeeSize;

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

    function deregisterMember(
        address member
    ) external onlyRole(COMMITTEE_ADMIN_ROLE) {
        if (!isMember[member]) revert MemberNotRegistered(member);
        isMember[member] = false;
        delete memberMetadata[member];
        _revokeRole(MEMBER_ROLE, member);
        emit MemberDeregistered(member);
    }

    /// @notice Record a compliance action against `targetTag`. Emits an attestation only; no verification.
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
