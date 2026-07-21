// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @notice Storage-gate negative-test baseline: one ERC-7201 namespace, two same-type fields, so
/// StorageGate.test can prove assertStorageUpgradeSafe rejects a namespace-internal reorder (a class the
/// bare-sequential snapshot cannot see).
contract StorageGateBaseMock is Initializable, UUPSUpgradeable {
    /// @custom:storage-location erc7201:hisoka.storagegate
    struct GateStorage {
        uint256 first;
        uint256 second;
    }

    // keccak256(abi.encode(uint256(keccak256("hisoka.storagegate")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant GATE_LOCATION =
        0x24d3b05bf82765017534caf39d5599e304f76fa40023f68fff15df5ed4a5ed00;

    function initialize() external initializer {}

    function _gate() private pure returns (GateStorage storage $) {
        assembly {
            $.slot := GATE_LOCATION
        }
    }

    function _authorizeUpgrade(address) internal override {}
}

/// @notice Storage-incompatible sibling of StorageGateBaseMock: one field is inserted at the FRONT of the
/// same namespace struct, shifting `first`/`second` down a slot. validateUpgrade(base, bad) MUST reject it.
contract StorageGateBadMock is Initializable, UUPSUpgradeable {
    /// @custom:storage-location erc7201:hisoka.storagegate
    struct GateStorage {
        uint256 inserted;
        uint256 first;
        uint256 second;
    }

    bytes32 private constant GATE_LOCATION =
        0x24d3b05bf82765017534caf39d5599e304f76fa40023f68fff15df5ed4a5ed00;

    function initialize() external initializer {}

    function _gate() private pure returns (GateStorage storage $) {
        assembly {
            $.slot := GATE_LOCATION
        }
    }

    function _authorizeUpgrade(address) internal override {}
}
