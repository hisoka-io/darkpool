// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {MerkleTreeLib} from "../../contracts/libraries/MerkleTreeLib.sol";

// A production MerkleTreeLib tree (depth 32) that records every root it produces. The invariant fuzzer drives
// insert() with random leaves; the invariant asserts no historical root is ever forgotten, which is the
// anti-Nomad store-all-roots property that lets a spend prove against any past root the wallet last synced.
contract MerkleTreeHandler {
    using MerkleTreeLib for MerkleTreeLib.Tree;

    // BN254 scalar field modulus; leaves are reduced into it so Field.toField accepts them (a raw bytes32 is
    // out of range ~half the time), letting the fuzzer land real inserts instead of reverting at the field check.
    uint256 internal constant FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    MerkleTreeLib.Tree internal tree;
    bytes32[] public roots;

    constructor() {
        tree.init(32);
    }

    function insert(bytes32 leaf) external {
        uint256 v = uint256(leaf) % FIELD;
        if (v == 0) return; // MerkleTreeLib rejects the zero leaf; skip so the sequence continues
        tree.insert(bytes32(v));
        roots.push(tree.getCurrentRoot());
    }

    function rootCount() external view returns (uint256) {
        return roots.length;
    }

    function known(bytes32 root) external view returns (bool) {
        return tree.isKnownRoot[root];
    }
}

contract MerkleTreeInvariant {
    MerkleTreeHandler internal handler;

    function setUp() public {
        handler = new MerkleTreeHandler();
    }

    // Each run starts from an empty tree, so a depth above 256 makes a bounded history of up to 256 roots fail
    // inside one run; at a depth of 32 a 64-root ring passes.
    /// forge-config: default.invariant.runs = 32
    /// forge-config: default.invariant.depth = 300
    function invariant_allPastRootsRemainKnown() public view {
        uint256 n = handler.rootCount();
        for (uint256 i = 0; i < n; i++) {
            require(
                handler.known(handler.roots(i)),
                "historical root was evicted"
            );
        }
    }
}
