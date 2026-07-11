// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "../libraries/MerkleTreeLib.sol";

contract MerkleTreeLibHarness {
    using MerkleTreeLib for MerkleTreeLib.Tree;
    MerkleTreeLib.Tree public tree;

    constructor(uint32 depth) {
        tree.init(depth);
    }

    function insert(bytes32 leaf) public {
        tree.insert(leaf);
    }

    function getCurrentRoot() public view returns (bytes32) {
        return tree.getCurrentRoot();
    }

    function getNextLeafIndex() public view returns (uint256) {
        return tree.nextLeafIndex;
    }

    function isKnownRoot(bytes32 root) public view returns (bool) {
        return tree.isKnownRoot[root];
    }
}
