// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "../libraries/MerkleTreeLib.sol";

contract MerkleTreeLibHarness {
    using MerkleTreeLib for MerkleTreeLib.Tree;
    MerkleTreeLib.Tree public tree;

    constructor(uint32 depth, uint32 rootHistorySize) {
        tree.init(depth, rootHistorySize);
    }

    function insert(bytes32 leaf) public {
        tree.insert(leaf);
    }

    function getCurrentRoot() public view returns (bytes32) {
        return tree.getCurrentRoot();
    }

    function getMerklePath(
        uint256 leafIndex
    ) public view returns (bytes32[32] memory) {
        return tree.getMerklePath(leafIndex);
    }

    function getNextLeafIndex() public view returns (uint256) {
        return tree.nextLeafIndex;
    }

    function getSubtreeWithProof(
        uint256 treeLevel,
        uint256 positionAtLevel
    ) public view returns (bytes32[] memory proof, bytes32[] memory leafs) {
        return tree.getSubtreeWithProof(treeLevel, positionAtLevel);
    }
}
