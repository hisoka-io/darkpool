// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Poseidon2} from "../Poseidon/Poseidon2.sol";
import {Field} from "../Poseidon/Field.sol";

/**
 * @title MerkleTreeLib
 * @author Hisoka Protocol
 * @notice A library for managing the state and logic of a Lean Incremental Merkle Tree.
 * It operates on a storage struct provided by the calling contract.
 */
library MerkleTreeLib {
    using Field for uint256;

    error TreeIsFull();
    error InvalidDepth();
    error InvalidRootHistorySize();
    error InvalidLeaf();
    error LevelOutOfBounds();
    error PositionOutOfBounds();
    error LeafIndexOutOfBounds();
    error SubtreeTooLarge();

    event LeafInserted(
        uint256 indexed leafIndex,
        bytes32 leaf,
        bytes32 newRoot
    );
    event RootSaved(uint256 indexed rootIndex, bytes32 root);

    /// @dev Root history is a ring buffer; a root evicted after ROOT_HISTORY_SIZE later inserts
    ///      makes `isKnownRoot` false, so clients must submit proofs before their root goes stale.
    struct Tree {
        uint256 TREE_DEPTH;
        uint256 ROOT_HISTORY_SIZE;
        bytes32[][] levels;
        bytes32[] roots;
        uint256 currentRootIndex;
        uint256 nextLeafIndex;
        mapping(bytes32 => bool) isKnownRoot;
    }

    function init(
        Tree storage self,
        uint32 _depth,
        uint32 _rootHistorySize
    ) internal {
        if (_depth == 0 || _depth > 32) revert InvalidDepth();
        if (_rootHistorySize == 0) revert InvalidRootHistorySize();
        self.TREE_DEPTH = _depth;
        self.ROOT_HISTORY_SIZE = _rootHistorySize;
        self.levels = new bytes32[][](_depth);
        self.roots = new bytes32[](_rootHistorySize);
    }

    function insert(
        Tree storage self,
        bytes32 _leaf
    ) internal returns (uint256) {
        if (_leaf == bytes32(0)) revert InvalidLeaf();
        uint256 leafIndex = self.nextLeafIndex;
        if (leafIndex >= (1 << self.TREE_DEPTH)) {
            revert TreeIsFull();
        }

        self.levels[0].push(_leaf);
        self.nextLeafIndex++;

        bytes32 currentComputedNode = _leaf;
        uint256 currentIndexInLevel = leafIndex;

        for (uint256 level = 0; level < self.TREE_DEPTH; ++level) {
            uint256 siblingIndex = currentIndexInLevel ^ 1;

            bytes32 siblingNode = (siblingIndex < self.levels[level].length)
                ? self.levels[level][siblingIndex]
                : bytes32(0);

            bytes32 left = (currentIndexInLevel & 1) == 0
                ? currentComputedNode
                : siblingNode;
            bytes32 right = (currentIndexInLevel & 1) == 0
                ? siblingNode
                : currentComputedNode;

            if (right == bytes32(0)) {
                currentComputedNode = left;
            } else if (left == bytes32(0)) {
                currentComputedNode = right;
            } else {
                currentComputedNode = bytes32(
                    Field.Type.unwrap(
                        Poseidon2.hash_2(
                            uint256(left).toField(),
                            uint256(right).toField()
                        )
                    )
                );
            }

            uint256 parentIndex = currentIndexInLevel / 2;

            if (level < self.TREE_DEPTH - 1) {
                if (parentIndex >= self.levels[level + 1].length) {
                    self.levels[level + 1].push(currentComputedNode);
                } else {
                    self.levels[level + 1][parentIndex] = currentComputedNode;
                }
            }
            currentIndexInLevel = parentIndex;
        }

        _saveRoot(self, currentComputedNode);
        emit LeafInserted(leafIndex, _leaf, currentComputedNode);
        return leafIndex;
    }

    function _saveRoot(Tree storage self, bytes32 _root) private {
        if (self.ROOT_HISTORY_SIZE > 0) {
            bytes32 oldRoot = self.roots[self.currentRootIndex];
            if (oldRoot != bytes32(0)) {
                self.isKnownRoot[oldRoot] = false;
            }
            self.roots[self.currentRootIndex] = _root;
            self.isKnownRoot[_root] = true;
            emit RootSaved(self.currentRootIndex, _root);
            self.currentRootIndex =
                (self.currentRootIndex + 1) %
                self.ROOT_HISTORY_SIZE;
        }
    }

    function getCurrentRoot(Tree storage self) internal view returns (bytes32) {
        if (self.nextLeafIndex == 0) return bytes32(0);
        uint256 indexToReturn = (self.currentRootIndex == 0)
            ? self.ROOT_HISTORY_SIZE - 1
            : self.currentRootIndex - 1;
        return self.roots[indexToReturn];
    }

    /// @notice Sibling path (32 nodes, leaf level up to root) for light clients to build proofs.
    function getMerklePath(
        Tree storage self,
        uint256 leafIndex
    ) internal view returns (bytes32[32] memory path) {
        if (leafIndex >= self.nextLeafIndex) revert LeafIndexOutOfBounds();

        uint256 currentIndex = leafIndex;

        for (uint256 level = 0; level < self.TREE_DEPTH; ++level) {
            uint256 siblingIndex = currentIndex ^ 1;

            if (siblingIndex < self.levels[level].length) {
                path[level] = self.levels[level][siblingIndex];
            } else {
                path[level] = bytes32(0);
            }

            currentIndex = currentIndex / 2;
        }

        return path;
    }

    function getSubtreeWithProof(
        Tree storage self,
        uint256 treeLevel,
        uint256 positionAtLevel
    ) internal view returns (bytes32[] memory proof, bytes32[] memory leafs) {
        if (treeLevel > self.TREE_DEPTH) revert LevelOutOfBounds();
        if (positionAtLevel >= (1 << (self.TREE_DEPTH - treeLevel)))
            revert PositionOutOfBounds();

        // bound the leaf allocation to the populated set so an oversized subtree reverts instead of OOG-ing the view
        uint256 maxSubtreeLeafs = self.nextLeafIndex == 0
            ? 1
            : self.nextLeafIndex << 1;
        if ((1 << treeLevel) > maxSubtreeLeafs) revert SubtreeTooLarge();

        uint256 levelFromRoot = self.TREE_DEPTH - treeLevel;

        proof = new bytes32[](levelFromRoot);
        uint256 currentPos = positionAtLevel;

        for (uint256 i = 0; i < levelFromRoot; i++) {
            uint256 siblingPos = currentPos ^ 1;
            uint256 currentTreeLevel = treeLevel + i;

            if (siblingPos < self.levels[currentTreeLevel].length) {
                proof[i] = self.levels[currentTreeLevel][siblingPos];
            } else {
                proof[i] = bytes32(0);
            }

            currentPos >>= 1;
        }

        uint256 numLeafs = 1 << treeLevel;
        uint256 leftmostLeafIndex = positionAtLevel << treeLevel;

        leafs = new bytes32[](numLeafs);
        for (uint256 i = 0; i < numLeafs; i++) {
            uint256 leafIndex = leftmostLeafIndex + i;
            if (leafIndex < self.levels[0].length) {
                leafs[i] = self.levels[0][leafIndex];
            } else {
                leafs[i] = bytes32(0);
            }
        }
    }
}
