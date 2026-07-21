// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "../libraries/MerkleTreeLib.sol";
import {Poseidon2} from "../Poseidon/Poseidon2.sol";
import {Field} from "../Poseidon/Field.sol";

/**
 * @dev Test-only frontier walk that runs every level unconditionally: the differential reference for
 * MerkleTreeLib.insert. Above the tree top the running index is 0, so each remaining level rewrites
 * sideNodes[level] with an unchanged `node`. Operates on MerkleTreeLib.Tree so the frontier of a
 * reference tree and a production tree are slot-for-slot comparable.
 */
library FullWalkMerkleTree {
    using Field for uint256;

    // Mirrors MerkleTreeLib's log output so a gas delta against it is the walk, not the events.
    event LeafInserted(
        uint256 indexed leafIndex,
        bytes32 leaf,
        bytes32 newRoot
    );
    event RootSaved(bytes32 indexed root);

    function insert(
        MerkleTreeLib.Tree storage self,
        bytes32 _leaf
    ) internal returns (uint256) {
        if (_leaf == bytes32(0)) revert MerkleTreeLib.InvalidLeaf();
        uint256 depth = self.TREE_DEPTH;
        uint256 leafIndex = self.nextLeafIndex;
        if (leafIndex >= (1 << depth)) revert MerkleTreeLib.TreeIsFull();

        bytes32 node = _leaf;
        uint256 index = leafIndex;

        for (uint256 level = 0; level < depth; ) {
            if (index & 1 == 0) {
                self.sideNodes[level] = node;
            } else {
                node = bytes32(
                    Field.Type.unwrap(
                        Poseidon2.hash_2(
                            uint256(self.sideNodes[level]).toField(),
                            uint256(node).toField()
                        )
                    )
                );
            }
            unchecked {
                index >>= 1;
                ++level;
            }
        }

        unchecked {
            self.nextLeafIndex = leafIndex + 1;
        }
        self.isKnownRoot[node] = true;
        self.latestRoot = node;
        emit RootSaved(node);
        emit LeafInserted(leafIndex, _leaf, node);
        return leafIndex;
    }
}

/**
 * @dev Test-only MUTANT: skips the frontier write at the first index==0 level. That write is live (leaf 2^L-1
 * stores the left-subtree root that leaf 2^L reads as its left sibling), so this diverges at every power-of-two
 * crossing. Proves the boundary suite fails when the write is dropped; nothing may depend on it.
 */
library BreakBeforeWriteMerkleTree {
    using Field for uint256;

    event LeafInserted(
        uint256 indexed leafIndex,
        bytes32 leaf,
        bytes32 newRoot
    );
    event RootSaved(bytes32 indexed root);

    function insert(
        MerkleTreeLib.Tree storage self,
        bytes32 _leaf
    ) internal returns (uint256) {
        if (_leaf == bytes32(0)) revert MerkleTreeLib.InvalidLeaf();
        uint256 depth = self.TREE_DEPTH;
        uint256 leafIndex = self.nextLeafIndex;
        if (leafIndex >= (1 << depth)) revert MerkleTreeLib.TreeIsFull();

        bytes32 node = _leaf;
        uint256 index = leafIndex;

        for (uint256 level = 0; level < depth; ) {
            if (index == 0) break;
            if (index & 1 == 0) {
                self.sideNodes[level] = node;
            } else {
                node = bytes32(
                    Field.Type.unwrap(
                        Poseidon2.hash_2(
                            uint256(self.sideNodes[level]).toField(),
                            uint256(node).toField()
                        )
                    )
                );
            }
            unchecked {
                index >>= 1;
                ++level;
            }
        }

        unchecked {
            self.nextLeafIndex = leafIndex + 1;
        }
        self.isKnownRoot[node] = true;
        self.latestRoot = node;
        emit RootSaved(node);
        emit LeafInserted(leafIndex, _leaf, node);
        return leafIndex;
    }
}

/// @dev Shared surface so the three insert variants are compared through an identical ABI.
abstract contract MerkleTreeHarnessBase {
    using MerkleTreeLib for MerkleTreeLib.Tree;

    MerkleTreeLib.Tree internal tree;
    bytes32[] internal rootHistory;

    function _doInsert(bytes32 leaf) internal virtual;

    function insert(bytes32 leaf) public {
        _doInsert(leaf);
    }

    /// @dev One tx per sequence: records the root after every insert so a fuzz run can compare each step.
    function insertMany(bytes32[] calldata leaves) public {
        for (uint256 i = 0; i < leaves.length; ++i) {
            _doInsert(leaves[i]);
            rootHistory.push(tree.latestRoot);
        }
    }

    function sideNode(uint256 level) public view returns (bytes32) {
        return tree.sideNodes[level];
    }

    /// @dev Fakes the storage shape of a tree holding `leafIndex` leaves (seeds `filledLevels` frontier slots)
    ///      so mature-tree/upgraded-proxy gas is exact. Invariant: injected nodes are not real subtree roots, so
    ///      a warped tree is only valid against another walk over the SAME warped state, never as a standalone root.
    function warpTo(uint256 leafIndex, uint256 filledLevels) public {
        tree.nextLeafIndex = leafIndex;
        for (uint256 level = 0; level < filledLevels; ++level) {
            // Non-zero and in-field: the walk feeds a frontier node straight into Poseidon2 on the odd branch.
            uint256 v = (uint256(keccak256(abi.encode("warp", level))) %
                (Field.PRIME - 1)) + 1;
            tree.sideNodes[level] = bytes32(v);
        }
    }

    function getRootHistory() public view returns (bytes32[] memory) {
        return rootHistory;
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

contract MerkleTreeLibHarness is MerkleTreeHarnessBase {
    using MerkleTreeLib for MerkleTreeLib.Tree;

    constructor(uint32 depth) {
        tree.init(depth);
    }

    function _doInsert(bytes32 leaf) internal override {
        tree.insert(leaf);
    }
}

contract FullWalkMerkleTreeHarness is MerkleTreeHarnessBase {
    using FullWalkMerkleTree for MerkleTreeLib.Tree;
    using MerkleTreeLib for MerkleTreeLib.Tree;

    constructor(uint32 depth) {
        tree.init(depth);
    }

    function _doInsert(bytes32 leaf) internal override {
        FullWalkMerkleTree.insert(tree, leaf);
    }
}

contract BreakBeforeWriteMerkleTreeHarness is MerkleTreeHarnessBase {
    using BreakBeforeWriteMerkleTree for MerkleTreeLib.Tree;
    using MerkleTreeLib for MerkleTreeLib.Tree;

    constructor(uint32 depth) {
        tree.init(depth);
    }

    function _doInsert(bytes32 leaf) internal override {
        BreakBeforeWriteMerkleTree.insert(tree, leaf);
    }
}
