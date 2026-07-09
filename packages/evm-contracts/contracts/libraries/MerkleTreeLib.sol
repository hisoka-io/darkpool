// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Poseidon2} from "../Poseidon/Poseidon2.sol";
import {Field} from "../Poseidon/Field.sol";

/**
 * @title MerkleTreeLib
 * @author Hisoka Protocol
 * @notice Append-only Lean Incremental Merkle Tree (Poseidon2). Stores only the O(depth) frontier - the left
 * node awaiting its right sibling at each level - rather than the full node set, so per-insert cost and state
 * growth are bounded by the depth, not the leaf count. The produced root is byte-identical to a full-tree lean
 * IMT. Operates on a storage struct owned by the calling contract.
 */
library MerkleTreeLib {
    using Field for uint256;

    error TreeIsFull();
    error InvalidDepth();
    error AlreadyInitialized();
    error InvalidLeaf();

    event LeafInserted(
        uint256 indexed leafIndex,
        bytes32 leaf,
        bytes32 newRoot
    );
    event RootSaved(bytes32 indexed root);

    /// @dev `sideNodes[level]` holds the frontier: the left node waiting for its right sibling at `level`.
    ///      Every inserted root is retained forever in `isKnownRoot` (never cleared); the nullifier set, not
    ///      root recency, is the double-spend guard, so a proof against any historical root stays valid. Full
    ///      sibling paths are not held on-chain; light clients rebuild them from `LeafInserted` events.
    struct Tree {
        uint256 TREE_DEPTH;
        mapping(uint256 => bytes32) sideNodes;
        uint256 nextLeafIndex;
        bytes32 latestRoot;
        mapping(bytes32 => bool) isKnownRoot;
    }

    function init(Tree storage self, uint32 _depth) internal {
        if (self.TREE_DEPTH != 0) revert AlreadyInitialized();
        if (_depth == 0 || _depth > 32) revert InvalidDepth();
        self.TREE_DEPTH = _depth;
    }

    function insert(
        Tree storage self,
        bytes32 _leaf
    ) internal returns (uint256) {
        if (_leaf == bytes32(0)) revert InvalidLeaf();
        uint256 depth = self.TREE_DEPTH;
        uint256 leafIndex = self.nextLeafIndex;
        if (leafIndex >= (1 << depth)) revert TreeIsFull();

        bytes32 node = _leaf;
        uint256 index = leafIndex;

        // Counters are bounded by depth (<=32) and index < 2^depth, so the increments cannot overflow.
        for (uint256 level = 0; level < depth; ) {
            if (index & 1 == 0) {
                // Left child, right sibling still empty: lean rule keeps the parent equal to the left child
                // (no hash). Record it as this level's frontier for the sibling that arrives later.
                self.sideNodes[level] = node;
            } else {
                // Right child: the left sibling is the recorded frontier (always populated for an append-only
                // tree at an odd position), so hash left||right.
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
        _saveRoot(self, node);
        emit LeafInserted(leafIndex, _leaf, node);
        return leafIndex;
    }

    function _saveRoot(Tree storage self, bytes32 _root) private {
        self.isKnownRoot[_root] = true;
        self.latestRoot = _root;
        emit RootSaved(_root);
    }

    function getCurrentRoot(Tree storage self) internal view returns (bytes32) {
        return self.latestRoot;
    }
}
