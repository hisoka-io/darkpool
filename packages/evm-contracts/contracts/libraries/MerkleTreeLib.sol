// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import {Poseidon2} from "../Poseidon/Poseidon2.sol";
import {Field} from "../Poseidon/Field.sol";

/**
 * @title MerkleTreeLib
 * @notice Append-only Lean Incremental Merkle Tree (Poseidon2) storing only the O(depth) frontier. The root
 * is byte-identical to a full-tree lean IMT. Operates on a storage struct owned by the calling contract.
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
    ///      root recency, is the double-spend guard, so a proof against any historical root stays valid.
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
                self.sideNodes[level] = node;
                // The frontier write must precede this break -- leaf 2^L reads the slot as its left sibling.
                if (index == 0) break;
            } else {
                // Odd position: the frontier is the left sibling, so hash left||right||level. The level is
                // absorbed so a sibling cannot be relocated between levels; see the matching binding in
                // Noir `lean_imt_inclusion_proof` and `LeanIMT.ts`.
                node = bytes32(
                    Field.Type.unwrap(
                        Poseidon2.hash_3(
                            uint256(self.sideNodes[level]).toField(),
                            uint256(node).toField(),
                            level.toField()
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
