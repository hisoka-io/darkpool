// Index uniqueness under the membership proof.
//
// The predecessor of this file guarded the wrong axis. `packages/prover/test-harness/leaf-index-forgery`
// proves `leaf_index.to_le_bits::<32>()` bounds the index to 32 bits, which stops `k` aliasing `2^32 + k`.
// It says nothing about aliasing WITHIN 32 bits, and that is where the real forgery lived: an empty level is
// a pass-through, so the same sibling sequence placed in different slots reproduced one root under many
// indices, and `nullifier = Poseidon2(psi, leaf_index)` turned that into unlimited spends of one note.
//
// The binding is that the level is absorbed into every tree hash, so a sibling cannot move between levels.
// These tests pin the property itself, not the mechanism that delivers it.
use crate::{lean_imt_inclusion_proof, TREE_DEPTH};

global S: Field = 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383;
global T: Field = 0x232400b3cca0da78d26295f345d21e9bf8949238bee02b285140ebf183119982;

fn at(level: u32, sibling: Field) -> [Field; 8] {
    let mut p: [Field; 8] = [0; 8];
    p[level] = sibling;
    p
}

// One sibling relocated across every level must give a distinct root at every distinct index.
// Index 2^level is the index whose only set bit is at that level.
#[test]
fn one_sibling_relocated_never_repeats_a_root() {
    let leaf: Field = 4;
    let indices: [Field; 8] = [1, 2, 4, 8, 16, 32, 64, 128];
    let mut roots: [Field; 8] = [0; 8];
    for level in 0..8 {
        roots[level] = lean_imt_inclusion_proof(leaf, indices[level], at(level, S));
    }
    for a in 0..8 {
        for b in 0..8 {
            if a != b {
                assert(
                    roots[a] != roots[b],
                    "a relocated sibling reproduced a root at another index",
                );
            }
        }
    }
}

// Two siblings, order preserved, moved into a different pair of slots: still distinct.
#[test]
fn two_siblings_relocated_never_repeat_a_root() {
    let leaf: Field = 4;
    let mut low: [Field; 8] = [0; 8];
    low[0] = S;
    low[1] = T;
    let mut high: [Field; 8] = [0; 8];
    high[2] = S;
    high[3] = T;
    // indices carrying bits at {0,1} and at {2,3}
    let root_low = lean_imt_inclusion_proof(leaf, 3, low);
    let root_high = lean_imt_inclusion_proof(leaf, 12, high);
    assert(root_low != root_high, "an order-preserving relocation reproduced the root");
}

// The honest interleaved-zero shape must stay provable: in a 5-leaf tree, leaf 4 has empty levels 0 and 1
// beneath a populated level 2. A rule banning a non-zero sibling after a zero would freeze that note.
#[test]
fn interleaved_empty_levels_stay_provable() {
    let leaf: Field = 4;
    let root = lean_imt_inclusion_proof(leaf, 4, at(2, S));
    assert(root != 0, "honest interleaved-zero path failed to prove");
}

// The empty-level rule still holds: a right child at an empty level is rejected.
#[test(should_fail_with = "non-canonical leaf index: right child at empty level")]
fn right_child_at_empty_level_still_rejected() {
    let _ = lean_imt_inclusion_proof(4, 1, [0; 8]);
}

// The depth-8 cases above are the readable form. Production spends run at TREE_DEPTH = 32, and a property
// proven only at a smaller width is exactly the "true statement about a neighbouring case" this file exists
// to avoid. So relocate across all 32 real levels too.
#[test]
fn relocation_is_blocked_at_the_production_depth() {
    let leaf: Field = 4;
    let mut roots: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    // index 2^level: its only set bit sits at the level carrying the sibling. Doubled rather than shifted,
    // because a Noir shift needs both operands at one width and 2^31 does not fit the loop counter's.
    let mut index: Field = 1;
    for level in 0..TREE_DEPTH {
        let mut path: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
        path[level] = S;
        roots[level] = lean_imt_inclusion_proof(leaf, index, path);
        index = index * 2;
    }
    for a in 0..TREE_DEPTH {
        for b in 0..TREE_DEPTH {
            if a != b {
                assert(roots[a] != roots[b], "relocation reproduced a root at depth 32");
            }
        }
    }
}
