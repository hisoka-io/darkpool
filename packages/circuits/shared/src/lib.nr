mod common;
mod multisig;
mod spend;
mod harness;
pub mod mint;

pub use common::{conservation, note, test_fixtures};
use common::{dem, domains, even_y, kem, note_nullifier, owner};
pub use multisig::frost;
pub use spend::{open_multisig_note, verify_spend};

use poseidon::poseidon2::Poseidon2;

pub global TREE_DEPTH: u32 = 32;

// BabyJubJub prime-order subgroup order.
// https://docs.iden3.io/publications/pdfs/Baby-Jubjub.pdf
pub global SUBORDER: Field =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;

// Double-spend is bound by leaf_index + the psi nullifier elsewhere, not by this range check.
pub fn assert_subgroup_scalar(x: Field) {
    assert(x != 0, "scalar must be non-zero");
    assert(x.lt(SUBORDER), "scalar not in BabyJubJub prime-order subgroup");
}

pub fn lean_imt_inclusion_proof<let MAX_DEPTH: u32>(
    leaf: Field,
    leaf_index: Field,
    siblings: [Field; MAX_DEPTH],
) -> Field {
    let path_bits: [u1; MAX_DEPTH] = leaf_index.to_le_bits();
    let mut current = leaf;

    for i in 0..MAX_DEPTH {
        let sibling = siblings[i];
        if sibling != 0 {
            let path_bit = path_bits[i] as Field;
            let left = current + path_bit * (sibling - current);
            let right = sibling + path_bit * (current - sibling);
            current = Poseidon2::hash([left, right], 2);
        } else {
            assert(path_bits[i] == 0, "non-canonical leaf index: right child at empty level");
        }
    }
    current
}

#[test]
pub fn test_lean_imt_inclusion_proof() {
    let leaf: Field = (4 as u8).into();
    let leaf_index: Field = (3 as u8).into();
    let siblings: [Field; 8] = [
        3,
        0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
        0x232400b3cca0da78d26295f345d21e9bf8949238bee02b285140ebf183119982,
        0,
        0,
        0,
        0,
        0,
    ];
    let root = lean_imt_inclusion_proof(leaf, leaf_index, siblings);
    assert(root == 0x05d7e5aaddb74c086c24617065e8c97dea94b86fdae0eab7b498249e0dfee2a8);
}
