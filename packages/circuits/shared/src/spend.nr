use crate::assert_subgroup_scalar;
use crate::{lean_imt_inclusion_proof, TREE_DEPTH};
use crate::note::{assert_asset_id, Note, NOTE_TYPE_MULTISIG, NOTE_TYPE_STANDARD, NOTE_VERSION};
use crate::note_nullifier;
use crate::owner;
use ecdh::{bjj::BJJ, ECDHTrait, Point};
use edwards::{bjj::BabyJubJub, CurveTrait};

fn spend_membership_nullifier(
    note: Note,
    leaf_index: Field,
    path: [Field; TREE_DEPTH],
) -> (Field, Field) {
    assert(note.note_version == NOTE_VERSION, "unexpected note version");
    assert_asset_id(note.asset_id);
    let leaf = note.leaf();
    let computed_root = lean_imt_inclusion_proof(leaf, leaf_index, path);
    let nf = note_nullifier::nullifier(note.psi, leaf_index);
    (nf, computed_root)
}

pub fn verify_spend(
    note: Note,
    spend_scalar: Field,
    leaf_index: Field,
    path: [Field; TREE_DEPTH],
) -> (Field, Field) {
    assert_subgroup_scalar(spend_scalar);
    let pk = BJJ::new(spend_scalar).derive_public_key();
    assert(note.owner == owner::pubkey_owner(pk), "spender does not own this note");
    assert(note.note_type == NOTE_TYPE_STANDARD, "unexpected note type");
    spend_membership_nullifier(note, leaf_index, path)
}

// Does NOT authorize: owner == Poseidon2(gpk) is public, so callers MUST also verify a FROST quorum.
pub fn open_multisig_note(
    note: Note,
    gpk: Point,
    leaf_index: Field,
    path: [Field; TREE_DEPTH],
) -> (Field, Field) {
    let gpk_ed = BabyJubJub::new(gpk.x, gpk.y);
    crate::subgroup::assert_in_prime_subgroup(gpk, "gpk not in prime-order subgroup");
    assert(!gpk_ed.is_zero(), "gpk must not be the identity");
    assert(note.owner == owner::pubkey_owner(gpk), "spender does not own this multisig note");
    assert(note.note_type == NOTE_TYPE_MULTISIG, "unexpected note type");
    spend_membership_nullifier(note, leaf_index, path)
}
