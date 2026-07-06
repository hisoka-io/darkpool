use crate::assert_subgroup_scalar;
use crate::{lean_imt_inclusion_proof, TREE_DEPTH};
use crate::note::{assert_asset_id, Note, NOTE_TYPE_STANDARD, NOTE_VERSION};
use crate::note_nullifier;
use crate::owner;
use ecdh::{bjj::BJJ, ECDHTrait};

// Consume a STANDARD note: the spender proves the scalar whose pubkey commits owner, membership is folded
// in so a spend cannot omit it, and the canonical index feeds the nullifier (one spendable index per
// note). computed_root is a public output the contract range-checks against its known roots.
pub fn verify_spend(
    note: Note,
    spend_scalar: Field,
    leaf_index: Field,
    path: [Field; TREE_DEPTH],
) -> (Field, Field) {
    assert_subgroup_scalar(spend_scalar);
    let pk = BJJ::new(spend_scalar).derive_public_key();
    assert(note.owner == owner::pubkey_owner(pk), "spender does not own this note");
    assert(note.note_version == NOTE_VERSION, "unexpected note version");
    assert(note.note_type == NOTE_TYPE_STANDARD, "unexpected note type");
    assert_asset_id(note.asset_id);

    let leaf = note.leaf();
    let computed_root = lean_imt_inclusion_proof(leaf, leaf_index, path);
    let nf = note_nullifier::nullifier(note.psi, leaf_index);
    (nf, computed_root)
}
