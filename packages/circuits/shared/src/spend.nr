use crate::assert_subgroup_scalar;
use crate::{lean_imt_inclusion_proof, TREE_DEPTH};
use crate::note::{assert_asset_id, Note, NOTE_TYPE_MULTISIG, NOTE_TYPE_STANDARD, NOTE_VERSION};
use crate::note_nullifier;
use crate::owner;
use ecdh::{bjj::{BJJ, check_subgroup}, ECDHTrait, Point};
use edwards::{bjj::BabyJubJub, CurveTrait};

// Shared spend core called by BOTH the standard and multisig paths: version + asset checks, membership
// folded in (so a spend cannot omit it), and the canonical index feeding the nullifier (one spendable index
// per note). computed_root is returned as a public output the contract range-checks against its known roots.
// Extracting it keeps the conserve/asset/membership/nullifier tail from being hand-copied per path.
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

// Consume a STANDARD note: the spender proves the scalar whose pubkey commits owner, then the shared core
// folds membership + nullifier. The note_type pin plus its commitment in the leaf stop a MULTISIG note being
// routed through a standard verifier or vice versa.
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

// OPEN a MULTISIG note for spending: validate the account key gpk (subgroup + non-identity), bind the note
// owner to it, pin note_type, and fold membership + the canonical nullifier. This gadget does NOT AUTHORIZE
// the spend -- owner == Poseidon2(gpk) is public-computable, so it only proves "a well-formed MULTISIG note
// owned by the gpk supplied." The CALLER MUST verify a FROST quorum signature over the op message m (which
// binds this nullifier + root) via frost::verify_frost_spend; the message depends on this gadget's outputs
// (and join binds two nullifiers under one message), so the FROST check cannot be folded in here. Named
// `open_*` not `verify_*` precisely so no caller mistakes membership-opening for authorization.
pub fn open_multisig_note(
    note: Note,
    gpk: Point,
    leaf_index: Field,
    path: [Field; TREE_DEPTH],
) -> (Field, Field) {
    let gpk_ed = BabyJubJub::new(gpk.x, gpk.y);
    assert(check_subgroup(gpk_ed), "gpk not in prime-order subgroup");
    assert(!gpk_ed.is_zero(), "gpk must not be the identity");
    assert(note.owner == owner::pubkey_owner(gpk), "spender does not own this multisig note");
    assert(note.note_type == NOTE_TYPE_MULTISIG, "unexpected note type");
    spend_membership_nullifier(note, leaf_index, path)
}
