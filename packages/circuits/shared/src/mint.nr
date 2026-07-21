//! psi == Poseidon2(CEK, PSI_DOMAIN) asserted against the committed leaf field, so a mis-derived psi locks
//! the note and breaks compliance tracing.

use crate::assert_subgroup_scalar;
use crate::dem;
use crate::even_y;
use crate::kem;
use crate::note::{
    assert_asset_id, assert_valid_note_type, Note, NOTE_TYPE_MULTISIG, NOTE_TYPE_STANDARD,
    NOTE_VERSION,
};
use crate::note_nullifier;
use crate::owner;
use ecdh::{bjj::{BJJ, check_subgroup}, ECDHTrait, Point};
use edwards::{bjj::BabyJubJub, CurveTrait};

pub fn assert_valid_compliance_pk(c: Point) {
    let c_ed = BabyJubJub::new(c.x, c.y);
    assert(check_subgroup(c_ed), "compliance key not in prime-order subgroup");
    assert(!c_ed.is_zero(), "compliance key must not be the identity");
}

fn assert_valid_recipient_key(p: Point) {
    let ed = BabyJubJub::new(p.x, p.y);
    assert(check_subgroup(ed), "recipient key not in prime-order subgroup");
    assert(!ed.is_zero(), "recipient key must not be the identity");
}

fn transmitted_fields(note: Note) -> [Field; dem::DEM_FIELDS] {
    [
        note.note_version,
        note.asset_id,
        note.note_type,
        note.conditions_hash,
        note.value as Field,
        note.owner,
        note.parents,
    ]
}

fn mint_common(
    note: Note,
    eph: Field,
    compliance_pk: Point,
) -> (Field, Point, Field, [Field; dem::DEM_FIELDS]) {
    assert_subgroup_scalar(eph);
    assert(note.owner != 0, "note owner must be non-zero");
    assert(note.note_version == NOTE_VERSION, "unexpected note version");
    assert_valid_note_type(note.note_type);
    assert(note.conditions_hash == 0, "note conditions_hash must be zero");
    assert_asset_id(note.asset_id);

    let cek = kem::derive_cek(eph, compliance_pk);
    assert(note.psi == note_nullifier::psi(cek), "psi not bound to CEK");

    let eph_pub = BJJ::new(eph).derive_public_key();
    let ciphertext = dem::dem_encrypt(cek, transmitted_fields(note));
    let leaf = note.leaf();
    (leaf, eph_pub, cek, ciphertext)
}

pub struct SelfMint {
    pub leaf: Field,
    pub eph_pub: Point,
    pub ciphertext: [Field; dem::DEM_FIELDS],
}

pub fn mint_self_note(note: Note, eph: Field, compliance_pk: Point) -> SelfMint {
    assert(note.note_type == NOTE_TYPE_STANDARD, "self note must be STANDARD");
    let (leaf, eph_pub, _cek, ciphertext) = mint_common(note, eph, compliance_pk);
    assert(even_y::is_even_y(eph_pub), "self discovery tag must be even-y");
    SelfMint { leaf, eph_pub, ciphertext }
}

// owner == Poseidon2(gpk) pins change to the spending account: without it a coordinator could redirect the
// group's residual to a solo key (theft-from-group). FROST binds only the output leaf, so this pin is the sole guard.
pub fn mint_self_note_multisig(
    note: Note,
    eph: Field,
    compliance_pk: Point,
    gpk: Point,
) -> SelfMint {
    assert(note.note_type == NOTE_TYPE_MULTISIG, "multisig self note must be MULTISIG");
    assert(
        note.owner == owner::pubkey_owner(gpk),
        "multisig change/self must be owned by the account gpk",
    );
    let (leaf, eph_pub, _cek, ciphertext) = mint_common(note, eph, compliance_pk);
    assert(even_y::is_even_y(eph_pub), "self discovery tag must be even-y");
    SelfMint { leaf, eph_pub, ciphertext }
}

pub fn mint_deposit(note: Note, eph: Field, compliance_pk: Point) -> SelfMint {
    let (leaf, eph_pub, _cek, ciphertext) = mint_common(note, eph, compliance_pk);
    assert(even_y::is_even_y(eph_pub), "deposit discovery tag must be even-y");
    SelfMint { leaf, eph_pub, ciphertext }
}

pub struct IncomingMint {
    pub leaf: Field,
    pub eph_pub: Point,
    pub tag: Field,
    pub cek_wrap: Field,
    pub ciphertext: [Field; dem::DEM_FIELDS],
}

// owner/wrap/tag all bind in_pub_j, so no owned-but-undiscoverable memo (griefing lock). Pinned STANDARD:
// a MULTISIG memo needs owner/view decoupled (deferred feature).
pub fn mint_incoming_note(
    note: Note,
    eph: Field,
    compliance_pk: Point,
    in_pub: Point,
) -> IncomingMint {
    assert(note.note_type == NOTE_TYPE_STANDARD, "incoming memo must be STANDARD");
    assert_valid_recipient_key(in_pub);
    assert(note.owner == owner::pubkey_owner(in_pub), "memo owner must be the recipient owner");
    let (leaf, eph_pub, cek, ciphertext) = mint_common(note, eph, compliance_pk);
    assert(even_y::is_even_y(in_pub), "incoming discovery tag must be even-y");
    // The emitted eph_pub rides on-chain as x only, so it must be even-y for the recipient/compliance to
    // recover y from x before the unwrap ECDH (mint_self and deposit pin this too).
    assert(even_y::is_even_y(eph_pub), "incoming eph tag must be even-y");
    let cek_wrap = kem::wrap_cek(cek, eph, in_pub);
    IncomingMint { leaf, eph_pub, tag: in_pub.x, cek_wrap, ciphertext }
}
