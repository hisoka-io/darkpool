//! psi == Poseidon2(CEK, PSI_DOMAIN) is asserted against the leaf; a mis-derived psi locks the note.

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

// FROST binds only the output leaf, so this owner pin is the sole guard on the group's change note.
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

pub fn mint_incoming_note(
    note: Note,
    eph: Field,
    compliance_pk: Point,
    spend_pub: Point,
    view_pub: Point,
) -> IncomingMint {
    let is_std = (note.note_type == NOTE_TYPE_STANDARD) as Field;
    let is_ms = (note.note_type == NOTE_TYPE_MULTISIG) as Field;
    // Sum == 1 rather than an OR so a future CONDITIONAL type fails closed here.
    assert(is_std + is_ms == 1, "incoming memo note_type must be STANDARD or MULTISIG");
    // y is pinned too: x-equality alone admits the y-twin (x, -y), whose owner no scalar can ever open.
    let same_x = (spend_pub.x == view_pub.x) as Field;
    assert(same_x == is_std, "STANDARD memo must collapse spend/view; MULTISIG must decouple them");
    assert(
        is_std * (spend_pub.y - view_pub.y) == 0,
        "STANDARD memo must collapse spend/view; MULTISIG must decouple them",
    );

    // spend_pub determines owner: a cofactor-coset key mints a leaf nobody can open, burning the funds.
    crate::subgroup::assert_in_prime_subgroup(
        spend_pub,
        "memo spend key not in prime-order subgroup",
    );
    let spend_ed = BabyJubJub::new(spend_pub.x, spend_pub.y);
    assert(!spend_ed.is_zero(), "memo spend key must not be the identity");
    assert_valid_recipient_key(view_pub);

    assert(note.owner == owner::pubkey_owner(spend_pub), "memo owner must be the recipient owner");
    let (leaf, eph_pub, cek, ciphertext) = mint_common(note, eph, compliance_pk);
    assert(even_y::is_even_y(view_pub), "incoming discovery tag must be even-y");
    assert(even_y::is_even_y(eph_pub), "incoming eph tag must be even-y");
    let cek_wrap = kem::wrap_cek(cek, eph, view_pub);
    IncomingMint { leaf, eph_pub, tag: view_pub.x, cek_wrap, ciphertext }
}
