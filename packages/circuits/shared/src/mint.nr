//! Minting: bind one note plaintext to its ciphertext, leaf, and psi under a single in-circuit CEK =
//! (eph*C).x. The leaf commits the PLAINTEXT, so psi == Poseidon2(CEK, PSI_DOMAIN) is asserted against the
//! committed field: a mis-derived psi both locks the note (readers re-derive psi from CEK) and breaks
//! compliance tracing.

use crate::assert_subgroup_scalar;
use crate::dem;
use crate::even_y;
use crate::kem;
use crate::note_nullifier;
use crate::note_v2::{assert_asset_id, Note, NOTE_TYPE_STANDARD, NOTE_VERSION};
use crate::owner;
use ecdh::{bjj::{BJJ, check_subgroup}, ECDHTrait, Point};
use edwards::{bjj::BabyJubJub, CurveTrait};

// Subgroup + non-identity check on C so a low-order key cannot leak a compliance share via the cofactor.
pub fn assert_valid_compliance_pk(c: Point) {
    let c_ed = BabyJubJub::new(c.x, c.y);
    assert(check_subgroup(c_ed), "compliance key not in prime-order subgroup");
    assert(!c_ed.is_zero(), "compliance key must not be the identity");
}

// The 7 transmitted DEM fields, fixed order k=0..6 (leaf's stable-first order minus the never-sent psi).
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
    assert(note.note_type == NOTE_TYPE_STANDARD, "unexpected note type");
    assert(note.conditions_hash == 0, "standard note conditions_hash must be zero");
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
    // eph_pub.x IS the self discovery tag (fresh per note, even-y for an injective Raven key).
    pub eph_pub: Point,
    pub ciphertext: [Field; dem::DEM_FIELDS],
}

// Self / change / deposit output: the creator controls eph, so there is no wrap; the tag is eph_pub.x.
pub fn mint_self_note(note: Note, eph: Field, compliance_pk: Point) -> SelfMint {
    let (leaf, eph_pub, _cek, ciphertext) = mint_common(note, eph, compliance_pk);
    assert(even_y::is_even_y(eph_pub), "self discovery tag must be even-y");
    SelfMint { leaf, eph_pub, ciphertext }
}

pub struct IncomingMint {
    pub leaf: Field,
    pub eph_pub: Point,
    // in_pub_j.x: the incoming discovery tag (static per recipient address, even-y).
    pub tag: Field,
    pub cek_wrap: Field,
    pub ciphertext: [Field; dem::DEM_FIELDS],
}

// Incoming memo: owner bound to owner == Poseidon2(in_pub_j) so a sender cannot mint to an unspendable
// owner, and CEK is wrapped to the recipient who unwraps from in_key_j + eph_pub.
pub fn mint_incoming_note(
    note: Note,
    eph: Field,
    compliance_pk: Point,
    in_pub_j: Point,
) -> IncomingMint {
    // Recipient address is attacker-supplied; validate like C so no low-order/off-curve point slips in.
    let in_ed = BabyJubJub::new(in_pub_j.x, in_pub_j.y);
    assert(check_subgroup(in_ed), "recipient address not in prime-order subgroup");
    assert(!in_ed.is_zero(), "recipient address must not be the identity");
    assert(note.owner == owner::pubkey_owner(in_pub_j), "memo owner must be the recipient owner");
    let (leaf, eph_pub, cek, ciphertext) = mint_common(note, eph, compliance_pk);
    assert(even_y::is_even_y(in_pub_j), "incoming discovery tag must be even-y");
    let cek_wrap = kem::wrap_cek(cek, eph, in_pub_j);
    IncomingMint { leaf, eph_pub, tag: in_pub_j.x, cek_wrap, ciphertext }
}
