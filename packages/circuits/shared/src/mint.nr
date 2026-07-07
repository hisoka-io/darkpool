//! Minting: bind one note plaintext to its ciphertext, leaf, and psi under a single in-circuit CEK =
//! (eph*C).x. The leaf commits the PLAINTEXT, so psi == Poseidon2(CEK, PSI_DOMAIN) is asserted against the
//! committed field: a mis-derived psi both locks the note (readers re-derive psi from CEK) and breaks
//! compliance tracing. note_type + owner are sender-chosen witnesses (a STANDARD or a MULTISIG output); the
//! per-output helpers pin type where authority demands it (self/change to the spender, memo to the sender's
//! chosen recipient key).

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

// Subgroup + non-identity check on C so a low-order key cannot leak a compliance share via the cofactor.
pub fn assert_valid_compliance_pk(c: Point) {
    let c_ed = BabyJubJub::new(c.x, c.y);
    assert(check_subgroup(c_ed), "compliance key not in prime-order subgroup");
    assert(!c_ed.is_zero(), "compliance key must not be the identity");
}

// An attacker-supplied recipient point (owner key / viewing key): reject off-curve, identity, and low-order
// so no ECDH scalar leaks via the cofactor and no owner commits to an unspendable point.
fn assert_valid_recipient_key(p: Point) {
    let ed = BabyJubJub::new(p.x, p.y);
    assert(check_subgroup(ed), "recipient key not in prime-order subgroup");
    assert(!ed.is_zero(), "recipient key must not be the identity");
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

// Common mint core: note_type is a witness constrained to the enabled set (never pinned here), owner is
// non-zero, psi is bound to the in-circuit CEK, and the plaintext is committed to the leaf and encrypted.
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
    // eph_pub.x IS the self discovery tag (fresh per note, even-y for an injective Raven key).
    pub eph_pub: Point,
    pub ciphertext: [Field; dem::DEM_FIELDS],
}

// Self / change output owned by a STANDARD spender: type pinned to the spender's own so a spend cannot mint
// its change to a different authority class. The creator controls eph, so there is no wrap; tag = eph_pub.x.
pub fn mint_self_note(note: Note, eph: Field, compliance_pk: Point) -> SelfMint {
    assert(note.note_type == NOTE_TYPE_STANDARD, "self note must be STANDARD");
    let (leaf, eph_pub, _cek, ciphertext) = mint_common(note, eph, compliance_pk);
    assert(even_y::is_even_y(eph_pub), "self discovery tag must be even-y");
    SelfMint { leaf, eph_pub, ciphertext }
}

// Self / change output owned by a FROST account. BOTH note_type == MULTISIG AND owner == Poseidon2(gpk) are
// pinned to the SPENDING account (the same gpk open_multisig_note bound the consumed input to), so a malicious
// coordinator cannot redirect the change to a solo key it could later spend alone via a 1-of-1 Schnorr,
// draining the group's residual past the t-of-n quorum (theft-from-group). The FROST message binds only the
// output LEAF, not the owner separately, so this in-circuit owner pin is what actually stops the redirect --
// members do not have to inspect the leaf preimage before signing. Identical KEM/DEM/discovery to a standard
// self note; the coordinator derives eph from the shared viewing key v (member-partitioned) so every member
// re-derives CEK = (eph*C).x and reads it.
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

// Deposit output: a pure self-mint funding either a STANDARD or a MULTISIG account. note_type + owner are
// witnesses (validated in mint_common); no owner well-formedness beyond owner != 0, matching the permissive
// standard deposit (a malformed owner only self-harms the depositor). Anyone may fund any account.
pub fn mint_deposit(note: Note, eph: Field, compliance_pk: Point) -> SelfMint {
    let (leaf, eph_pub, _cek, ciphertext) = mint_common(note, eph, compliance_pk);
    assert(even_y::is_even_y(eph_pub), "deposit discovery tag must be even-y");
    SelfMint { leaf, eph_pub, ciphertext }
}

pub struct IncomingMint {
    pub leaf: Field,
    pub eph_pub: Point,
    // in_pub.x: the incoming discovery tag (static per recipient address, even-y).
    pub tag: Field,
    pub cek_wrap: Field,
    pub ciphertext: [Field; dem::DEM_FIELDS],
}

// Incoming memo to a recipient address in_pub_j. Under Option A the address IS the spend + view + discovery
// key (one key), so owner, the cek_wrap target, and the tag ALL bind to in_pub_j. Binding the owner therefore
// also binds the discovery/wrap key -- a minter cannot produce an owned-but-undiscoverable memo (griefing
// lock). The memo is PINNED to STANDARD: sending to a MULTISIG account (owner = Poseidon2(gpk) != the viewing
// key V) needs owner/view decoupled and carries the same unproven-V gap as group public-claim, so it is a
// DEFERRED feature -- the note_type pin makes a degenerate MULTISIG memo (owner==view==tag==gpk, unspendable)
// unmintable here rather than merely undiscoverable.
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
    let cek_wrap = kem::wrap_cek(cek, eph, in_pub);
    IncomingMint { leaf, eph_pub, tag: in_pub.x, cek_wrap, ciphertext }
}
