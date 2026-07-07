use crate::kem;
use crate::mint;
use crate::note::Note;
use crate::test_fixtures::{fixture_compliance_pk, fixture_note};
use crate::TREE_DEPTH;
use crate::verify_spend;
use ecdh::Point;

global VALID_SCALAR: Field = 789;
global EXPECTED_ROOT: Field = 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551;
global EXPECTED_NF: Field = 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e;

fn compliance() -> Point {
    fixture_compliance_pk()
}

fn valid_note() -> Note {
    fixture_note()
}

fn spend_at_zero(note: Note, scalar: Field, index: Field) -> (Field, Field) {
    verify_spend(note, scalar, index, [0; TREE_DEPTH])
}

#[test]
fn test_valid_spend_accepts() {
    let (nf, root) = spend_at_zero(valid_note(), VALID_SCALAR, 0);
    assert(nf == EXPECTED_NF);
    assert(root == EXPECTED_ROOT);
}

#[test(should_fail_with = "spender does not own this note")]
fn audit_wrong_spend_scalar_rejected() {
    let _ = spend_at_zero(valid_note(), 0x2a, 0);
}

#[test(should_fail_with = "spender does not own this note")]
fn audit_mutated_owner_rejected() {
    let mut note = valid_note();
    note.owner = 0xdeadbeef;
    let _ = spend_at_zero(note, VALID_SCALAR, 0);
}

// psi is committed in the leaf, so mutating it changes the membership root.
#[test(should_fail)]
fn audit_mutated_psi_breaks_membership() {
    let mut note = valid_note();
    note.psi = note.psi + 1;
    let (_, root) = spend_at_zero(note, VALID_SCALAR, 0);
    assert(root == EXPECTED_ROOT);
}

#[test(should_fail_with = "unexpected note version")]
fn audit_wrong_note_version_rejected() {
    let mut note = valid_note();
    note.note_version = 2;
    let _ = spend_at_zero(note, VALID_SCALAR, 0);
}

#[test(should_fail_with = "unexpected note type")]
fn audit_wrong_note_type_rejected() {
    let mut note = valid_note();
    note.note_type = 1;
    let _ = spend_at_zero(note, VALID_SCALAR, 0);
}

// The nullifier keys off this same index, so index malleability would mean two nullifiers per note.
#[test(should_fail_with = "non-canonical leaf index")]
fn audit_noncanonical_index_rejected() {
    let _ = spend_at_zero(valid_note(), VALID_SCALAR, 7);
}

#[test(should_fail_with = "unexpected note version")]
fn audit_mint_wrong_version() {
    let mut note = valid_note();
    note.note_version = 2;
    let _ = mint::mint_self_note(note, 5, compliance());
}

#[test(should_fail_with = "self note must be STANDARD")]
fn audit_mint_wrong_type() {
    let mut note = valid_note();
    note.note_type = 1;
    let _ = mint::mint_self_note(note, 5, compliance());
}

#[test(should_fail_with = "psi not bound to CEK")]
fn audit_mint_unbound_psi_rejected() {
    let mut note = valid_note();
    note.psi = note.psi + 1;
    let _ = mint::mint_self_note(note, 5, compliance());
}

#[test(should_fail_with = "note owner must be non-zero")]
fn audit_mint_zero_owner_rejected() {
    let mut note = valid_note();
    note.owner = 0;
    let _ = mint::mint_self_note(note, 5, compliance());
}

#[test(should_fail_with = "note conditions_hash must be zero")]
fn audit_mint_nonzero_conditions_hash_rejected() {
    let mut note = valid_note();
    note.conditions_hash = 1;
    let _ = mint::mint_self_note(note, 5, compliance());
}

// eph=456 is odd-y and its CEK yields psi 0x0441d9b1..., so mint_common passes and even-y is what fires.
#[test(should_fail_with = "self discovery tag must be even-y")]
fn audit_mint_odd_y_tag_rejected() {
    let mut note = valid_note();
    note.psi = 0x0441d9b1006cd55062a6458b5dd1db14869f1a5c8fbc66f73032208c2b109956;
    let _ = mint::mint_self_note(note, 456, compliance());
}

#[test]
fn test_cek_wrap_roundtrip() {
    let in_pub = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let eph_pub = Point {
        x: 0x06263d32df3940b1135a6a6b85bd84ea1dc0e4746a15a5d204efffec30a18010,
        y: 0x13fdbd796de262a086329a56d29f53f98f8c9e52b16939652d27eeb9646efdd1,
    };
    let cek = 0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bda;
    let wrapped = kem::wrap_cek(cek, 456, in_pub);
    assert(kem::unwrap_cek(wrapped, 789, eph_pub) == cek);
    assert(kem::unwrap_cek(wrapped + 1, 789, eph_pub) != cek);
}
