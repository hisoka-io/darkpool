mod mutation_tests;

use ::ecdh::Point;
use ::shared::mint;
use ::shared::note::Note;
use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, fixture_note};

fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    note: Note,
    eph: Field,
) -> pub (Field, Field, Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    assert(note.parents == 0, "deposit output parents must be zero");

    let minted = mint::mint_deposit(note, eph, compliance_pk);

    (minted.leaf, minted.eph_pub.x, note.value as Field, note.asset_id, minted.ciphertext)
}

// TS/Noir/Solidity parity golden
#[test]
fn test_deposit_kat() {
    let (leaf, epk_x, value, asset, ct) = main(
        FIXTURE_COMPLIANCE_X,
        FIXTURE_COMPLIANCE_Y,
        fixture_note(),
        5,
    );
    assert(leaf == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
    assert(epk_x == 0x1961ff2315812fd2f3e459a258f5ded2dde68cd35c79c8b9fb443e1860e1fbe4);
    assert(value == 100);
    assert(asset == 0x1234567890123456789012345678901234567890);
    assert(ct[0] == 0x13e12fd48ec5eefe22cea1ccf4f29e16f8883011140afbe24dfe35a049b34f1d);
    assert(ct[6] == 0x0f0c848a687a5d761bda9b0043218db11eddbbdab55c4bec7d5dae04c89182cb);
}

#[test(should_fail_with = "note owner must be non-zero")]
fn audit_reject_zero_owner() {
    let mut note = fixture_note();
    note.owner = 0;
    let _ = main(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, 5);
}

#[test(should_fail_with = "deposit output parents must be zero")]
fn audit_reject_nonzero_parents() {
    let mut note = fixture_note();
    note.parents = 0x1;
    let _ = main(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, 5);
}

#[test(should_fail_with = "psi not bound to CEK")]
fn audit_reject_unbound_psi() {
    let mut note = fixture_note();
    note.psi = note.psi + 1;
    let _ = main(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, 5);
}

#[test(should_fail_with = "note_type not in {STANDARD, MULTISIG}")]
fn audit_reject_note_type_2() {
    let mut note = fixture_note();
    note.note_type = 2;
    let _ = main(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, 5);
}
