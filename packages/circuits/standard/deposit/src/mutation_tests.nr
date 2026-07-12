//! Additive mutation harness for the `deposit` circuit (Layer-1, constraint-level). Prove-then-mutate-then-
//! reject: from the valid KAT witness, flip ONE soundness-relevant asserted witness and require the constraint
//! system to reject with the SPECIFIC guard message (a wrong-reason failure would not match `should_fail_with`,
//! so a test only passes if the intended guard fired). deposit is the simplest circuit: no spend, no
//! conservation, no change note; it only mints one self-note. No circuit logic is touched.

use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;
use shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, fixture_note};

// eph=5 is the golden KAT ephemeral (its derived eph_pub is even-y, so the discovery-tag guard passes).
global EPH: Field = 5;

fn note0() -> Note {
    fixture_note()
}

// Full-arg runner with the valid deposit as defaults; each test overrides exactly one argument.
fn run(cx: Field, cy: Field, note: Note, eph: Field) {
    let _ = super::main(cx, cy, note, eph);
}

fn valid() {
    run(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note0(), EPH);
}

#[test]
fn m_valid_accepts() {
    valid();
}

// --- compliance key: BJJ curve-op entry (identity / off-curve / small-order / non-subgroup) ---------------
#[test(should_fail_with = "compliance key must not be the identity")]
fn m_compliance_identity() {
    let p = mutation::bad_identity();
    run(p.x, p.y, note0(), EPH);
}
#[test(should_fail)]
fn m_compliance_off_curve() {
    let p = mutation::bad_off_curve();
    run(p.x, p.y, note0(), EPH);
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_small_order() {
    let p = mutation::bad_small_order();
    run(p.x, p.y, note0(), EPH);
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_non_subgroup() {
    let p = mutation::bad_non_subgroup();
    run(p.x, p.y, note0(), EPH);
}

// --- minted note guards (mint_common) ---------------------------------------------------------------------
#[test(should_fail_with = "note owner must be non-zero")]
fn m_owner_zero() {
    let mut note = note0();
    note.owner = 0;
    run(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, EPH);
}
#[test(should_fail_with = "unexpected note version")]
fn m_note_version() {
    let mut note = note0();
    note.note_version = 2;
    run(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, EPH);
}
#[test(should_fail_with = "note_type not in {STANDARD, MULTISIG}")]
fn m_note_type_conditional() {
    let mut note = note0();
    note.note_type = 2;
    run(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, EPH);
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_conditions_hash() {
    let mut note = note0();
    note.conditions_hash = 1;
    run(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, EPH);
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_psi_unbound() {
    let mut note = note0();
    note.psi = note.psi + 1;
    run(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, EPH);
}
// asset_id must fit in 20 bytes (assert_asset_id decomposes to [u8; 20]); a 21-byte value overflows.
#[test(should_fail)]
fn m_asset_invalid() {
    let mut note = note0();
    note.asset_id = 0x010000000000000000000000000000000000000000;
    run(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, EPH);
}
#[test(should_fail_with = "deposit output parents must be zero")]
fn m_parents_nonzero() {
    let mut note = note0();
    note.parents = 1;
    run(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note, EPH);
}

// --- ephemeral scalar (feeds the ECDH mul) ----------------------------------------------------------------
#[test(should_fail_with = "scalar must be non-zero")]
fn m_eph_zero() {
    run(FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, note0(), 0);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_eph_ge_suborder() {
    run(
        FIXTURE_COMPLIANCE_X,
        FIXTURE_COMPLIANCE_Y,
        note0(),
        SUBORDER,
    );
}
