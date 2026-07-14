//! Mutation harness: from the valid KAT witness flip ONE soundness-relevant witness and require rejection with
//! the specific guard (should_fail_with means a wrong-reason failure still fails). Public-output-bound fields
//! (nullifier/root/leaf/eph_pub/ciphertext) are covered at the deployed-verifier layer (RealProofE2E). Guard
//! order is load-bearing: outputs mint left-to-right, so an out_2 mint-field mutation surfaces only after out_1
//! mints clean.

use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;
use shared::TREE_DEPTH;

global ASSET: Field = 0x1234567890123456789012345678901234567890;
global SCALAR: Field = 789;
global EPH1: Field = 15;
global EPH2: Field = 20;

fn note_in() -> Note {
    super::note_in()
}
// KAT-valid self outputs (values 40 / 60; psi bound to eph 15 / 20 against the fixture compliance key).
fn out1() -> Note {
    super::out_note(
        40,
        0x017131231dbfc29f6bdfb775d6e859c148b7379acc2844380ff9f824fa7073ad,
    )
}
fn out2() -> Note {
    super::out_note(
        60,
        0x1fc1420fa8dd294ee9feaa5067000d40945bdc796e47ce5dfbfa4cbb4210ef8d,
    )
}
fn compliance() -> (Field, Field) {
    (super::CX, super::CY)
}

fn run(
    cx: Field,
    cy: Field,
    ni: Note,
    s: Field,
    idx: Field,
    o1: Note,
    e1: Field,
    o2: Note,
    e2: Field,
) {
    let _ = super::main(cx, cy, ni, s, idx, [0; TREE_DEPTH], o1, e1, o2, e2);
}

fn valid(cx: Field, cy: Field) {
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, out2(), EPH2);
}

#[test]
fn m_valid_accepts() {
    let (cx, cy) = compliance();
    valid(cx, cy);
}

#[test(should_fail_with = "spender does not own this note")]
fn m_in_owner_mutated() {
    let (cx, cy) = compliance();
    let mut ni = note_in();
    ni.owner = 0xdeadbeef;
    run(cx, cy, ni, SCALAR, 0, out1(), EPH1, out2(), EPH2);
}
#[test(should_fail_with = "unexpected note type")]
fn m_in_note_type() {
    let (cx, cy) = compliance();
    let mut ni = note_in();
    ni.note_type = 1;
    run(cx, cy, ni, SCALAR, 0, out1(), EPH1, out2(), EPH2);
}
#[test(should_fail_with = "unexpected note version")]
fn m_in_note_version() {
    let (cx, cy) = compliance();
    let mut ni = note_in();
    ni.note_version = 2;
    run(cx, cy, ni, SCALAR, 0, out1(), EPH1, out2(), EPH2);
}
// note_in asset is pinned to the outputs; perturbing it surfaces at the out_1 asset-equality guard.
#[test(should_fail_with = "out1 asset mismatch")]
fn m_in_asset_mismatch() {
    let (cx, cy) = compliance();
    let mut ni = note_in();
    ni.asset_id = ASSET + 1;
    run(cx, cy, ni, SCALAR, 0, out1(), EPH1, out2(), EPH2);
}
#[test(should_fail_with = "non-canonical leaf index")]
fn m_noncanonical_leaf_index() {
    let (cx, cy) = compliance();
    run(cx, cy, note_in(), SCALAR, 7, out1(), EPH1, out2(), EPH2);
}

#[test(should_fail_with = "spender does not own this note")]
fn m_spend_scalar_wrong() {
    let (cx, cy) = compliance();
    run(cx, cy, note_in(), 0x2a, 0, out1(), EPH1, out2(), EPH2);
}
#[test(should_fail_with = "scalar must be non-zero")]
fn m_spend_scalar_zero() {
    let (cx, cy) = compliance();
    run(cx, cy, note_in(), 0, 0, out1(), EPH1, out2(), EPH2);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_spend_scalar_ge_suborder() {
    let (cx, cy) = compliance();
    run(cx, cy, note_in(), SUBORDER, 0, out1(), EPH1, out2(), EPH2);
}

#[test(should_fail_with = "value not conserved")]
fn m_value_not_conserved() {
    let (cx, cy) = compliance();
    let mut ni = note_in();
    ni.value = 101;
    run(cx, cy, ni, SCALAR, 0, out1(), EPH1, out2(), EPH2);
}
#[test(should_fail_with = "attempt to add with overflow")]
fn m_value_output_overflow() {
    let (cx, cy) = compliance();
    let mut o1 = out1();
    o1.value = 0xffffffffffffffffffffffffffffffff;
    let mut o2 = out2();
    o2.value = 1;
    run(cx, cy, note_in(), SCALAR, 0, o1, EPH1, o2, EPH2);
}

#[test(should_fail_with = "note owner must be non-zero")]
fn m_out1_owner_zero() {
    let (cx, cy) = compliance();
    let mut o1 = out1();
    o1.owner = 0;
    run(cx, cy, note_in(), SCALAR, 0, o1, EPH1, out2(), EPH2);
}
#[test(should_fail_with = "self note must be STANDARD")]
fn m_out1_note_type() {
    let (cx, cy) = compliance();
    let mut o1 = out1();
    o1.note_type = 1;
    run(cx, cy, note_in(), SCALAR, 0, o1, EPH1, out2(), EPH2);
}
#[test(should_fail_with = "unexpected note version")]
fn m_out1_note_version() {
    let (cx, cy) = compliance();
    let mut o1 = out1();
    o1.note_version = 2;
    run(cx, cy, note_in(), SCALAR, 0, o1, EPH1, out2(), EPH2);
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_out1_conditions_hash() {
    let (cx, cy) = compliance();
    let mut o1 = out1();
    o1.conditions_hash = 1;
    run(cx, cy, note_in(), SCALAR, 0, o1, EPH1, out2(), EPH2);
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_out1_psi_unbound() {
    let (cx, cy) = compliance();
    let mut o1 = out1();
    o1.psi = o1.psi + 1;
    run(cx, cy, note_in(), SCALAR, 0, o1, EPH1, out2(), EPH2);
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_out1_parents_forged() {
    let (cx, cy) = compliance();
    let mut o1 = out1();
    o1.parents = 1;
    run(cx, cy, note_in(), SCALAR, 0, o1, EPH1, out2(), EPH2);
}

// out_2 mint guards are reached only after out_1 mints clean.
#[test(should_fail_with = "note owner must be non-zero")]
fn m_out2_owner_zero() {
    let (cx, cy) = compliance();
    let mut o2 = out2();
    o2.owner = 0;
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, o2, EPH2);
}
#[test(should_fail_with = "self note must be STANDARD")]
fn m_out2_note_type() {
    let (cx, cy) = compliance();
    let mut o2 = out2();
    o2.note_type = 1;
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, o2, EPH2);
}
#[test(should_fail_with = "unexpected note version")]
fn m_out2_note_version() {
    let (cx, cy) = compliance();
    let mut o2 = out2();
    o2.note_version = 2;
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, o2, EPH2);
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_out2_conditions_hash() {
    let (cx, cy) = compliance();
    let mut o2 = out2();
    o2.conditions_hash = 1;
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, o2, EPH2);
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_out2_psi_unbound() {
    let (cx, cy) = compliance();
    let mut o2 = out2();
    o2.psi = o2.psi + 1;
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, o2, EPH2);
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_out2_parents_forged() {
    let (cx, cy) = compliance();
    let mut o2 = out2();
    o2.parents = 1;
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, o2, EPH2);
}

#[test(should_fail_with = "compliance key must not be the identity")]
fn m_compliance_identity() {
    let p = mutation::bad_identity();
    run(p.x, p.y, note_in(), SCALAR, 0, out1(), EPH1, out2(), EPH2);
}
#[test(should_fail)]
fn m_compliance_off_curve() {
    let p = mutation::bad_off_curve();
    run(p.x, p.y, note_in(), SCALAR, 0, out1(), EPH1, out2(), EPH2);
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_small_order() {
    let p = mutation::bad_small_order();
    run(p.x, p.y, note_in(), SCALAR, 0, out1(), EPH1, out2(), EPH2);
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_non_subgroup() {
    let p = mutation::bad_non_subgroup();
    run(p.x, p.y, note_in(), SCALAR, 0, out1(), EPH1, out2(), EPH2);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn m_eph1_zero() {
    let (cx, cy) = compliance();
    run(cx, cy, note_in(), SCALAR, 0, out1(), 0, out2(), EPH2);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_eph1_ge_suborder() {
    let (cx, cy) = compliance();
    run(cx, cy, note_in(), SCALAR, 0, out1(), SUBORDER, out2(), EPH2);
}
#[test(should_fail_with = "scalar must be non-zero")]
fn m_eph2_zero() {
    let (cx, cy) = compliance();
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, out2(), 0);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_eph2_ge_suborder() {
    let (cx, cy) = compliance();
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, out2(), SUBORDER);
}
// Reusing one eph across outputs reuses the CEK (two-time pad); the circuit pins them distinct.
#[test(should_fail_with = "ephemerals must be distinct")]
fn m_eph_reused() {
    let (cx, cy) = compliance();
    run(cx, cy, note_in(), SCALAR, 0, out1(), EPH1, out2(), EPH1);
}
