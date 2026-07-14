//! Mutation harness: from a valid witness flip ONE soundness-relevant witness and require rejection with the
//! specific guard (should_fail_with means a wrong-reason failure still fails). Public-output-bound fields
//! (nullifier/root) are covered at the deployed-verifier layer (RealProofE2E), not here.

use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;
use shared::TREE_DEPTH;

global ASSET: Field = 0x1234567890123456789012345678901234567890;
global SCALAR: Field = 789;
global EPH: Field = 8;
global WVAL: u128 = 40;

fn old() -> Note {
    super::spent_note()
}
fn change() -> Note {
    super::change_note()
}

fn run(wval: u128, cx: Field, cy: Field, o: Note, s: Field, idx: Field, ch: Note, eph: Field) {
    let _ = super::main(wval, 0, 0, cx, cy, o, s, idx, [0; TREE_DEPTH], ch, eph);
}

fn valid(cx: Field, cy: Field) {
    run(WVAL, cx, cy, old(), SCALAR, 0, change(), EPH);
}

#[test]
fn m_valid_accepts() {
    let (cx, cy) = super::compliance();
    valid(cx, cy);
}

#[test(should_fail_with = "spender does not own this note")]
fn m_spend_scalar_wrong() {
    let (cx, cy) = super::compliance();
    run(WVAL, cx, cy, old(), 0x2a, 0, change(), EPH);
}
#[test(should_fail_with = "scalar must be non-zero")]
fn m_spend_scalar_zero() {
    let (cx, cy) = super::compliance();
    run(WVAL, cx, cy, old(), 0, 0, change(), EPH);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_spend_scalar_ge_suborder() {
    let (cx, cy) = super::compliance();
    run(WVAL, cx, cy, old(), SUBORDER, 0, change(), EPH);
}
#[test(should_fail_with = "spender does not own this note")]
fn m_old_owner_mutated() {
    let (cx, cy) = super::compliance();
    let mut o = old();
    o.owner = 0xdeadbeef;
    run(WVAL, cx, cy, o, SCALAR, 0, change(), EPH);
}

#[test(should_fail_with = "unexpected note type")]
fn m_old_note_type() {
    let (cx, cy) = super::compliance();
    let mut o = old();
    o.note_type = 1;
    run(WVAL, cx, cy, o, SCALAR, 0, change(), EPH);
}
#[test(should_fail_with = "unexpected note version")]
fn m_old_note_version() {
    let (cx, cy) = super::compliance();
    let mut o = old();
    o.note_version = 2;
    run(WVAL, cx, cy, o, SCALAR, 0, change(), EPH);
}
#[test(should_fail_with = "asset mismatch")]
fn m_old_asset_mismatch() {
    let (cx, cy) = super::compliance();
    let mut o = old();
    o.asset_id = ASSET + 1;
    run(WVAL, cx, cy, o, SCALAR, 0, change(), EPH);
}
#[test(should_fail_with = "non-canonical leaf index")]
fn m_noncanonical_leaf_index() {
    let (cx, cy) = super::compliance();
    run(WVAL, cx, cy, old(), SCALAR, 7, change(), EPH);
}

#[test(should_fail_with = "value not conserved")]
fn m_value_not_conserved() {
    let (cx, cy) = super::compliance();
    run(WVAL + 1, cx, cy, old(), SCALAR, 0, change(), EPH);
}
#[test(should_fail_with = "attempt to add with overflow")]
fn m_value_output_overflow() {
    let (cx, cy) = super::compliance();
    let mut ch = change();
    ch.value = 0xffffffffffffffffffffffffffffffff;
    run(1, cx, cy, old(), SCALAR, 0, ch, EPH);
}

#[test(should_fail_with = "note owner must be non-zero")]
fn m_change_owner_zero() {
    let (cx, cy) = super::compliance();
    let mut ch = change();
    ch.owner = 0;
    run(WVAL, cx, cy, old(), SCALAR, 0, ch, EPH);
}
#[test(should_fail_with = "self note must be STANDARD")]
fn m_change_note_type() {
    let (cx, cy) = super::compliance();
    let mut ch = change();
    ch.note_type = 1;
    run(WVAL, cx, cy, old(), SCALAR, 0, ch, EPH);
}
#[test(should_fail_with = "unexpected note version")]
fn m_change_note_version() {
    let (cx, cy) = super::compliance();
    let mut ch = change();
    ch.note_version = 2;
    run(WVAL, cx, cy, old(), SCALAR, 0, ch, EPH);
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_change_conditions_hash() {
    let (cx, cy) = super::compliance();
    let mut ch = change();
    ch.conditions_hash = 1;
    run(WVAL, cx, cy, old(), SCALAR, 0, ch, EPH);
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_change_psi_unbound() {
    let (cx, cy) = super::compliance();
    let mut ch = change();
    ch.psi = ch.psi + 1;
    run(WVAL, cx, cy, old(), SCALAR, 0, ch, EPH);
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_change_parents_forged() {
    let (cx, cy) = super::compliance();
    let mut ch = change();
    ch.parents = 1;
    run(WVAL, cx, cy, old(), SCALAR, 0, ch, EPH);
}

#[test(should_fail_with = "compliance key must not be the identity")]
fn m_compliance_identity() {
    let p = mutation::bad_identity();
    run(WVAL, p.x, p.y, old(), SCALAR, 0, change(), EPH);
}
#[test(should_fail)]
fn m_compliance_off_curve() {
    let p = mutation::bad_off_curve();
    run(WVAL, p.x, p.y, old(), SCALAR, 0, change(), EPH);
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_small_order() {
    let p = mutation::bad_small_order();
    run(WVAL, p.x, p.y, old(), SCALAR, 0, change(), EPH);
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_non_subgroup() {
    let p = mutation::bad_non_subgroup();
    run(WVAL, p.x, p.y, old(), SCALAR, 0, change(), EPH);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn m_change_eph_zero() {
    let (cx, cy) = super::compliance();
    run(WVAL, cx, cy, old(), SCALAR, 0, change(), 0);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_change_eph_ge_suborder() {
    let (cx, cy) = super::compliance();
    run(WVAL, cx, cy, old(), SCALAR, 0, change(), SUBORDER);
}
