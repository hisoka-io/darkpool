// One negative test per constraint build_intent enforces, each changing a single witness of the honest taker.
use super::{
    compliance, intent_args, ODD_Y_EPH, psi_of, run_intent, TWO_POW_160, TWO_POW_32, U128_MAX,
};
use shared::mutation;
use shared::SUBORDER;
use shared::TREE_DEPTH;

#[test]
fn intent_accepts_honest_taker() {
    let intent = run_intent(intent_args());
    assert(intent.from_amount == 60);
    assert(intent.expected_return == 50);
}

#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn intent_reject_compliance_non_subgroup() {
    let mut a = intent_args();
    a.compliance = mutation::bad_non_subgroup();
    let _ = run_intent(a);
}

#[test(should_fail_with = "compliance key must not be the identity")]
fn intent_reject_compliance_identity() {
    let mut a = intent_args();
    a.compliance = mutation::bad_identity();
    let _ = run_intent(a);
}

// The change absorbs the whole input, so conservation holds and only the zero-leg guard can reject.
#[test(should_fail_with = "from_amount must be non-zero")]
fn intent_reject_zero_from_amount() {
    let mut a = intent_args();
    a.from_amount = 0;
    a.change.value = a.note_in.value;
    let _ = run_intent(a);
}

#[test(should_fail_with = "expected_return must be non-zero")]
fn intent_reject_zero_expected_return() {
    let mut a = intent_args();
    a.received.value = 0;
    let _ = run_intent(a);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn intent_reject_zero_spend_scalar() {
    let mut a = intent_args();
    a.spend = 0;
    let _ = run_intent(a);
}

#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn intent_reject_spend_scalar_at_suborder() {
    let mut a = intent_args();
    a.spend = SUBORDER;
    let _ = run_intent(a);
}

#[test(should_fail_with = "spender does not own this note")]
fn intent_reject_wrong_owner() {
    let mut a = intent_args();
    a.note_in.owner = a.note_in.owner + 1;
    let _ = run_intent(a);
}

#[test(should_fail_with = "unexpected note type")]
fn intent_reject_multisig_input() {
    let mut a = intent_args();
    a.note_in.note_type = 1;
    let _ = run_intent(a);
}

#[test(should_fail_with = "unexpected note version")]
fn intent_reject_input_version() {
    let mut a = intent_args();
    a.note_in.note_version = 2;
    let _ = run_intent(a);
}

// The change note must carry the input's asset, so both move together and the spend's range check fires first.
#[test(should_fail_with = "Field failed to decompose into specified 20 limbs")]
fn intent_reject_input_asset_over_160_bits() {
    let mut a = intent_args();
    a.note_in.asset_id = TWO_POW_160;
    a.change.asset_id = TWO_POW_160;
    let _ = run_intent(a);
}

// Index 2 sets bit 1 at a level whose sibling is empty.
#[test(should_fail_with = "non-canonical leaf index: right child at empty level")]
fn intent_reject_noncanonical_index() {
    let mut a = intent_args();
    a.index = 2;
    let _ = run_intent(a);
}

// 2^32 has the same low 32 bits as the honest index 0 and parents pack(0, 0), so only the 32-bit decomposition
// stops one note from proving membership under a second, aliased nullifier.
#[test(should_fail_with = "Field failed to decompose into specified 32 limbs")]
fn intent_reject_index_over_2_32() {
    let mut a = intent_args();
    a.index = TWO_POW_32;
    let _ = run_intent(a);
}

#[test(should_fail_with = "attempt to add with overflow")]
fn intent_reject_amount_overflow() {
    let mut a = intent_args();
    a.from_amount = U128_MAX;
    let _ = run_intent(a);
}

#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn intent_reject_change_parents() {
    let mut a = intent_args();
    a.change.parents = 1;
    let _ = run_intent(a);
}

#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn intent_reject_received_parents() {
    let mut a = intent_args();
    a.received.parents = 1;
    let _ = run_intent(a);
}

#[test(should_fail_with = "self note must be STANDARD")]
fn intent_reject_change_multisig_type() {
    let mut a = intent_args();
    a.change.note_type = 1;
    let _ = run_intent(a);
}

#[test(should_fail_with = "self note must be STANDARD")]
fn intent_reject_received_multisig_type() {
    let mut a = intent_args();
    a.received.note_type = 1;
    let _ = run_intent(a);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn intent_reject_eph_zero() {
    let mut a = intent_args();
    a.change_eph = 0;
    let _ = run_intent(a);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn intent_reject_received_eph_zero() {
    let mut a = intent_args();
    a.received_eph = 0;
    let _ = run_intent(a);
}

#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn intent_reject_eph_at_suborder() {
    let mut a = intent_args();
    a.change_eph = SUBORDER;
    let _ = run_intent(a);
}

#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn intent_reject_received_eph_at_suborder() {
    let mut a = intent_args();
    a.received_eph = SUBORDER;
    let _ = run_intent(a);
}

#[test(should_fail_with = "note owner must be non-zero")]
fn intent_reject_zero_owner_output() {
    let mut a = intent_args();
    a.received.owner = 0;
    let _ = run_intent(a);
}

#[test(should_fail_with = "unexpected note version")]
fn intent_reject_output_version() {
    let mut a = intent_args();
    a.received.note_version = 2;
    let _ = run_intent(a);
}

#[test(should_fail_with = "note conditions_hash must be zero")]
fn intent_reject_conditions_hash() {
    let mut a = intent_args();
    a.received.conditions_hash = 1;
    let _ = run_intent(a);
}

// Only the received note can carry an out-of-range asset: the change asset equals the spent input's, which the
// spend range-checks first.
#[test(should_fail_with = "Field failed to decompose into specified 20 limbs")]
fn intent_reject_output_asset_over_160_bits() {
    let mut a = intent_args();
    a.to_asset = TWO_POW_160;
    a.received.asset_id = TWO_POW_160;
    let _ = run_intent(a);
}

#[test(should_fail_with = "psi not bound to CEK")]
fn intent_reject_change_psi() {
    let mut a = intent_args();
    a.change.psi = a.change.psi + 1;
    let _ = run_intent(a);
}

#[test(should_fail_with = "psi not bound to CEK")]
fn intent_reject_received_psi() {
    let mut a = intent_args();
    a.received.psi = a.received.psi + 1;
    let _ = run_intent(a);
}

#[test(should_fail_with = "self discovery tag must be even-y")]
fn intent_reject_odd_y_eph() {
    let mut a = intent_args();
    a.change_eph = ODD_Y_EPH;
    a.change.psi = psi_of(ODD_Y_EPH, compliance());
    let _ = run_intent(a);
}

#[test(should_fail_with = "self discovery tag must be even-y")]
fn intent_reject_received_odd_y_eph() {
    let mut a = intent_args();
    a.received_eph = ODD_Y_EPH;
    a.received.psi = psi_of(ODD_Y_EPH, compliance());
    let _ = run_intent(a);
}

// The same two siblings at levels (0, 1) under index 3 and at levels (2, 3) under index 12. Absorbing the level into
// every node hash keeps the roots apart; without it one note proves membership at both indexes and
// Poseidon2(psi, leaf_index) mints a second nullifier for it.
#[test]
fn intent_relocated_index_moves_root_and_nullifier() {
    let mut low = intent_args();
    low.index = 3;
    low.path = [0; TREE_DEPTH];
    low.path[0] = 7;
    low.path[1] = 11;
    low.change.parents = 3;
    low.received.parents = 3;
    let mut high = intent_args();
    high.index = 12;
    high.path = [0; TREE_DEPTH];
    high.path[2] = 7;
    high.path[3] = 11;
    high.change.parents = 12;
    high.received.parents = 12;
    let a = run_intent(low);
    let b = run_intent(high);
    assert(a.root != b.root, "relocated siblings reproduced the root");
    assert(a.nullifier != b.nullifier, "relocated index left the nullifier unchanged");
}
