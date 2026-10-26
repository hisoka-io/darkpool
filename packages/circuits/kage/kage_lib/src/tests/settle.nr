// One negative test per constraint settle_swap and unpack_intent enforce, each changing a single witness of the
// honest maker (or, where the recursion would bind it, a single word of the taker's intent).
use crate::{pack_intent, unpack_intent};
use super::{
    compliance, EPH_A_CHANGE, EPH_A_RECEIVED, INDEX_A, intent_args, ODD_Y_EPH, psi_of, run_intent,
    run_settle, settle_args, TWO_POW_128, TWO_POW_160, TWO_POW_32,
};
use shared::lean_imt_inclusion_proof;
use shared::mutation;
use shared::SUBORDER;
use shared::TREE_DEPTH;

#[test]
fn settle_accepts_honest_maker() {
    let a = settle_args();
    let intent = a.intent;
    let out = run_settle(a);
    assert(out.taker_nullifier == intent.nullifier);
    assert(out.root == intent.root);
}

// The last second before expiry still settles; `maker_reject_expired_at_expiry` pins the other side.
#[test]
fn settle_accepts_one_second_before_expiry() {
    let mut a = settle_args();
    a.current_ts = a.intent.expiry - 1;
    let _ = run_settle(a);
}

#[test]
fn unpack_accepts_u128_max_amounts() {
    let mut words = pack_intent(run_intent(intent_args()));
    words[6] = TWO_POW_128 - 1;
    words[7] = TWO_POW_128 - 1;
    let intent = unpack_intent(words);
    assert(intent.from_amount as Field == TWO_POW_128 - 1);
    assert(intent.expected_return as Field == TWO_POW_128 - 1);
}

#[test(should_fail_with = "from_amount exceeds u128 range")]
fn unpack_reject_from_amount_over_u128() {
    let mut words = pack_intent(run_intent(intent_args()));
    words[6] = TWO_POW_128;
    let _ = unpack_intent(words);
}

#[test(should_fail_with = "expected_return exceeds u128 range")]
fn unpack_reject_expected_return_over_u128() {
    let mut words = pack_intent(run_intent(intent_args()));
    words[7] = TWO_POW_128;
    let _ = unpack_intent(words);
}

#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn settle_reject_compliance_non_subgroup() {
    let mut a = settle_args();
    a.compliance = mutation::bad_non_subgroup();
    let _ = run_settle(a);
}

#[test(should_fail_with = "compliance key must not be the identity")]
fn settle_reject_compliance_identity() {
    let mut a = settle_args();
    a.compliance = mutation::bad_identity();
    let _ = run_settle(a);
}

// y matches, so only the x comparison can reject (`maker_reject_compliance_mismatch` changes both).
#[test(should_fail_with = "compliance key mismatch between halves")]
fn settle_reject_compliance_x_mismatch() {
    let mut a = settle_args();
    a.intent.compliance_x = a.intent.compliance_x + 1;
    let _ = run_settle(a);
}

// x matches, so only the y comparison can reject.
#[test(should_fail_with = "compliance key mismatch between halves")]
fn settle_reject_compliance_y_mismatch() {
    let mut a = settle_args();
    a.intent.compliance_y = a.intent.compliance_y + 1;
    let _ = run_settle(a);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn settle_reject_zero_spend_scalar() {
    let mut a = settle_args();
    a.spend = 0;
    let _ = run_settle(a);
}

#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn settle_reject_spend_scalar_at_suborder() {
    let mut a = settle_args();
    a.spend = SUBORDER;
    let _ = run_settle(a);
}

#[test(should_fail_with = "spender does not own this note")]
fn settle_reject_wrong_owner() {
    let mut a = settle_args();
    a.note_in.owner = a.note_in.owner + 1;
    let _ = run_settle(a);
}

#[test(should_fail_with = "unexpected note type")]
fn settle_reject_multisig_input() {
    let mut a = settle_args();
    a.note_in.note_type = 1;
    let _ = run_settle(a);
}

#[test(should_fail_with = "unexpected note version")]
fn settle_reject_input_version() {
    let mut a = settle_args();
    a.note_in.note_version = 2;
    let _ = run_settle(a);
}

#[test(should_fail_with = "Field failed to decompose into specified 20 limbs")]
fn settle_reject_input_asset_over_160_bits() {
    let mut a = settle_args();
    a.note_in.asset_id = TWO_POW_160;
    let _ = run_settle(a);
}

// Index 3 sets bit 1 at a level whose sibling is empty.
#[test(should_fail_with = "non-canonical leaf index: right child at empty level")]
fn settle_reject_noncanonical_index() {
    let mut a = settle_args();
    a.index = 3;
    let _ = run_settle(a);
}

// 2^32 + 1 has the honest index's low 32 bits and parents pack(1, 0), so only the 32-bit decomposition stops the
// maker note settling under a second, aliased nullifier.
#[test(should_fail_with = "Field failed to decompose into specified 32 limbs")]
fn settle_reject_index_over_2_32() {
    let mut a = settle_args();
    a.index = TWO_POW_32 + 1;
    let _ = run_settle(a);
}

// The maker spends the taker's own note at the taker's index: same root, same nullifier.
#[test(should_fail_with = "cannot swap a note with itself")]
fn settle_reject_same_note_both_sides() {
    let mut a = settle_args();
    let taker = intent_args();
    a.note_in = taker.note_in;
    a.index = INDEX_A;
    a.path = taker.path;
    let _ = run_settle(a);
}

#[test(should_fail_with = "swap expired")]
fn maker_reject_expired_at_expiry() {
    let mut a = settle_args();
    a.current_ts = a.intent.expiry;
    let _ = run_settle(a);
}

#[test(should_fail_with = "maker_received asset mismatch")]
fn settle_reject_maker_received_asset() {
    let mut a = settle_args();
    a.received.asset_id = a.intent.to_asset;
    let _ = run_settle(a);
}

#[test(should_fail_with = "maker_change asset mismatch")]
fn settle_reject_maker_change_asset() {
    let mut a = settle_args();
    a.change.asset_id = a.intent.from_asset;
    let _ = run_settle(a);
}

#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn settle_reject_maker_change_parents() {
    let mut a = settle_args();
    a.change.parents = 0;
    let _ = run_settle(a);
}

#[test(should_fail_with = "self note must be STANDARD")]
fn settle_reject_maker_received_multisig_type() {
    let mut a = settle_args();
    a.received.note_type = 1;
    let _ = run_settle(a);
}

#[test(should_fail_with = "self note must be STANDARD")]
fn settle_reject_maker_change_multisig_type() {
    let mut a = settle_args();
    a.change.note_type = 1;
    let _ = run_settle(a);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn settle_reject_maker_received_eph_zero() {
    let mut a = settle_args();
    a.received_eph = 0;
    let _ = run_settle(a);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn settle_reject_maker_change_eph_zero() {
    let mut a = settle_args();
    a.change_eph = 0;
    let _ = run_settle(a);
}

#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn settle_reject_maker_received_eph_at_suborder() {
    let mut a = settle_args();
    a.received_eph = SUBORDER;
    let _ = run_settle(a);
}

#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn settle_reject_maker_change_eph_at_suborder() {
    let mut a = settle_args();
    a.change_eph = SUBORDER;
    let _ = run_settle(a);
}

#[test(should_fail_with = "note owner must be non-zero")]
fn settle_reject_maker_received_zero_owner() {
    let mut a = settle_args();
    a.received.owner = 0;
    let _ = run_settle(a);
}

#[test(should_fail_with = "note owner must be non-zero")]
fn settle_reject_maker_change_zero_owner() {
    let mut a = settle_args();
    a.change.owner = 0;
    let _ = run_settle(a);
}

#[test(should_fail_with = "unexpected note version")]
fn settle_reject_maker_received_version() {
    let mut a = settle_args();
    a.received.note_version = 2;
    let _ = run_settle(a);
}

#[test(should_fail_with = "unexpected note version")]
fn settle_reject_maker_change_version() {
    let mut a = settle_args();
    a.change.note_version = 2;
    let _ = run_settle(a);
}

#[test(should_fail_with = "note conditions_hash must be zero")]
fn settle_reject_maker_received_conditions_hash() {
    let mut a = settle_args();
    a.received.conditions_hash = 1;
    let _ = run_settle(a);
}

#[test(should_fail_with = "note conditions_hash must be zero")]
fn settle_reject_maker_change_conditions_hash() {
    let mut a = settle_args();
    a.change.conditions_hash = 1;
    let _ = run_settle(a);
}

// In the circuit the recursion binds from_asset to the taker's range-checked input; the struct is forged here to
// reach the maker-side mint check. The maker_change asset equals the maker's own input asset, which the maker's
// spend range-checks first, so that side has no reachable twin.
#[test(should_fail_with = "Field failed to decompose into specified 20 limbs")]
fn settle_reject_maker_received_asset_over_160_bits() {
    let mut a = settle_args();
    a.intent.from_asset = TWO_POW_160;
    a.received.asset_id = TWO_POW_160;
    let _ = run_settle(a);
}

#[test(should_fail_with = "psi not bound to CEK")]
fn settle_reject_maker_received_psi() {
    let mut a = settle_args();
    a.received.psi = a.received.psi + 1;
    let _ = run_settle(a);
}

#[test(should_fail_with = "psi not bound to CEK")]
fn settle_reject_maker_change_psi() {
    let mut a = settle_args();
    a.change.psi = a.change.psi + 1;
    let _ = run_settle(a);
}

#[test(should_fail_with = "self discovery tag must be even-y")]
fn settle_reject_maker_received_odd_y_eph() {
    let mut a = settle_args();
    a.received_eph = ODD_Y_EPH;
    a.received.psi = psi_of(ODD_Y_EPH, compliance());
    let _ = run_settle(a);
}

#[test(should_fail_with = "self discovery tag must be even-y")]
fn settle_reject_maker_change_odd_y_eph() {
    let mut a = settle_args();
    a.change_eph = ODD_Y_EPH;
    a.change.psi = psi_of(ODD_Y_EPH, compliance());
    let _ = run_settle(a);
}

// e0..e3 = taker change, taker received, maker received, maker change. Each test makes exactly one pair equal;
// `maker_reject_duplicate_ephemeral` covers e2 == e3.
#[test(should_fail_with = "output ephemerals must be distinct")]
fn settle_reject_eph_e0_e1() {
    let mut t = intent_args();
    t.received_eph = EPH_A_CHANGE;
    t.received.psi = psi_of(EPH_A_CHANGE, compliance());
    let mut a = settle_args();
    a.intent = run_intent(t);
    let _ = run_settle(a);
}

#[test(should_fail_with = "output ephemerals must be distinct")]
fn settle_reject_eph_e0_e2() {
    let mut a = settle_args();
    a.received_eph = EPH_A_CHANGE;
    a.received.psi = psi_of(EPH_A_CHANGE, compliance());
    let _ = run_settle(a);
}

#[test(should_fail_with = "output ephemerals must be distinct")]
fn settle_reject_eph_e0_e3() {
    let mut a = settle_args();
    a.change_eph = EPH_A_CHANGE;
    a.change.psi = psi_of(EPH_A_CHANGE, compliance());
    let _ = run_settle(a);
}

#[test(should_fail_with = "output ephemerals must be distinct")]
fn settle_reject_eph_e1_e2() {
    let mut a = settle_args();
    a.received_eph = EPH_A_RECEIVED;
    a.received.psi = psi_of(EPH_A_RECEIVED, compliance());
    let _ = run_settle(a);
}

#[test(should_fail_with = "output ephemerals must be distinct")]
fn settle_reject_eph_e1_e3() {
    let mut a = settle_args();
    a.change_eph = EPH_A_RECEIVED;
    a.change.psi = psi_of(EPH_A_RECEIVED, compliance());
    let _ = run_settle(a);
}

// The maker's note moved between the same two placements as the taker relocation test. The intent root is set to
// each placement's root so the root check passes; the settlement then proves the circuit computed that root.
#[test]
fn settle_relocated_maker_index_moves_root_and_nullifier() {
    let mut low = settle_args();
    low.index = 3;
    low.path = [0; TREE_DEPTH];
    low.path[0] = 7;
    low.path[1] = 11;
    low.received.parents = 3;
    low.change.parents = 3;
    low.intent.root = lean_imt_inclusion_proof(low.note_in.leaf(), 3, low.path);
    let mut high = settle_args();
    high.index = 12;
    high.path = [0; TREE_DEPTH];
    high.path[2] = 7;
    high.path[3] = 11;
    high.received.parents = 12;
    high.change.parents = 12;
    high.intent.root = lean_imt_inclusion_proof(high.note_in.leaf(), 12, high.path);
    let a = run_settle(low);
    let b = run_settle(high);
    assert(a.root != b.root, "relocated siblings reproduced the root");
    assert(a.maker_nullifier != b.maker_nullifier, "relocated index left the nullifier unchanged");
}
