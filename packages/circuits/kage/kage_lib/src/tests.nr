mod intent;
mod settle;

use super::{build_intent, KageOutputs, settle_swap, SwapIntent};
use ecdh::{bjj::BJJ, ECDHTrait, Point};
use poseidon::poseidon2::Poseidon2;
use shared::note::Note;
use shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y};
use shared::TREE_DEPTH;

// shared/src/common/domains.nr PSI_DOMAIN (frozen).
global PSI_DOMAIN: Field = 0x138d495e7a5c1b3f504318dd6cfcf0a7cf7bb6d69cf9eadb049cc35d6831ef5b;

global FROM_ASSET: Field = 0x1234567890123456789012345678901234567890;
global TO_ASSET: Field = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd;
// fixture spend key 789 -> owner; reused for A_in, B_in, and every self-note owner in the test.
global SELF_OWNER: Field = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
global SPEND: Field = 789;

// Even-y self ephemerals (proven even-y by the existing split/transfer/join KATs).
global EPH_A_CHANGE: Field = 9;
global EPH_A_RECEIVED: Field = 15;
global EPH_B_RECEIVED: Field = 20;
global EPH_B_CHANGE: Field = 28;

global INDEX_A: Field = 0;
global INDEX_B: Field = 1;
global PARENTS_A: Field = 0; // pack(index_A=0, 0)
global PARENTS_B: Field = 1; // pack(index_B=1, 0)

// Out-of-range witnesses: one past each width the circuit range-checks.
global TWO_POW_32: Field = 0x100000000;
global TWO_POW_128: Field = 0x100000000000000000000000000000000;
global TWO_POW_160: Field = 0x10000000000000000000000000000000000000000;
global U128_MAX: u128 = 0xffffffffffffffffffffffffffffffff;
// An ephemeral whose public key has odd y (the even-y tag rule rejects it).
global ODD_Y_EPH: Field = 456;

fn compliance() -> Point {
    Point { x: FIXTURE_COMPLIANCE_X, y: FIXTURE_COMPLIANCE_Y }
}

fn other_compliance() -> Point {
    // a different valid subgroup point (the transfer recipient in_pub), for the C-mismatch test
    Point {
        x: 0x1b16e357953d68d73398c838aa883cc65ddae2aef75a4bc437e4232afdbe43c8,
        y: 0x02d7ee0be055310d2895c5ed5090a8aa1c700e73c64294f1e817ec77f46b4fdc,
    }
}

fn psi_of(eph: Field, c: Point) -> Field {
    Poseidon2::hash([BJJ::new(eph).derive_shared_key(c), PSI_DOMAIN], 2)
}

fn note(asset: Field, value: u128, psi: Field, parents: Field) -> Note {
    Note {
        note_version: 1,
        asset_id: asset,
        note_type: 0,
        conditions_hash: 0,
        value,
        owner: SELF_OWNER,
        psi,
        parents,
    }
}

struct Scenario {
    taker_note_in: Note,
    a_change: Note,
    a_received: Note,
    maker_note_in: Note,
    b_received: Note,
    b_change: Note,
    to_asset: Field,
    from_amount: u128,
    expiry: Field,
    path_a: [Field; TREE_DEPTH],
    maker_path: [Field; TREE_DEPTH],
    current_ts: Field,
}

fn build(
    taker_note_in: Note,
    a_change: Note,
    a_received: Note,
    maker_note_in: Note,
    b_received: Note,
    b_change: Note,
    to_asset: Field,
    from_amount: u128,
    expiry: Field,
    current_ts: Field,
) -> Scenario {
    let leaf_a = taker_note_in.leaf();
    let leaf_b = maker_note_in.leaf();
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = leaf_b;
    let mut maker_path = [0; TREE_DEPTH];
    maker_path[0] = leaf_a;
    Scenario {
        taker_note_in,
        a_change,
        a_received,
        maker_note_in,
        b_received,
        b_change,
        to_asset,
        from_amount,
        expiry,
        path_a,
        maker_path,
        current_ts,
    }
}

// A_in 100 -> release 60, keep 40; taker wants 50 toAsset. B_in 100 -> maker keeps 50.
fn scenario() -> Scenario {
    let c = compliance();
    build(
        note(FROM_ASSET, 100, psi_of(111, c), 0),
        note(FROM_ASSET, 40, psi_of(EPH_A_CHANGE, c), PARENTS_A),
        note(TO_ASSET, 50, psi_of(EPH_A_RECEIVED, c), PARENTS_A),
        note(TO_ASSET, 100, psi_of(222, c), 0),
        note(FROM_ASSET, 60, psi_of(EPH_B_RECEIVED, c), PARENTS_B),
        note(TO_ASSET, 50, psi_of(EPH_B_CHANGE, c), PARENTS_B),
        TO_ASSET,
        60,
        2000000000,
        1000000000,
    )
}

fn taker_intent(s: Scenario) -> SwapIntent {
    build_intent(
        compliance(),
        s.taker_note_in,
        SPEND,
        INDEX_A,
        s.path_a,
        s.a_change,
        EPH_A_CHANGE,
        s.a_received,
        EPH_A_RECEIVED,
        s.to_asset,
        s.from_amount,
        s.expiry,
    )
}

fn settle(s: Scenario, intent: SwapIntent) -> KageOutputs {
    settle_swap(
        intent,
        compliance(),
        s.current_ts,
        s.maker_note_in,
        SPEND,
        INDEX_B,
        s.maker_path,
        s.b_received,
        EPH_B_RECEIVED,
        s.b_change,
        EPH_B_CHANGE,
    )
}

#[test]
fn kage_swap_accepts() {
    let s = scenario();
    let intent = taker_intent(s);
    let out = settle(s, intent);
    assert(out.taker_nullifier != out.maker_nullifier);
    assert(out.root == intent.root);
    assert(out.taker_received.leaf == intent.received_leaf);
    assert(out.taker_change.leaf == intent.change_leaf);
}

#[test(should_fail_with = "value not conserved")]
fn taker_reject_change_inflation() {
    let mut s = scenario();
    s.a_change = note(
        FROM_ASSET,
        50,
        psi_of(EPH_A_CHANGE, compliance()),
        PARENTS_A,
    );
    let _ = taker_intent(s);
}

#[test(should_fail_with = "swap assets must differ")]
fn taker_reject_same_asset_swap() {
    let mut s = scenario();
    s.to_asset = FROM_ASSET;
    let _ = taker_intent(s);
}

#[test(should_fail_with = "change asset mismatch")]
fn taker_reject_change_asset_mismatch() {
    let mut s = scenario();
    s.a_change = note(TO_ASSET, 40, psi_of(EPH_A_CHANGE, compliance()), PARENTS_A);
    let _ = taker_intent(s);
}

#[test(should_fail_with = "received asset mismatch")]
fn taker_reject_received_asset_mismatch() {
    let mut s = scenario();
    s.a_received = note(
        FROM_ASSET,
        50,
        psi_of(EPH_A_RECEIVED, compliance()),
        PARENTS_A,
    );
    let _ = taker_intent(s);
}

// taker over-asks -> the maker's toAsset conservation makes it unfillable.
#[test(should_fail_with = "value not conserved")]
fn maker_reject_taker_received_inflation() {
    let c = compliance();
    let s = build(
        note(FROM_ASSET, 100, psi_of(111, c), 0),
        note(FROM_ASSET, 40, psi_of(EPH_A_CHANGE, c), PARENTS_A),
        note(TO_ASSET, 1000, psi_of(EPH_A_RECEIVED, c), PARENTS_A), // the taker asks for 1000 toAsset
        note(TO_ASSET, 100, psi_of(222, c), 0),
        note(FROM_ASSET, 60, psi_of(EPH_B_RECEIVED, c), PARENTS_B),
        note(TO_ASSET, 50, psi_of(EPH_B_CHANGE, c), PARENTS_B),
        TO_ASSET,
        60,
        2000000000,
        1000000000,
    );
    let intent = taker_intent(s);
    let _ = settle(s, intent);
}

#[test(should_fail_with = "value not conserved")]
fn maker_reject_toasset_inflation() {
    let s = scenario();
    let intent = taker_intent(s);
    let mut s2 = scenario();
    s2.b_change = note(TO_ASSET, 60, psi_of(EPH_B_CHANGE, compliance()), PARENTS_B);
    let _ = settle(s2, intent);
}

#[test(should_fail_with = "maker_received value mismatch")]
fn maker_reject_fromasset_inflation() {
    let s = scenario();
    let intent = taker_intent(s);
    let mut s2 = scenario();
    s2.b_received = note(
        FROM_ASSET,
        80,
        psi_of(EPH_B_RECEIVED, compliance()),
        PARENTS_B,
    );
    let _ = settle(s2, intent);
}

#[test(should_fail_with = "inputs must share a root")]
fn maker_reject_root_mismatch() {
    let s = scenario();
    let intent = taker_intent(s);
    let mut s2 = scenario();
    s2.maker_path[0] = 0x0abc;
    let _ = settle(s2, intent);
}

#[test(should_fail_with = "swap expired")]
fn maker_reject_expired() {
    let s = scenario();
    let intent = taker_intent(s);
    let mut s2 = scenario();
    s2.current_ts = 2000000001;
    let _ = settle(s2, intent);
}

#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn maker_reject_forged_parents() {
    let s = scenario();
    let intent = taker_intent(s);
    let mut s2 = scenario();
    s2.b_received = note(FROM_ASSET, 60, psi_of(EPH_B_RECEIVED, compliance()), 0x999);
    let _ = settle(s2, intent);
}

#[test(should_fail_with = "compliance key mismatch between halves")]
fn maker_reject_compliance_mismatch() {
    let s = scenario();
    let intent = taker_intent(s);
    let _ = settle_swap(
        intent,
        other_compliance(),
        s.current_ts,
        s.maker_note_in,
        SPEND,
        INDEX_B,
        s.maker_path,
        s.b_received,
        EPH_B_RECEIVED,
        s.b_change,
        EPH_B_CHANGE,
    );
}

// wrong-asset B_in placed in the tree so the root check passes and the asset guard is what fires.
#[test(should_fail_with = "maker input asset mismatch")]
fn maker_reject_wrong_input_asset() {
    let c = compliance();
    let s = build(
        note(FROM_ASSET, 100, psi_of(111, c), 0),
        note(FROM_ASSET, 40, psi_of(EPH_A_CHANGE, c), PARENTS_A),
        note(TO_ASSET, 50, psi_of(EPH_A_RECEIVED, c), PARENTS_A),
        note(FROM_ASSET, 100, psi_of(222, c), 0), // B_in has the wrong asset
        note(FROM_ASSET, 60, psi_of(EPH_B_RECEIVED, c), PARENTS_B),
        note(TO_ASSET, 50, psi_of(EPH_B_CHANGE, c), PARENTS_B),
        TO_ASSET,
        60,
        2000000000,
        1000000000,
    );
    let intent = taker_intent(s);
    let _ = settle(s, intent);
}

// reuse b_received's eph for b_change -> shared CEK -> caught by the pairwise-distinct assert.
#[test(should_fail_with = "output ephemerals must be distinct")]
fn maker_reject_duplicate_ephemeral() {
    let s = scenario();
    let intent = taker_intent(s);
    let mut s2 = scenario();
    s2.b_change = note(
        TO_ASSET,
        50,
        psi_of(EPH_B_RECEIVED, compliance()),
        PARENTS_B,
    );
    let _ = settle_swap(
        intent,
        compliance(),
        s2.current_ts,
        s2.maker_note_in,
        SPEND,
        INDEX_B,
        s2.maker_path,
        s2.b_received,
        EPH_B_RECEIVED,
        s2.b_change,
        EPH_B_RECEIVED,
    );
}

// Every argument of build_intent, defaulting to the honest taker side of scenario(), so a negative test changes
// exactly one witness.
pub struct IntentArgs {
    pub compliance: Point,
    pub note_in: Note,
    pub spend: Field,
    pub index: Field,
    pub path: [Field; TREE_DEPTH],
    pub change: Note,
    pub change_eph: Field,
    pub received: Note,
    pub received_eph: Field,
    pub to_asset: Field,
    pub from_amount: u128,
    pub expiry: Field,
}

pub fn intent_args() -> IntentArgs {
    let s = scenario();
    IntentArgs {
        compliance: compliance(),
        note_in: s.taker_note_in,
        spend: SPEND,
        index: INDEX_A,
        path: s.path_a,
        change: s.a_change,
        change_eph: EPH_A_CHANGE,
        received: s.a_received,
        received_eph: EPH_A_RECEIVED,
        to_asset: s.to_asset,
        from_amount: s.from_amount,
        expiry: s.expiry,
    }
}

pub fn run_intent(a: IntentArgs) -> SwapIntent {
    build_intent(
        a.compliance,
        a.note_in,
        a.spend,
        a.index,
        a.path,
        a.change,
        a.change_eph,
        a.received,
        a.received_eph,
        a.to_asset,
        a.from_amount,
        a.expiry,
    )
}

// Every argument of settle_swap, defaulting to the honest maker side of scenario() over the honest intent.
pub struct SettleArgs {
    pub intent: SwapIntent,
    pub compliance: Point,
    pub current_ts: Field,
    pub note_in: Note,
    pub spend: Field,
    pub index: Field,
    pub path: [Field; TREE_DEPTH],
    pub received: Note,
    pub received_eph: Field,
    pub change: Note,
    pub change_eph: Field,
}

pub fn settle_args() -> SettleArgs {
    let s = scenario();
    SettleArgs {
        intent: taker_intent(s),
        compliance: compliance(),
        current_ts: s.current_ts,
        note_in: s.maker_note_in,
        spend: SPEND,
        index: INDEX_B,
        path: s.maker_path,
        received: s.b_received,
        received_eph: EPH_B_RECEIVED,
        change: s.b_change,
        change_eph: EPH_B_CHANGE,
    }
}

pub fn run_settle(a: SettleArgs) -> KageOutputs {
    settle_swap(
        a.intent,
        a.compliance,
        a.current_ts,
        a.note_in,
        a.spend,
        a.index,
        a.path,
        a.received,
        a.received_eph,
        a.change,
        a.change_eph,
    )
}
