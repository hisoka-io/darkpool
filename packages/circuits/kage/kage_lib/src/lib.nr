//! Kage private in-pool swap: FOUR self-notes, two minted by each party, so output-owner binding is STRUCTURAL
//! (each mints to itself; neither can redirect or shortchange the other, nor learns the other's psi or index).
//!
//! Per-asset conservation is split across the two proofs:
//!   fromAsset:  A_in == from_amount + A_change (taker)   AND   B_received == from_amount (maker)
//!   toAsset:    B_in == expected_return + B_change (maker, over the taker's exposed expected_return)
//!
//! Additive to the note format (reuses verify_spend / mint_self_note / conservation). eph.x-only: mint_self_note
//! asserts even-y, so only eph_pub.x is surfaced.

use ecdh::Point;
use shared::conservation;
use shared::mint;
use shared::note::{assert_parents_bound, Note};
use shared::TREE_DEPTH;
use shared::verify_spend;

// DEM transmitted-field count (shared/src/common/dem.nr DEM_FIELDS).
global CT_LEN: u32 = 7;

// Inner-VK binding: the single most load-bearing value in Kage. `verification_key` is a solver-supplied WITNESS;
// only this hardcoded constant stops a solver proving his own circuit to forge the taker's half. `0` = not pinned
// = total forge. Must stay a compile-time CONSTANT (the stdlib asserts constants for proof_type but NOT key_hash).
// The stdlib does not constrain hash(vk) == key_hash; barretenberg enforces it (as Payy relies on), so an
// adversarial test gates it: wrong VK / different-circuit proof / tampered public inputs all reject.
pub global INTENT_VK_HASH: Field =
    0x2f282faa1ed7f0c76b2d4dfd8ef8555ad443c8fb448373936bb11a1f2678313b;
pub global PROOF_TYPE: u32 = 6;
// Compiled swap_intent bb recursion widths (verifierTarget noir-recursive); regenerate on any change (kageVkParity guard).
pub global INTENT_VK_LEN: u32 = 115;
pub global INTENT_PROOF_LEN: u32 = 458;

// Public-input width swap_intent exposes (see pack_intent): 9 scalars + (leaf + eph_x + ct[7]) per note x 2.
pub global INTENT_PI_LEN: u32 = 27;

// The taker's public interface: consumed as WITNESS by the maker's recursion, never on-chain. The amount fields
// are the swap terms; the note blocks are relayed on-chain for insertion + events.
pub struct SwapIntent {
    pub nullifier: Field,
    pub root: Field,
    pub compliance_x: Field, // C the taker used (the maker binds his C to it)
    pub compliance_y: Field,
    pub from_asset: Field,
    pub to_asset: Field,
    pub from_amount: u128, // fromAsset the taker releases (the maker binds B_out_received to it)
    pub expected_return: u128, // toAsset the taker wants (== A_out_received.value; the maker's toAsset conservation)
    pub expiry: Field,
    pub change_leaf: Field,
    pub change_eph_x: Field,
    pub change_ct: [Field; CT_LEN],
    pub received_leaf: Field,
    pub received_eph_x: Field,
    pub received_ct: [Field; CT_LEN],
}

pub fn pack_intent(pi: SwapIntent) -> [Field; INTENT_PI_LEN] {
    [
        pi.nullifier,
        pi.root,
        pi.compliance_x,
        pi.compliance_y,
        pi.from_asset,
        pi.to_asset,
        pi.from_amount as Field,
        pi.expected_return as Field,
        pi.expiry,
        pi.change_leaf,
        pi.change_eph_x,
        pi.change_ct[0],
        pi.change_ct[1],
        pi.change_ct[2],
        pi.change_ct[3],
        pi.change_ct[4],
        pi.change_ct[5],
        pi.change_ct[6],
        pi.received_leaf,
        pi.received_eph_x,
        pi.received_ct[0],
        pi.received_ct[1],
        pi.received_ct[2],
        pi.received_ct[3],
        pi.received_ct[4],
        pi.received_ct[5],
        pi.received_ct[6],
    ]
}

// Range-assert the amounts even though the recursion already constrains them to u128: defense-in-depth against a
// silent `as u128` narrowing.
pub fn unpack_intent(a: [Field; INTENT_PI_LEN]) -> SwapIntent {
    let from_amount = a[6] as u128;
    assert(from_amount as Field == a[6], "from_amount exceeds u128 range");
    let expected_return = a[7] as u128;
    assert(expected_return as Field == a[7], "expected_return exceeds u128 range");
    SwapIntent {
        nullifier: a[0],
        root: a[1],
        compliance_x: a[2],
        compliance_y: a[3],
        from_asset: a[4],
        to_asset: a[5],
        from_amount,
        expected_return,
        expiry: a[8],
        change_leaf: a[9],
        change_eph_x: a[10],
        change_ct: [a[11], a[12], a[13], a[14], a[15], a[16], a[17]],
        received_leaf: a[18],
        received_eph_x: a[19],
        received_ct: [a[20], a[21], a[22], a[23], a[24], a[25], a[26]],
    }
}

// the maker's settled outputs (become the kageSwap on-chain public inputs: 2 nullifiers + 4 leaves + events).
pub struct MintedOutput {
    pub leaf: Field,
    pub eph_pub: Point,
    pub ciphertext: [Field; CT_LEN],
}
pub struct RelayOutput {
    pub leaf: Field,
    pub eph_pub_x: Field,
    pub ciphertext: [Field; CT_LEN],
}
pub struct KageOutputs {
    pub taker_nullifier: Field,
    pub maker_nullifier: Field,
    pub root: Field,
    pub taker_change: RelayOutput, // relayed from the taker's proof
    pub taker_received: RelayOutput, // relayed from the taker's proof
    pub maker_received: MintedOutput, // minted by the maker
    pub maker_change: MintedOutput, // minted by the maker
}

// swap_intent (taker): spend A_in + mint her two self-notes (change + received). Client-provable.
pub fn build_intent(
    compliance_pk: Point,
    note_in: Note, // A_in (fromAsset)
    spend_scalar: Field,
    index_in: Field,
    path_in: [Field; TREE_DEPTH],
    change_note: Note, // A_out_change (fromAsset self-note)
    change_eph: Field,
    received_note: Note, // A_out_received (toAsset self-note the taker mints for herself)
    received_eph: Field,
    to_asset: Field,
    from_amount: u128,
    expiry: Field,
) -> SwapIntent {
    mint::assert_valid_compliance_pk(compliance_pk);

    let from_asset = note_in.asset_id;
    assert(from_asset != to_asset, "swap assets must differ");
    assert(change_note.asset_id == from_asset, "change asset mismatch");
    assert(received_note.asset_id == to_asset, "received asset mismatch");

    let (nullifier, computed_root) = verify_spend(note_in, spend_scalar, index_in, path_in);

    // fromAsset split: A_in == from_amount (released) + A_out_change (kept). the taker cannot inflate her change.
    conservation::assert_conserved([note_in.value], [change_note.value], from_amount);

    // Each output binds to only the taker's own consumed input; the counterparty index is recovered by compliance from
    // the atomic tx, so binding it here would only leak the taker's position to the maker.
    assert_parents_bound(change_note, [index_in, 0]);
    assert_parents_bound(received_note, [index_in, 0]);

    let change = mint::mint_self_note(change_note, change_eph, compliance_pk);
    let received = mint::mint_self_note(received_note, received_eph, compliance_pk);

    SwapIntent {
        nullifier,
        root: computed_root,
        compliance_x: compliance_pk.x,
        compliance_y: compliance_pk.y,
        from_asset,
        to_asset,
        from_amount,
        expected_return: received_note.value,
        expiry,
        change_leaf: change.leaf,
        change_eph_x: change.eph_pub.x,
        change_ct: change.ciphertext,
        received_leaf: received.leaf,
        received_eph_x: received.eph_pub.x,
        received_ct: received.ciphertext,
    }
}

// swap_settle (maker): runs after main authenticates intent via std::verify_proof_with_type; mints the maker's
// two self-notes and both conservations.
pub fn settle_swap(
    intent: SwapIntent,
    compliance_pk: Point,
    current_timestamp: Field,
    maker_note_in: Note, // B_in (toAsset)
    maker_spend_scalar: Field,
    maker_index: Field,
    maker_path: [Field; TREE_DEPTH],
    maker_received: Note, // B_out_received (fromAsset self-note)
    maker_received_eph: Field,
    maker_change: Note, // B_out_change (toAsset self-note)
    maker_change_eph: Field,
) -> KageOutputs {
    mint::assert_valid_compliance_pk(compliance_pk);

    // Both halves must target the SAME compliance key, else compliance cannot decrypt the taker's relayed notes.
    assert(intent.compliance_x == compliance_pk.x, "compliance key mismatch between halves");
    assert(intent.compliance_y == compliance_pk.y, "compliance key mismatch between halves");

    let (maker_nullifier, root_b) =
        verify_spend(maker_note_in, maker_spend_scalar, maker_index, maker_path);
    assert(root_b == intent.root, "inputs must share a root");
    assert(intent.nullifier != maker_nullifier, "cannot swap a note with itself");
    assert(maker_note_in.asset_id == intent.to_asset, "maker input asset mismatch");

    // current_timestamp is the solver witness; the contract MUST floor it to block time so the maker cannot settle
    // an expired swap against a stale price. intent.expiry is taker-authenticated (bound by the recursion).
    assert(current_timestamp.lt(intent.expiry), "swap expired");

    // B_received.value == from_amount closes fromAsset conservation across the two proofs (taker: A_in == from_amount + change).
    assert(maker_received.asset_id == intent.from_asset, "maker_received asset mismatch");
    assert(maker_received.value == intent.from_amount, "maker_received value mismatch");
    assert_parents_bound(maker_received, [maker_index, 0]);
    let breceived = mint::mint_self_note(maker_received, maker_received_eph, compliance_pk);

    // toAsset: B_in == expected_return + B_change forces the maker to deliver the taker's asked amount.
    assert(maker_change.asset_id == intent.to_asset, "maker_change asset mismatch");
    conservation::assert_conserved(
        [maker_note_in.value],
        [intent.expected_return, maker_change.value],
        0,
    );
    assert_parents_bound(maker_change, [maker_index, 0]);
    let bchange = mint::mint_self_note(maker_change, maker_change_eph, compliance_pk);

    // All 4 output ephemerals distinct: a shared eph gives a shared CEK, which is a two-time-pad on the stream
    // DEM. Comparing eph_pub.x is exact on the prime-order subgroup (same x implies same point).
    let e0 = intent.change_eph_x;
    let e1 = intent.received_eph_x;
    let e2 = breceived.eph_pub.x;
    let e3 = bchange.eph_pub.x;
    assert(e0 != e1, "output ephemerals must be distinct");
    assert(e0 != e2, "output ephemerals must be distinct");
    assert(e0 != e3, "output ephemerals must be distinct");
    assert(e1 != e2, "output ephemerals must be distinct");
    assert(e1 != e3, "output ephemerals must be distinct");
    assert(e2 != e3, "output ephemerals must be distinct");

    KageOutputs {
        taker_nullifier: intent.nullifier,
        maker_nullifier,
        root: intent.root,
        taker_change: RelayOutput {
            leaf: intent.change_leaf,
            eph_pub_x: intent.change_eph_x,
            ciphertext: intent.change_ct,
        },
        taker_received: RelayOutput {
            leaf: intent.received_leaf,
            eph_pub_x: intent.received_eph_x,
            ciphertext: intent.received_ct,
        },
        maker_received: MintedOutput {
            leaf: breceived.leaf,
            eph_pub: breceived.eph_pub,
            ciphertext: breceived.ciphertext,
        },
        maker_change: MintedOutput {
            leaf: bchange.leaf,
            eph_pub: bchange.eph_pub,
            ciphertext: bchange.ciphertext,
        },
    }
}

// Self-contained tests (no SDK / no recursion): a 2-leaf tree built in-circuit, every psi derived the way the mint
// asserts, and settle_swap run on the REAL build_intent output. The only unproven link is
// std::verify_proof_with_type (covered in the bb.js e2e).
mod tests {
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
}
