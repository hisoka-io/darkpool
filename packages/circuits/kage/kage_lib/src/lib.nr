//! Kage private in-pool swap -- shared core logic for both halves.
//!
//! A swap is FOUR self-notes, two minted by each party. Alice mints her own outputs inside her own proof, so Bob
//! cannot redirect or shortchange them -- the output-owner binding is STRUCTURAL, not a constraint. Neither party
//! learns the other's psi (each mints to itself) or leaf index (each binds parents to only its own input).
//!
//!   pre_swap       (Alice/taker): spend A_in (fromAsset); mint A_out_change (fromAsset) + A_out_received
//!                                 (toAsset), both self-notes; expose the values Bob needs + expiry.
//!   recursive_swap (Bob/maker):   verify Alice's proof inside; spend B_in (toAsset); mint B_out_received
//!                                 (fromAsset) + B_out_change (toAsset), both self-notes; run BOTH conservations.
//!
//! Per-asset conservation, split across the two proofs:
//!   fromAsset:  A_in == from_amount + A_out_change   (Alice)   AND   B_out_received == from_amount   (Bob)
//!   toAsset:    B_in == expected_return + B_out_change            (Bob, using Alice's exposed expected_return)
//!
//! Reuses the frozen shared primitives (verify_spend / mint_self_note / conservation / note), so Kage is additive
//! to the note format. eph.x-only: every emitted ephemeral is even-y canonicalized (mint_self_note asserts it), so
//! only eph_pub.x is surfaced and y is recovered off-chain.

use ecdh::Point;
use shared::conservation;
use shared::mint;
use shared::note::{assert_parents_bound, Note};
use shared::TREE_DEPTH;
use shared::verify_spend;

// DEM transmitted-field count (shared/src/common/dem.nr DEM_FIELDS).
global CT_LEN: u32 = 7;

// Inner-VK binding -- the single most load-bearing value in Kage. `verification_key` is a solver-supplied WITNESS;
// the only thing stopping a solver from passing a random VK plus a proof of his own malicious circuit (forging
// Alice's entire half) is this key_hash: verify_proof_with_type makes the backend enforce
// hash(verification_key) == key_hash, and because it is a hardcoded CONSTANT it pins the inner circuit to the
// canonical pre_swap. Three requirements: (1) set it to the real bb VK hash of the compiled pre_swap (`0` = NOT
// pinned = total forge); (2) keep it a compile-time CONSTANT (the stdlib assert_constants proof_type but NOT
// key_hash; a witness key_hash lets the solver pick both VK and hash); (3) the stdlib does not itself constrain
// hash(vk)==key_hash (backend-defined; barretenberg enforces it, as Payy relies on in production), so it is gated
// by an adversarial test: wrong VK / different-circuit proof / tampered public inputs all reject.
pub global PRE_SWAP_VK_HASH: Field =
    0x00fb71aeb00e890cc5e4e94bbc75ac0043eb2e0eb9e9a333461bf3c0eee38cb2;
pub global PROOF_TYPE: u32 = 6;
// VK / proof widths are the compiled pre_swap's bb recursion values (verifierTarget noir-recursive); regenerate on
// any pre_swap change. Tests never touch the recursion call (they drive kage_settle on real pre_swap output).
pub global PRE_SWAP_VK_LEN: u32 = 115;
pub global PRE_SWAP_PROOF_LEN: u32 = 500;

// Public-input width pre_swap exposes (see pack_alice_pi): 9 scalars + (leaf + eph_x + ct[7]) per note x 2.
pub global ALICE_PI_LEN: u32 = 27;

// ---------------------------------------------------------------------------------------------------------------
// Alice's pre_swap public interface (consumed as WITNESS by Bob's recursion; never surfaced on-chain).
// The two amount fields ARE the swap terms; the two note blocks are relayed on-chain for insertion + events.
// ---------------------------------------------------------------------------------------------------------------
pub struct AlicePublicInputs {
    pub nullifier: Field, // A_in nullifier
    pub root: Field,
    pub compliance_x: Field, // C Alice used (Bob binds his C to it)
    pub compliance_y: Field,
    pub from_asset: Field,
    pub to_asset: Field,
    pub from_amount: u128, // fromAsset Alice releases (Bob binds B_out_received to it)
    pub expected_return: u128, // toAsset Alice wants (== A_out_received.value; Bob's toAsset conservation)
    pub expiry: Field,
    pub change_leaf: Field, // A_out_change (fromAsset self-note)
    pub change_eph_x: Field,
    pub change_ct: [Field; CT_LEN],
    pub received_leaf: Field, // A_out_received (toAsset self-note)
    pub received_eph_x: Field,
    pub received_ct: [Field; CT_LEN],
}

pub fn pack_alice_pi(pi: AlicePublicInputs) -> [Field; ALICE_PI_LEN] {
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

// The recursion authenticates that Alice's circuit constrained the amount fields to u128; the explicit range
// assert keeps value integrity from leaning solely on the pin plus the `as u128` narrowing. The tested kage_settle
// path receives the struct with genuine u128s and never casts.
pub fn unpack_alice_pi(a: [Field; ALICE_PI_LEN]) -> AlicePublicInputs {
    let from_amount = a[6] as u128;
    assert(from_amount as Field == a[6], "from_amount exceeds u128 range");
    let expected_return = a[7] as u128;
    assert(expected_return as Field == a[7], "expected_return exceeds u128 range");
    AlicePublicInputs {
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

// ---------------------------------------------------------------------------------------------------------------
// Bob's settled outputs (become the kageSwap on-chain public inputs: 2 nullifiers + 4 leaves + events).
// ---------------------------------------------------------------------------------------------------------------
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
    pub nullifier_a: Field,
    pub nullifier_b: Field,
    pub root: Field,
    pub alice_change: RelayOutput, // relayed from Alice's proof
    pub alice_received: RelayOutput, // relayed from Alice's proof
    pub bob_received: MintedOutput, // minted by Bob
    pub bob_change: MintedOutput, // minted by Bob
}

// ---------------------------------------------------------------------------------------------------------------
// Circuit 1 -- pre_swap (Alice). Spend A_in + mint her own two self-notes (change + received). Client-provable.
// ---------------------------------------------------------------------------------------------------------------
pub fn pre_swap_core(
    compliance_pk: Point,
    note_in: Note, // A_in (fromAsset)
    spend_scalar: Field,
    index_in: Field,
    path_in: [Field; TREE_DEPTH],
    change_note: Note, // A_out_change (fromAsset self-note)
    change_eph: Field,
    received_note: Note, // A_out_received (toAsset self-note Alice mints for herself)
    received_eph: Field,
    to_asset: Field,
    from_amount: u128,
    expiry: Field,
) -> AlicePublicInputs {
    mint::assert_valid_compliance_pk(compliance_pk);

    let from_asset = note_in.asset_id;
    assert(from_asset != to_asset, "swap assets must differ");
    assert(change_note.asset_id == from_asset, "change asset mismatch");
    assert(received_note.asset_id == to_asset, "received asset mismatch");

    let (nullifier, computed_root) = verify_spend(note_in, spend_scalar, index_in, path_in);

    // fromAsset split: A_in == from_amount (released) + A_out_change (kept). Alice cannot inflate her change.
    conservation::assert_conserved([note_in.value], [change_note.value], from_amount);

    // Each output binds to only Alice's own consumed input; the counterparty index is recovered by compliance from
    // the atomic tx, so binding it here would only leak Alice's position to Bob.
    assert_parents_bound(change_note, [index_in, 0]);
    assert_parents_bound(received_note, [index_in, 0]);

    let change = mint::mint_self_note(change_note, change_eph, compliance_pk);
    let received = mint::mint_self_note(received_note, received_eph, compliance_pk);

    AlicePublicInputs {
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

// ---------------------------------------------------------------------------------------------------------------
// Circuit 2 -- recursive_swap (Bob), settlement logic. Called AFTER main authenticates alice_pi via
// std::verify_proof_with_type. Bob mints only his two self-notes; both conservations live here.
// ---------------------------------------------------------------------------------------------------------------
pub fn kage_settle(
    alice_pi: AlicePublicInputs,
    compliance_pk: Point,
    current_timestamp: Field,
    note_b_in: Note, // B_in (toAsset)
    spend_scalar_b: Field,
    index_b: Field,
    path_b: [Field; TREE_DEPTH],
    bob_received: Note, // B_out_received (fromAsset self-note)
    eph_breceived: Field,
    bob_change: Note, // B_out_change (toAsset self-note)
    eph_bchange: Field,
) -> KageOutputs {
    mint::assert_valid_compliance_pk(compliance_pk);

    // Both halves must target the SAME compliance key, else compliance cannot decrypt Alice's relayed notes.
    assert(alice_pi.compliance_x == compliance_pk.x, "compliance key mismatch between halves");
    assert(alice_pi.compliance_y == compliance_pk.y, "compliance key mismatch between halves");

    let (nullifier_b, root_b) = verify_spend(note_b_in, spend_scalar_b, index_b, path_b);
    assert(root_b == alice_pi.root, "inputs must share a root");
    assert(alice_pi.nullifier != nullifier_b, "cannot swap a note with itself");
    assert(note_b_in.asset_id == alice_pi.to_asset, "bob input asset mismatch");

    // current_timestamp is the solver witness; the contract floors it to block time (>= now - tolerance) so Bob
    // cannot settle an expired swap against Alice's stale price. expiry is Alice-authenticated (alice_pi.expiry,
    // committed in pre_swap and bound by the recursion).
    assert(current_timestamp.lt(alice_pi.expiry), "swap expired");

    // B_out_received: Bob receives exactly from_amount of fromAsset. With Alice's pre_swap check
    // (A_in == from_amount + A_out_change) this conserves fromAsset across the two proofs.
    assert(bob_received.asset_id == alice_pi.from_asset, "bob_received asset mismatch");
    assert(bob_received.value == alice_pi.from_amount, "bob_received value mismatch");
    assert_parents_bound(bob_received, [index_b, 0]);
    let breceived = mint::mint_self_note(bob_received, eph_breceived, compliance_pk);

    // B_out_change: Bob keeps the toAsset remainder. toAsset conservation binds Alice's ask (expected_return): Bob
    // cannot settle unless he gives Alice exactly what her received note claims.
    assert(bob_change.asset_id == alice_pi.to_asset, "bob_change asset mismatch");
    conservation::assert_conserved(
        [note_b_in.value],
        [alice_pi.expected_return, bob_change.value],
        0,
    );
    assert_parents_bound(bob_change, [index_b, 0]);
    let bchange = mint::mint_self_note(bob_change, eph_bchange, compliance_pk);

    // All 4 output ephemerals distinct: a shared eph -> shared CEK -> two-time-pad on the stream DEM. Comparing
    // eph_pub.x is exact on the prime-order subgroup (same x => same point).
    let e0 = alice_pi.change_eph_x;
    let e1 = alice_pi.received_eph_x;
    let e2 = breceived.eph_pub.x;
    let e3 = bchange.eph_pub.x;
    assert(e0 != e1, "output ephemerals must be distinct");
    assert(e0 != e2, "output ephemerals must be distinct");
    assert(e0 != e3, "output ephemerals must be distinct");
    assert(e1 != e2, "output ephemerals must be distinct");
    assert(e1 != e3, "output ephemerals must be distinct");
    assert(e2 != e3, "output ephemerals must be distinct");

    KageOutputs {
        nullifier_a: alice_pi.nullifier,
        nullifier_b,
        root: alice_pi.root,
        alice_change: RelayOutput {
            leaf: alice_pi.change_leaf,
            eph_pub_x: alice_pi.change_eph_x,
            ciphertext: alice_pi.change_ct,
        },
        alice_received: RelayOutput {
            leaf: alice_pi.received_leaf,
            eph_pub_x: alice_pi.received_eph_x,
            ciphertext: alice_pi.received_ct,
        },
        bob_received: MintedOutput {
            leaf: breceived.leaf,
            eph_pub: breceived.eph_pub,
            ciphertext: breceived.ciphertext,
        },
        bob_change: MintedOutput {
            leaf: bchange.leaf,
            eph_pub: bchange.eph_pub,
            ciphertext: bchange.ciphertext,
        },
    }
}

// ===============================================================================================================
// Tests -- self-contained (no SDK / no live recursion). A 2-leaf tree is built in-circuit; every psi is derived
// with the same ECDH+Poseidon2 the mint asserts, so notes are valid by construction. kage_settle runs on the REAL
// AlicePublicInputs from pre_swap_core, so the two halves are proven to compose on genuine values -- the only
// unproven link is std::verify_proof_with_type (exercised in the bb.js e2e, not here).
// ===============================================================================================================
mod tests {
    use super::{AlicePublicInputs, kage_settle, KageOutputs, pre_swap_core};
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
        note_a_in: Note,
        a_change: Note,
        a_received: Note,
        note_b_in: Note,
        b_received: Note,
        b_change: Note,
        to_asset: Field,
        from_amount: u128,
        expiry: Field,
        path_a: [Field; TREE_DEPTH],
        path_b: [Field; TREE_DEPTH],
        current_ts: Field,
    }

    fn build(
        note_a_in: Note,
        a_change: Note,
        a_received: Note,
        note_b_in: Note,
        b_received: Note,
        b_change: Note,
        to_asset: Field,
        from_amount: u128,
        expiry: Field,
        current_ts: Field,
    ) -> Scenario {
        let leaf_a = note_a_in.leaf();
        let leaf_b = note_b_in.leaf();
        let mut path_a = [0; TREE_DEPTH];
        path_a[0] = leaf_b;
        let mut path_b = [0; TREE_DEPTH];
        path_b[0] = leaf_a;
        Scenario {
            note_a_in,
            a_change,
            a_received,
            note_b_in,
            b_received,
            b_change,
            to_asset,
            from_amount,
            expiry,
            path_a,
            path_b,
            current_ts,
        }
    }

    // A_in 100 fromAsset -> release 60, keep 40 change; Alice wants 50 toAsset. B_in 100 toAsset -> Bob keeps 50.
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

    fn alice(s: Scenario) -> AlicePublicInputs {
        pre_swap_core(
            compliance(),
            s.note_a_in,
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

    fn settle(s: Scenario, alice_pi: AlicePublicInputs) -> KageOutputs {
        kage_settle(
            alice_pi,
            compliance(),
            s.current_ts,
            s.note_b_in,
            SPEND,
            INDEX_B,
            s.path_b,
            s.b_received,
            EPH_B_RECEIVED,
            s.b_change,
            EPH_B_CHANGE,
        )
    }

    #[test]
    fn kage_swap_accepts() {
        let s = scenario();
        let alice_pi = alice(s);
        let out = settle(s, alice_pi);
        assert(out.nullifier_a != out.nullifier_b);
        assert(out.root == alice_pi.root);
        assert(out.alice_received.leaf == alice_pi.received_leaf);
        assert(out.alice_change.leaf == alice_pi.change_leaf);
    }

    // ---- pre_swap (Alice) negatives ----
    #[test(should_fail_with = "value not conserved")]
    fn alice_reject_change_inflation() {
        let mut s = scenario();
        s.a_change = note(
            FROM_ASSET,
            50,
            psi_of(EPH_A_CHANGE, compliance()),
            PARENTS_A,
        );
        let _ = alice(s);
    }

    #[test(should_fail_with = "swap assets must differ")]
    fn alice_reject_same_asset_swap() {
        let mut s = scenario();
        s.to_asset = FROM_ASSET;
        let _ = alice(s);
    }

    #[test(should_fail_with = "change asset mismatch")]
    fn alice_reject_change_asset_mismatch() {
        let mut s = scenario();
        s.a_change = note(TO_ASSET, 40, psi_of(EPH_A_CHANGE, compliance()), PARENTS_A);
        let _ = alice(s);
    }

    #[test(should_fail_with = "received asset mismatch")]
    fn alice_reject_received_asset_mismatch() {
        let mut s = scenario();
        s.a_received = note(
            FROM_ASSET,
            50,
            psi_of(EPH_A_RECEIVED, compliance()),
            PARENTS_A,
        );
        let _ = alice(s);
    }

    // ---- recursive_swap (Bob) negatives ----

    // Alice cannot inflate her OWN received note: Bob's toAsset conservation makes the swap unfillable.
    #[test(should_fail_with = "value not conserved")]
    fn bob_reject_alice_received_inflation() {
        let c = compliance();
        let s = build(
            note(FROM_ASSET, 100, psi_of(111, c), 0),
            note(FROM_ASSET, 40, psi_of(EPH_A_CHANGE, c), PARENTS_A),
            note(TO_ASSET, 1000, psi_of(EPH_A_RECEIVED, c), PARENTS_A), // Alice asks for 1000 toAsset
            note(TO_ASSET, 100, psi_of(222, c), 0),
            note(FROM_ASSET, 60, psi_of(EPH_B_RECEIVED, c), PARENTS_B),
            note(TO_ASSET, 50, psi_of(EPH_B_CHANGE, c), PARENTS_B),
            TO_ASSET,
            60,
            2000000000,
            1000000000,
        );
        let alice_pi = alice(s);
        let _ = settle(s, alice_pi);
    }

    // Bob keeps too much toAsset.
    #[test(should_fail_with = "value not conserved")]
    fn bob_reject_toasset_inflation() {
        let s = scenario();
        let alice_pi = alice(s);
        let mut s2 = scenario();
        s2.b_change = note(TO_ASSET, 60, psi_of(EPH_B_CHANGE, compliance()), PARENTS_B);
        let _ = settle(s2, alice_pi);
    }

    // Bob credits himself more fromAsset than Alice released.
    #[test(should_fail_with = "bob_received value mismatch")]
    fn bob_reject_fromasset_inflation() {
        let s = scenario();
        let alice_pi = alice(s);
        let mut s2 = scenario();
        s2.b_received = note(
            FROM_ASSET,
            80,
            psi_of(EPH_B_RECEIVED, compliance()),
            PARENTS_B,
        );
        let _ = settle(s2, alice_pi);
    }

    // Bob settles against a different root than Alice proved.
    #[test(should_fail_with = "inputs must share a root")]
    fn bob_reject_root_mismatch() {
        let s = scenario();
        let alice_pi = alice(s);
        let mut s2 = scenario();
        s2.path_b[0] = 0x0abc;
        let _ = settle(s2, alice_pi);
    }

    // settle after the deadline.
    #[test(should_fail_with = "swap expired")]
    fn bob_reject_expired() {
        let s = scenario();
        let alice_pi = alice(s);
        let mut s2 = scenario();
        s2.current_ts = 2000000001;
        let _ = settle(s2, alice_pi);
    }

    // Bob forges the backward-trace parentage on a produced note.
    #[test(should_fail_with = "output parents not bound to consumed inputs")]
    fn bob_reject_forged_parents() {
        let s = scenario();
        let alice_pi = alice(s);
        let mut s2 = scenario();
        s2.b_received = note(FROM_ASSET, 60, psi_of(EPH_B_RECEIVED, compliance()), 0x999);
        let _ = settle(s2, alice_pi);
    }

    // Compliance parity: Alice used one C, Bob settles under a different (still valid) key.
    #[test(should_fail_with = "compliance key mismatch between halves")]
    fn bob_reject_compliance_mismatch() {
        let s = scenario();
        let alice_pi = alice(s);
        let _ = kage_settle(
            alice_pi,
            other_compliance(),
            s.current_ts,
            s.note_b_in,
            SPEND,
            INDEX_B,
            s.path_b,
            s.b_received,
            EPH_B_RECEIVED,
            s.b_change,
            EPH_B_CHANGE,
        );
    }

    // Bob's input is not the toAsset Alice wants (tree built around the wrong-asset B_in so the root check passes
    // and the asset guard is what fires).
    #[test(should_fail_with = "bob input asset mismatch")]
    fn bob_reject_wrong_input_asset() {
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
        let alice_pi = alice(s);
        let _ = settle(s, alice_pi);
    }

    // Bob reuses b_received's ephemeral for b_change: a shared eph gives a shared CEK, a two-time-pad on the
    // stream DEM. kage_settle asserts all four output ephemerals are pairwise distinct.
    #[test(should_fail_with = "output ephemerals must be distinct")]
    fn bob_reject_duplicate_ephemeral() {
        let s = scenario();
        let alice_pi = alice(s);
        let mut s2 = scenario();
        s2.b_change = note(
            TO_ASSET,
            50,
            psi_of(EPH_B_RECEIVED, compliance()),
            PARENTS_B,
        );
        let _ = kage_settle(
            alice_pi,
            compliance(),
            s2.current_ts,
            s2.note_b_in,
            SPEND,
            INDEX_B,
            s2.path_b,
            s2.b_received,
            EPH_B_RECEIVED,
            s2.b_change,
            EPH_B_RECEIVED,
        );
    }
}
