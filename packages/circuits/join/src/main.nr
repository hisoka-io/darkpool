use ::ecdh::Point;
use ::shared::{conservation, mint, TREE_DEPTH, verify_spend};
use ::shared::note::{assert_parents_bound, Note};

// Spend two notes (a spend scalar each) into one self note. Both inputs must share a root and yield
// distinct nullifiers (no self-join). Internal consolidation: no value leaves the pool, no asset output.
fn main(
    current_timestamp: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    note_a: Note,
    spend_scalar_a: Field,
    index_a: Field,
    path_a: [Field; TREE_DEPTH],
    note_b: Note,
    spend_scalar_b: Field,
    index_b: Field,
    path_b: [Field; TREE_DEPTH],
    note_out: Note,
    eph_out: Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; 7]) {
    let _ = current_timestamp;
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier_a, root_a) = verify_spend(note_a, spend_scalar_a, index_a, path_a);
    let (nullifier_b, root_b) = verify_spend(note_b, spend_scalar_b, index_b, path_b);
    assert(root_a == root_b, "inputs must share a root");
    assert(nullifier_a != nullifier_b, "cannot join a note with itself");
    // Canonical input order: pack_parents is positional, so index_a < index_b pins one note_out.parents
    // commitment per consumed set and defeats a prover reordering the two inputs.
    assert(index_a.lt(index_b), "join inputs must be strictly index-ordered");

    assert(note_a.asset_id == note_b.asset_id, "input asset mismatch");
    assert(note_a.asset_id == note_out.asset_id, "output asset mismatch");
    conservation::assert_conserved([note_a.value, note_b.value], [note_out.value], 0);
    assert_parents_bound(note_out, [index_a, index_b]);

    let out = mint::mint_self_note(note_out, eph_out, compliance_pk);

    (nullifier_a, nullifier_b, root_a, out.leaf, out.eph_pub.x, out.eph_pub.y, out.ciphertext)
}

fn note(value: u128, psi: Field) -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        psi,
        parents: 0,
    }
}

global CX: Field = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
global CY: Field = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;
global LEAF_A: Field = 0x1a6b6e47769e1f5de94e5ce9f3094b49cc9967d5ba3ef90df6af6598ca26d41b;
global LEAF_B: Field = 0x2065744fd5ee65c5747ac8277513f27eadda10f02f9b5bb58d28131ec808b102;

// KAT: byte-identical to the TS/Solidity golden vector (two-leaf tree, eph 24/26 inputs, 28 output).
#[test]
fn test_join_kat() {
    let note_a = note(
        100,
        0x271c8cc2341079e393fa781a5e7b4664b27b649d4f0277a53110b7937ed9fada,
    );
    let note_b = note(
        50,
        0x22c2ddd73188e4c766c528228312ae28595623aba1a5c5341a8f7154943842d3,
    );
    let mut note_out = note(
        150,
        0x09fb1bde9d635c97fa5a0884a8a38d961cec75db95e76629aabec8b63baec84a,
    );
    note_out.parents = 0x100000000;
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = LEAF_B;
    let mut path_b = [0; TREE_DEPTH];
    path_b[0] = LEAF_A;

    let (nf_a, nf_b, root, leaf, epk_x, epk_y, ct) = main(
        0,
        CX,
        CY,
        note_a,
        789,
        0,
        path_a,
        note_b,
        789,
        1,
        path_b,
        note_out,
        28,
    );
    assert(nf_a == 0x0d03e7c701405c0572f9c8904d08cadc64679d2fb2c7430cf3b691c2fc0517e0);
    assert(nf_b == 0x0ce50a6b4132e77d1aba13c3d3763957eb373bfe81e4cd1582e1b9ac26f143eb);
    assert(root == 0x23bbb50573c7f196c32e4fd8cd8e1d3fe32285e77deddc2bdcb2728ee512b8bb);
    assert(leaf == 0x1b008ec77c6cb53d1f0cafce3e1e993cb1b0b828173ac378e809547f83972038);
    assert(epk_x == 0x239a26d12954771a03d624b21a260f447412b746b66eede628a2f0af3be0a212);
    assert(epk_y == 0x00ba27f648e334fba30865fee39f857d8f64a0417d2b8cd5fc2f238d64cd3d1e);
    assert(ct[0] == 0x059d4801f52074b83e793e4c9461d1686c52340eb324ae906ee4392535da6a57);
}

// The output binds its parents to the two spent indexes (0 and 1); a forgery that zeroes them to fake a
// fresh deposit is rejected.
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn audit_reject_forged_output_parents() {
    let note_a = note(
        100,
        0x271c8cc2341079e393fa781a5e7b4664b27b649d4f0277a53110b7937ed9fada,
    );
    let note_b = note(
        50,
        0x22c2ddd73188e4c766c528228312ae28595623aba1a5c5341a8f7154943842d3,
    );
    let note_out = note(
        150,
        0x09fb1bde9d635c97fa5a0884a8a38d961cec75db95e76629aabec8b63baec84a,
    );
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = LEAF_B;
    let mut path_b = [0; TREE_DEPTH];
    path_b[0] = LEAF_A;
    let _ = main(
        0,
        CX,
        CY,
        note_a,
        789,
        0,
        path_a,
        note_b,
        789,
        1,
        path_b,
        note_out,
        28,
    );
}

#[test(should_fail_with = "value not conserved")]
fn audit_reject_value_inflation() {
    let note_a = note(
        100,
        0x271c8cc2341079e393fa781a5e7b4664b27b649d4f0277a53110b7937ed9fada,
    );
    let note_b = note(
        50,
        0x22c2ddd73188e4c766c528228312ae28595623aba1a5c5341a8f7154943842d3,
    );
    let note_out = note(
        200,
        0x09fb1bde9d635c97fa5a0884a8a38d961cec75db95e76629aabec8b63baec84a,
    );
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = LEAF_B;
    let mut path_b = [0; TREE_DEPTH];
    path_b[0] = LEAF_A;
    let _ = main(
        0,
        CX,
        CY,
        note_a,
        789,
        0,
        path_a,
        note_b,
        789,
        1,
        path_b,
        note_out,
        28,
    );
}

// Spending one leaf as both inputs yields equal nullifiers: the no-self-join guard must reject it.
#[test(should_fail_with = "cannot join a note with itself")]
fn audit_reject_self_join() {
    let note_a = note(
        100,
        0x271c8cc2341079e393fa781a5e7b4664b27b649d4f0277a53110b7937ed9fada,
    );
    let note_out = note(
        200,
        0x09fb1bde9d635c97fa5a0884a8a38d961cec75db95e76629aabec8b63baec84a,
    );
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = LEAF_B;
    let _ = main(
        0,
        CX,
        CY,
        note_a,
        789,
        0,
        path_a,
        note_a,
        789,
        0,
        path_a,
        note_out,
        28,
    );
}

// Swapping the two inputs (a at index 1, b at index 0) consumes the SAME set in reversed order; the
// strict-order guard rejects it so note_out.parents has one canonical form per consumed set.
#[test(should_fail_with = "join inputs must be strictly index-ordered")]
fn audit_reject_unordered_inputs() {
    let note_a = note(
        100,
        0x271c8cc2341079e393fa781a5e7b4664b27b649d4f0277a53110b7937ed9fada,
    );
    let note_b = note(
        50,
        0x22c2ddd73188e4c766c528228312ae28595623aba1a5c5341a8f7154943842d3,
    );
    let mut note_out = note(
        150,
        0x09fb1bde9d635c97fa5a0884a8a38d961cec75db95e76629aabec8b63baec84a,
    );
    note_out.parents = 0x100000000;
    // note_b lives at index 1, note_a at index 0; passing b first drives index_a = 1 > index_b = 0.
    let mut path_b_at_1 = [0; TREE_DEPTH];
    path_b_at_1[0] = LEAF_A;
    let mut path_a_at_0 = [0; TREE_DEPTH];
    path_a_at_0[0] = LEAF_B;
    let _ = main(
        0,
        CX,
        CY,
        note_b,
        789,
        1,
        path_b_at_1,
        note_a,
        789,
        0,
        path_a_at_0,
        note_out,
        28,
    );
}

// A non-membership witness: note_b opened against a bogus sibling roots to a different subtree, so the
// two inputs no longer share a root.
#[test(should_fail_with = "inputs must share a root")]
fn audit_reject_root_mismatch() {
    let note_a = note(
        100,
        0x271c8cc2341079e393fa781a5e7b4664b27b649d4f0277a53110b7937ed9fada,
    );
    let note_b = note(
        50,
        0x22c2ddd73188e4c766c528228312ae28595623aba1a5c5341a8f7154943842d3,
    );
    let note_out = note(
        150,
        0x09fb1bde9d635c97fa5a0884a8a38d961cec75db95e76629aabec8b63baec84a,
    );
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = LEAF_B;
    let mut path_b = [0; TREE_DEPTH];
    path_b[0] = 0x0abc;
    let _ = main(
        0,
        CX,
        CY,
        note_a,
        789,
        0,
        path_a,
        note_b,
        789,
        1,
        path_b,
        note_out,
        28,
    );
}
