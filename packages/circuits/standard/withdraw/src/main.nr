mod mutation_tests;

use ::ecdh::Point;
use ::shared::{conservation, mint, TREE_DEPTH, verify_spend};
use ::shared::note::{assert_parents_bound, Note};
use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, fixture_note};

fn main(
    withdraw_value: pub u128,
    _recipient: pub Field,
    _intent_hash: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    old_note: Note,
    spend_scalar: Field,
    old_note_index: Field,
    old_note_path: [Field; TREE_DEPTH],
    change_note: Note,
    change_eph: Field,
) -> pub (Field, Field, Field, Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier, computed_root) =
        verify_spend(old_note, spend_scalar, old_note_index, old_note_path);

    assert(old_note.asset_id == change_note.asset_id, "asset mismatch");
    conservation::assert_conserved([old_note.value], [change_note.value], withdraw_value);
    assert_parents_bound(change_note, [old_note_index, 0]);

    let change = mint::mint_self_note(change_note, change_eph, compliance_pk);

    (nullifier, computed_root, old_note.asset_id, change.leaf, change.eph_pub.x, change.ciphertext)
}

fn spent_note() -> Note {
    fixture_note()
}

fn change_note() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 60,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        psi: 0x094cb623c946044df25c471166b70569c57b22e5b6af36baeb1349c48a4ba160,
        parents: 0,
    }
}

fn compliance() -> (Field, Field) {
    (FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y)
}

// KAT: byte-identical to the TS/Solidity golden vector (spend scalar 789 owns the index-0 note; change eph 8).
#[test]
fn test_withdraw_kat() {
    let (cx, cy) = compliance();
    let (nf, root, asset, change_leaf, epk_x, ct) = main(
        40,
        0x1234567890123456789012345678901234567890,
        0,
        cx,
        cy,
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        change_note(),
        8,
    );
    assert(nf == 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e);
    assert(root == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
    assert(asset == 0x1234567890123456789012345678901234567890);
    assert(change_leaf == 0x18509db8cff8ae040ded2a5ef14477885362213786db084c16c4b544f62776ef);
    assert(epk_x == 0x10c347ae3592776a678f9fc29ecd029f8297367209a4f28f7cb49b09bffd4145);
    assert(ct[0] == 0x2bbfb5aee72b9356d592a976eac4ad5286227a78e9daa3d8c2cb843c882fdf2e);
}

#[test(should_fail_with = "spender does not own this note")]
fn audit_reject_wrong_spender() {
    let (cx, cy) = compliance();
    let _ = main(
        40,
        0,
        0,
        cx,
        cy,
        spent_note(),
        0x2a,
        0,
        [0; TREE_DEPTH],
        change_note(),
        8,
    );
}

#[test(should_fail_with = "value not conserved")]
fn audit_reject_value_inflation() {
    let (cx, cy) = compliance();
    let mut inflated = change_note();
    inflated.value = 100;
    let _ = main(
        40,
        0,
        0,
        cx,
        cy,
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        inflated,
        8,
    );
}

#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn audit_reject_forged_change_parents() {
    let (cx, cy) = compliance();
    let mut change = change_note();
    change.parents = 0x100000000;
    let _ = main(
        40,
        0,
        0,
        cx,
        cy,
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        change,
        8,
    );
}

#[test(should_fail_with = "asset mismatch")]
fn audit_reject_change_asset_mismatch() {
    let (cx, cy) = compliance();
    let mut change = change_note();
    change.asset_id = 0x00000000000000000000000000000000000000ff;
    let _ = main(
        40,
        0,
        0,
        cx,
        cy,
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        change,
        8,
    );
}

#[test(should_fail)]
fn audit_reject_non_membership() {
    let (cx, cy) = compliance();
    let mut path = [0; TREE_DEPTH];
    path[0] = 0x0abc;
    let (_, root, _, _, _, _) = main(
        40,
        0,
        0,
        cx,
        cy,
        spent_note(),
        789,
        0,
        path,
        change_note(),
        8,
    );
    assert(root == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
}
