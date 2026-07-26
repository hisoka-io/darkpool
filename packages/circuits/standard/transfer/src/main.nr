mod mutation_tests;

use ::ecdh::Point;
use ::shared::{conservation, mint, TREE_DEPTH, verify_spend};
use ::shared::note::{assert_parents_bound, Note, PARENTS_HIDDEN};
use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, fixture_note};

fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    recipient_spend_pub: Point,
    recipient_view_pub: Point,
    old_note: Note,
    spend_scalar: Field,
    old_note_index: Field,
    old_note_path: [Field; TREE_DEPTH],
    memo_note: Note,
    memo_eph: Field,
    change_note: Note,
    change_eph: Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; 7], Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier, computed_root) =
        verify_spend(old_note, spend_scalar, old_note_index, old_note_path);

    assert(old_note.asset_id == memo_note.asset_id, "memo asset mismatch");
    assert(old_note.asset_id == change_note.asset_id, "change asset mismatch");
    assert(memo_eph != change_eph, "ephemerals must be distinct");
    conservation::assert_conserved([old_note.value], [memo_note.value, change_note.value], 0);
    assert(memo_note.parents == PARENTS_HIDDEN, "memo parents must be hidden sentinel");
    assert_parents_bound(change_note, [old_note_index, 0]);

    let memo = mint::mint_incoming_note(
        memo_note,
        memo_eph,
        compliance_pk,
        recipient_spend_pub,
        recipient_view_pub,
    );
    let change = mint::mint_self_note(change_note, change_eph, compliance_pk);

    (
        nullifier, computed_root, memo.leaf, memo.eph_pub.x, memo.tag, memo.cek_wrap,
        memo.ciphertext, change.leaf, change.eph_pub.x, change.ciphertext,
    )
}

fn spent_note() -> Note {
    fixture_note()
}

fn memo_note() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 40,
        owner: 0x1113074e2fb269d979ad2b64e6fe70b1967c67b007b706600603b847306aefe3,
        psi: 0x017131231dbfc29f6bdfb775d6e859c148b7379acc2844380ff9f824fa7073ad,
        parents: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000,
    }
}

fn change_note() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 60,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        psi: 0x0b78b93ec011fe550e1f125af7f7fa286a69a839cca56d248fa04abfe9312f7b,
        parents: 0,
    }
}

fn recipient_in_pub() -> Point {
    Point {
        x: 0x1b16e357953d68d73398c838aa883cc65ddae2aef75a4bc437e4232afdbe43c8,
        y: 0x02d7ee0be055310d2895c5ed5090a8aa1c700e73c64294f1e817ec77f46b4fdc,
    }
}

fn recipient_spend_pub() -> Point {
    Point {
        x: 0x2c6bfc7fe056ed38e26ec136ec8aec5f63ecc4b52c44afba967649cf1e6e2311,
        y: 0x1ac7675df6265f6e12d1c79a2b3b6658a0d46a320fba497ad0b817f9b19e0f21,
    }
}

fn multisig_memo_note() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 1,
        conditions_hash: 0,
        value: 40,
        owner: 0x07dc9f016dede5a174d347724b643ecd7f4f34dd928715592162bd4f5814a685,
        psi: 0x017131231dbfc29f6bdfb775d6e859c148b7379acc2844380ff9f824fa7073ad,
        parents: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000,
    }
}

global CX: Field = FIXTURE_COMPLIANCE_X;
global CY: Field = FIXTURE_COMPLIANCE_Y;

// TS/Noir/Solidity parity golden
#[test]
fn test_transfer_kat() {
    let (nf, root, memo_leaf, memo_x, tag, cek_wrap, memo_ct, ch_leaf, ch_x, ch_ct) = main(
        CX,
        CY,
        recipient_in_pub(),
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo_note(),
        15,
        change_note(),
        9,
    );
    assert(nf == 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e);
    assert(root == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
    assert(memo_leaf == 0x24865e6a40c43311de26adacd9309c99c518638e7f6ff3c5823e275ae350d92a);
    assert(memo_x == 0x0d2c8ddcfdd735e9fdd0d51538022ba533cfa83b81d2acec70b17f505c17f048);
    assert(tag == 0x1b16e357953d68d73398c838aa883cc65ddae2aef75a4bc437e4232afdbe43c8);
    assert(cek_wrap == 0x1c26e418b18e2072f8862447c7abbff3cc888b9bef1976bf14d7cf6910a926a0);
    assert(memo_ct[0] == 0x068ce47d657722bad36cdc4a62ea2eda509a4d750d3aed5a6217f6bac4126413);
    assert(ch_leaf == 0x1dfb591c5a79719d6d3b8f3c602079a6c186a567bd8b3d1d8e7993a660ac5983);
    assert(ch_x == 0x0a677185fd6cd905b6a544b1006f4b3ea4a0dd596d47cabdab76a305859d928f);
    assert(ch_ct[6] == 0x186a5c31e828e71e5f90dd57189b8c718fc107fecda0a132f22e705a6896c8d6);
}

// Accept branch of the note_type biconditional: a MULTISIG memo is owned by the spend key and discovered by the view key.
#[test]
fn test_transfer_multisig_memo_kat() {
    let (nf, root, memo_leaf, _, tag, _, _, ch_leaf, _, _) = main(
        CX,
        CY,
        recipient_spend_pub(),
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        multisig_memo_note(),
        15,
        change_note(),
        9,
    );
    assert(nf == 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e);
    assert(root == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
    assert(memo_leaf == 0x1dab8f6ecc6105641d0548e3421227b862eae99834f1f69e3cc8b361e155b771);
    assert(tag == recipient_in_pub().x);
    assert(ch_leaf == 0x1dfb591c5a79719d6d3b8f3c602079a6c186a567bd8b3d1d8e7993a660ac5983);
}

#[test(should_fail_with = "memo owner must be the recipient owner")]
fn audit_reject_memo_owner_mismatch() {
    let mut memo = memo_note();
    memo.owner = 0xdeadbeef;
    let _ = main(
        CX,
        CY,
        recipient_in_pub(),
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo,
        15,
        change_note(),
        9,
    );
}

// (x, -y) is on-curve and non-identity: an x-only collapse check would mint a memo no scalar can spend.
#[test(should_fail_with = "STANDARD memo must collapse spend/view; MULTISIG must decouple them")]
fn audit_reject_y_twin_owner() {
    let twin = Point {
        x: recipient_in_pub().x,
        y: 0x2d8c606700dc6f1c8fba7fc930f0afb30bc3d9d4b376db9f5bca091bfb94b025,
    };
    let _ = main(
        CX,
        CY,
        twin,
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo_note(),
        15,
        change_note(),
        9,
    );
}

// A MULTISIG memo with collapsed spend/view keys is owned by the 1-of-n view key: t-of-n becomes 1-of-n.
#[test(should_fail_with = "STANDARD memo must collapse spend/view; MULTISIG must decouple them")]
fn audit_reject_multisig_memo_with_collapsed_keys() {
    let mut memo = memo_note();
    memo.note_type = 1;
    let _ = main(
        CX,
        CY,
        recipient_in_pub(),
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo,
        15,
        change_note(),
        9,
    );
}

#[test(should_fail_with = "ephemerals must be distinct")]
fn audit_reject_reused_ephemeral() {
    let _ = main(
        CX,
        CY,
        recipient_in_pub(),
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo_note(),
        9,
        change_note(),
        9,
    );
}

#[test(should_fail_with = "memo parents must be hidden sentinel")]
fn audit_reject_forged_memo_parents() {
    let mut memo = memo_note();
    memo.parents = 0x100000000;
    let _ = main(
        CX,
        CY,
        recipient_in_pub(),
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo,
        15,
        change_note(),
        9,
    );
}

#[test(should_fail_with = "value not conserved")]
fn audit_reject_value_inflation() {
    let mut memo = memo_note();
    memo.value = 100;
    let _ = main(
        CX,
        CY,
        recipient_in_pub(),
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo,
        15,
        change_note(),
        9,
    );
}

#[test(should_fail_with = "change asset mismatch")]
fn audit_reject_change_asset_mismatch() {
    let mut change = change_note();
    change.asset_id = 0x00000000000000000000000000000000000000ff;
    let _ = main(
        CX,
        CY,
        recipient_in_pub(),
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo_note(),
        15,
        change,
        9,
    );
}

#[test(should_fail)]
fn audit_reject_non_membership() {
    let mut path = [0; TREE_DEPTH];
    path[0] = 0x0abc;
    let (_, root, _, _, _, _, _, _, _, _) = main(
        CX,
        CY,
        recipient_in_pub(),
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        path,
        memo_note(),
        15,
        change_note(),
        9,
    );
    assert(root == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
}
