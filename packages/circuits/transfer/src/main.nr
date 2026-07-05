use ::ecdh::Point;
use ::shared::{conservation, mint, TREE_DEPTH, verify_spend};
use ::shared::note_v2::Note;

// Spend one note, mint the incoming memo note to the recipient (owner bound to in_pub_j, CEK wrapped to
// the recipient) plus the self change note. recipient_in_pub is PRIVATE; only its x (the discovery tag) is
// published.
fn main(
    current_timestamp: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    recipient_in_pub: Point,
    old_note: Note,
    spend_scalar: Field,
    old_note_index: Field,
    old_note_path: [Field; TREE_DEPTH],
    memo_note: Note,
    memo_eph: Field,
    change_note: Note,
    change_eph: Field,
    ) -> pub (Field, Field, Field, Field, Field, Field, Field, [Field; 7], Field, Field, Field, [Field; 7]) {
    let _ = current_timestamp;
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier, computed_root) =
        verify_spend(old_note, spend_scalar, old_note_index, old_note_path);

    assert(old_note.asset_id == memo_note.asset_id, "memo asset mismatch");
    assert(old_note.asset_id == change_note.asset_id, "change asset mismatch");
    assert(memo_eph != change_eph, "ephemerals must be distinct");
    conservation::assert_conserved([old_note.value], [memo_note.value, change_note.value], 0);

    let memo = mint::mint_incoming_note(memo_note, memo_eph, compliance_pk, recipient_in_pub);
    let change = mint::mint_self_note(change_note, change_eph, compliance_pk);

    (
        nullifier, computed_root, memo.leaf, memo.eph_pub.x, memo.eph_pub.y, memo.tag,
        memo.cek_wrap, memo.ciphertext, change.leaf, change.eph_pub.x, change.eph_pub.y,
        change.ciphertext,
    )
}

fn spent_note() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 100,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        psi: 0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731,
        parents: 0,
    }
}

fn memo_note() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 40,
        owner: 0x1113074e2fb269d979ad2b64e6fe70b1967c67b007b706600603b847306aefe3,
        psi: 0x2ae9db6316c6ee380fa8c43bed4df9818e3207ff00b3cfb15a5ee1ef925f456d,
        parents: 0,
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

global CX: Field = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
global CY: Field = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

// KAT: byte-identical to the TS/Solidity golden vector (memo eph 0x378 to in_key_j=4, change eph 9).
#[test]
fn test_transfer_kat() {
    let (nf, root, memo_leaf, memo_x, memo_y, tag, cek_wrap, memo_ct, ch_leaf, ch_x, ch_y, ch_ct) = main(
        0,
        CX,
        CY,
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo_note(),
        0x378,
        change_note(),
        9,
    );
    assert(nf == 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e);
    assert(root == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
    assert(memo_leaf == 0x192da44b73da0d163a65d76aac64fd3bc8ab96f2a1bee6ed64bc284e0ec4c6f2);
    assert(memo_x == 0x25fbe8bb651983f4e6651fb47245f7f058afcda6958a3e468dc50e8d77af07e6);
    assert(memo_y == 0x2fe08fd5f557d0326251711696f8bfb3cfd33fc3c15168019ac86c9e8af6f3a9);
    assert(tag == 0x1b16e357953d68d73398c838aa883cc65ddae2aef75a4bc437e4232afdbe43c8);
    assert(cek_wrap == 0x1b67cde705ce9682a9d976006cff63dfcc524dedaf6f8d4bc31ac09bc3e084a6);
    assert(memo_ct[0] == 0x29bb025dd94ba3d39cfc290a2b868a66b8053f6d9a6ecbf6aad13eec3430c45f);
    assert(ch_leaf == 0x1dfb591c5a79719d6d3b8f3c602079a6c186a567bd8b3d1d8e7993a660ac5983);
    assert(ch_x == 0x0a677185fd6cd905b6a544b1006f4b3ea4a0dd596d47cabdab76a305859d928f);
    assert(ch_y == 0x197ff60e146d51c662c83f975fdb7d86ed9a3be3d68ec62213c43264ef75a148);
    assert(ch_ct[6] == 0x186a5c31e828e71e5f90dd57189b8c718fc107fecda0a132f22e705a6896c8d6);
}

#[test(should_fail_with = "memo owner must be the recipient owner")]
fn audit_reject_memo_owner_mismatch() {
    let mut memo = memo_note();
    memo.owner = 0xdeadbeef;
    let _ = main(
        0,
        CX,
        CY,
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo,
        0x378,
        change_note(),
        9,
    );
}

// Distinct ephemerals per output: reusing one eph across memo and change reuses CEK (two-time pad).
#[test(should_fail_with = "ephemerals must be distinct")]
fn audit_reject_reused_ephemeral() {
    let _ = main(
        0,
        CX,
        CY,
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

#[test(should_fail_with = "value not conserved")]
fn audit_reject_value_inflation() {
    let mut memo = memo_note();
    memo.value = 100;
    let _ = main(
        0,
        CX,
        CY,
        recipient_in_pub(),
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        memo,
        0x378,
        change_note(),
        9,
    );
}
