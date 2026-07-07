use ::ecdh::Point;
use ::shared::{conservation, mint, open_multisig_note, TREE_DEPTH};
use ::shared::frost::{msg_transfer, verify_frost_spend};
use ::shared::note::{assert_parents_bound, Note};
use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y};

// Multisig transfer: a FROST quorum authorizes spending one MULTISIG note into a memo note for a STANDARD
// recipient (owner + wrap + tag all bind to in_pub_j) plus a MULTISIG change note back to the account. The
// recipient is bound via memo.leaf, so m need not carry it separately. Paying a MULTISIG recipient (owner=gpk
// != view=V) is a deferred feature (same unproven-V gap as group public-claim).
fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    gpk: Point,
    frost_r: Point,
    frost_z: Field,
    recipient_in_pub: Point,
    old_note: Note,
    old_note_index: Field,
    old_note_path: [Field; TREE_DEPTH],
    memo_note: Note,
    memo_eph: Field,
    change_note: Note,
    change_eph: Field,
    ) -> pub (Field, Field, Field, Field, Field, Field, Field, [Field; 7], Field, Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier, computed_root) =
        open_multisig_note(old_note, gpk, old_note_index, old_note_path);

    assert(old_note.asset_id == memo_note.asset_id, "memo asset mismatch");
    assert(old_note.asset_id == change_note.asset_id, "change asset mismatch");
    assert(memo_eph != change_eph, "ephemerals must be distinct");
    conservation::assert_conserved([old_note.value], [memo_note.value, change_note.value], 0);
    assert_parents_bound(memo_note, [old_note_index, 0]);
    assert_parents_bound(change_note, [old_note_index, 0]);

    let memo = mint::mint_incoming_note(memo_note, memo_eph, compliance_pk, recipient_in_pub);
    let change = mint::mint_self_note_multisig(change_note, change_eph, compliance_pk, gpk);

    let m = msg_transfer(
        computed_root,
        nullifier,
        memo.leaf,
        change.leaf,
        old_note.asset_id,
    );
    verify_frost_spend(gpk, frost_r, frost_z, m);

    (
        nullifier, computed_root, memo.leaf, memo.eph_pub.x, memo.eph_pub.y, memo.tag,
        memo.cek_wrap, memo.ciphertext, change.leaf, change.eph_pub.x, change.eph_pub.y,
        change.ciphertext,
    )
}

// Differential negatives for the multisig OUTPUT guards. The memo (STANDARD recipient) mints first, then the
// MULTISIG change; both guard asserts precede verify_frost_spend, so a dummy (frost_r, frost_z) never reached
// suffices. The consumed input is a well-formed MULTISIG note owned by the account gpk over a single-leaf
// synthetic tree; the memo fixtures (recipient key + owner + psi) are the transfer golden vector, so the memo
// mint fully succeeds and control reaches the change guards. gpk is the shared/src/frost.nr subgroup point.
global CX: Field = FIXTURE_COMPLIANCE_X;
global CY: Field = FIXTURE_COMPLIANCE_Y;
global ASSET_ID: Field = 0x1234567890123456789012345678901234567890;

fn kat_gpk() -> Point {
    Point {
        x: 0x2546ab52faee9ab8ead1ad868567473b9757c6456c137274b12a5c51330d764d,
        y: 0x0d7a564269d3675f75799ee9d7574b00d01190b243041994c0e460af507a71aa,
    }
}

fn gpk_owner() -> Field {
    let g = kat_gpk();
    poseidon::poseidon2::Poseidon2::hash([g.x, g.y], 2)
}

// Any on-curve point; never reached because an output guard fails first.
fn dummy_r() -> Point {
    Point {
        x: 0x262d28e21d283e57d8add3efde5b0ef36d18af221efa12d686b50fdae23c0b53,
        y: 0x20dba1d0aa62eab7f32a1a9eb2f4cb382080c3ea369f7422f9e27c075b9db09d,
    }
}

fn ms_input(value: u128) -> Note {
    Note {
        note_version: 1,
        asset_id: ASSET_ID,
        note_type: 1, // MULTISIG
        conditions_hash: 0,
        value,
        owner: gpk_owner(),
        psi: 0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731,
        parents: 0,
    }
}

fn recipient_in_pub() -> Point {
    Point {
        x: 0x1b16e357953d68d73398c838aa883cc65ddae2aef75a4bc437e4232afdbe43c8,
        y: 0x02d7ee0be055310d2895c5ed5090a8aa1c700e73c64294f1e817ec77f46b4fdc,
    }
}

// A STANDARD memo to recipient_in_pub with the transfer golden owner/psi (valid for memo_eph 0x378).
fn memo_note(note_type: Field) -> Note {
    Note {
        note_version: 1,
        asset_id: ASSET_ID,
        note_type,
        conditions_hash: 0,
        value: 40,
        owner: 0x1113074e2fb269d979ad2b64e6fe70b1967c67b007b706600603b847306aefe3,
        psi: 0x2ae9db6316c6ee380fa8c43bed4df9818e3207ff00b3cfb15a5ee1ef925f456d,
        parents: 0,
    }
}

// A MULTISIG change with the golden psi (valid for change_eph 9).
fn change_note(note_type: Field, owner: Field) -> Note {
    Note {
        note_version: 1,
        asset_id: ASSET_ID,
        note_type,
        conditions_hash: 0,
        value: 60,
        owner,
        psi: 0x0b78b93ec011fe550e1f125af7f7fa286a69a839cca56d248fa04abfe9312f7b,
        parents: 0,
    }
}

// THE P1 theft guard: a fully valid memo, but the MULTISIG change owner is set off the account gpk. The
// change owner pin rejects it before any FROST check.
#[test(should_fail_with = "multisig change/self must be owned by the account gpk")]
fn audit_reject_off_gpk_change_owner() {
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        dummy_r(),
        1,
        recipient_in_pub(),
        ms_input(100),
        0,
        [0; TREE_DEPTH],
        memo_note(0),
        0x378,
        change_note(1, gpk_owner() + 1),
        9,
    );
}

// Reserved note_type 2 on the STANDARD memo: mint_incoming_note has no note_type pin, so assert_valid_note_type
// gates it directly.
#[test(should_fail_with = "note_type not in {STANDARD, MULTISIG}")]
fn audit_reject_out_note_type_2() {
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        dummy_r(),
        1,
        recipient_in_pub(),
        ms_input(100),
        0,
        [0; TREE_DEPTH],
        memo_note(2),
        0x378,
        change_note(1, gpk_owner()),
        9,
    );
}

// A STANDARD change on the multisig self-mint: the note_type pin rejects it (the memo mints first and fully).
#[test(should_fail_with = "multisig self note must be MULTISIG")]
fn audit_reject_out_note_type_standard() {
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        dummy_r(),
        1,
        recipient_in_pub(),
        ms_input(100),
        0,
        [0; TREE_DEPTH],
        memo_note(0),
        0x378,
        change_note(0, gpk_owner()),
        9,
    );
}
