mod mutation_tests;

use ::ecdh::Point;
use ::shared::{conservation, mint, open_multisig_note, TREE_DEPTH};
use ::shared::frost::{msg_transfer, verify_frost_spend};
use ::shared::note::{assert_parents_bound, Note, PARENTS_HIDDEN};
use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y};

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
) -> pub (Field, Field, Field, Field, Field, Field, [Field; 7], Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier, computed_root) =
        open_multisig_note(old_note, gpk, old_note_index, old_note_path);

    assert(old_note.asset_id == memo_note.asset_id, "memo asset mismatch");
    assert(old_note.asset_id == change_note.asset_id, "change asset mismatch");
    assert(memo_eph != change_eph, "ephemerals must be distinct");
    conservation::assert_conserved([old_note.value], [memo_note.value, change_note.value], 0);
    assert(memo_note.parents == PARENTS_HIDDEN, "memo parents must be hidden sentinel");
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
        nullifier, computed_root, memo.leaf, memo.eph_pub.x, memo.tag, memo.cek_wrap,
        memo.ciphertext, change.leaf, change.eph_pub.x, change.ciphertext,
    )
}

// Output guards run before verify_frost_spend, so a never-reached dummy (frost_r, frost_z) suffices.
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

fn memo_note(note_type: Field) -> Note {
    Note {
        note_version: 1,
        asset_id: ASSET_ID,
        note_type,
        conditions_hash: 0,
        value: 40,
        owner: 0x1113074e2fb269d979ad2b64e6fe70b1967c67b007b706600603b847306aefe3,
        psi: KAT_MEMO_PSI,
        parents: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000,
    }
}

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
        4,
        change_note(1, gpk_owner() + 1),
        9,
    );
}

#[test(should_fail_with = "incoming memo must be STANDARD")]
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
        4,
        change_note(1, gpk_owner()),
        9,
    );
}

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
        4,
        change_note(0, gpk_owner()),
        9,
    );
}

// Real 3-of-5 FROST witness from the TS signer (gen-transfer-multisig-kat); accept parity.
global KAT_MEMO_EPH: Field = 4;
global KAT_CHANGE_EPH: Field = 5;
global KAT_MEMO_PSI: Field = 0x2aaee0e06ff8b0e8cf78d66b27f27fe9d0e82cc687724cee2eb92b0d8a90c2c2;
global KAT_CHANGE_PSI: Field = 0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731;
global KAT_FROST_Z: Field = 0x0424497705eaf7f6ba5f214139a68360f95452f59e3ad516d5ecae9add7394c3;

fn kat_frost_r() -> Point {
    Point {
        x: 0x008babeca5f9585000f81e056618f155be2465d91cb96fe6816033427124216e,
        y: 0x08ec1033e38655b06fee2209b3e635117d9df86e34340901e3c14c3d24f90848,
    }
}

fn kat_memo_note(value: u128) -> Note {
    Note {
        note_version: 1,
        asset_id: ASSET_ID,
        note_type: 0,
        conditions_hash: 0,
        value,
        owner: 0x1113074e2fb269d979ad2b64e6fe70b1967c67b007b706600603b847306aefe3,
        psi: KAT_MEMO_PSI,
        parents: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000,
    }
}

fn kat_change_note(value: u128) -> Note {
    Note {
        note_version: 1,
        asset_id: ASSET_ID,
        note_type: 1,
        conditions_hash: 0,
        value,
        owner: gpk_owner(),
        psi: KAT_CHANGE_PSI,
        parents: 0,
    }
}

#[test]
fn kat_multisig_transfer_accepts() {
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        kat_frost_r(),
        KAT_FROST_Z,
        recipient_in_pub(),
        ms_input(100),
        0,
        [0; TREE_DEPTH],
        kat_memo_note(40),
        KAT_MEMO_EPH,
        kat_change_note(60),
        KAT_CHANGE_EPH,
    );
}

// Shifting a FROST-signed output value moves the memo/change leaves, so the recomputed m no longer matches the
// signature; conservation still holds (41 + 59 == 100) so control reaches verify_frost_spend, which rejects.
#[test(should_fail_with = "FROST signature invalid")]
fn audit_reject_mutated_signed_value() {
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        kat_frost_r(),
        KAT_FROST_Z,
        recipient_in_pub(),
        ms_input(100),
        0,
        [0; TREE_DEPTH],
        kat_memo_note(41),
        KAT_MEMO_EPH,
        kat_change_note(59),
        KAT_CHANGE_EPH,
    );
}
