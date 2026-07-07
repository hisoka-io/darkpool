use ::ecdh::Point;
use ::shared::{conservation, mint, open_multisig_note, TREE_DEPTH};
use ::shared::frost::{msg_split, verify_frost_spend};
use ::shared::note::{assert_parents_bound, Note};
use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y};

fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    gpk: Point,
    frost_r: Point,
    frost_z: Field,
    note_in: Note,
    index_in: Field,
    path_in: [Field; TREE_DEPTH],
    note_out_1: Note,
    eph_1: Field,
    note_out_2: Note,
    eph_2: Field,
) -> pub (Field, Field, Field, Field, Field, [Field; 7], Field, Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier, computed_root) = open_multisig_note(note_in, gpk, index_in, path_in);

    assert(note_in.asset_id == note_out_1.asset_id, "out1 asset mismatch");
    assert(note_in.asset_id == note_out_2.asset_id, "out2 asset mismatch");
    assert(eph_1 != eph_2, "ephemerals must be distinct");
    conservation::assert_conserved([note_in.value], [note_out_1.value, note_out_2.value], 0);
    assert_parents_bound(note_out_1, [index_in, 0]);
    assert_parents_bound(note_out_2, [index_in, 0]);

    let out1 = mint::mint_self_note_multisig(note_out_1, eph_1, compliance_pk, gpk);
    let out2 = mint::mint_self_note_multisig(note_out_2, eph_2, compliance_pk, gpk);

    let m = msg_split(
        computed_root,
        nullifier,
        out1.leaf,
        out2.leaf,
        note_in.asset_id,
    );
    verify_frost_spend(gpk, frost_r, frost_z, m);

    (
        nullifier, computed_root, out1.leaf, out1.eph_pub.x, out1.eph_pub.y, out1.ciphertext,
        out2.leaf, out2.eph_pub.x, out2.eph_pub.y, out2.ciphertext,
    )
}

// Output guards run before verify_frost_spend, so a never-reached dummy (frost_r, frost_z) suffices; out1
// uses the golden self psi (eph 15) so it mints fully and control reaches out2's guard.
global CX: Field = FIXTURE_COMPLIANCE_X;
global CY: Field = FIXTURE_COMPLIANCE_Y;
global ASSET_ID: Field = 0x1234567890123456789012345678901234567890;
global OUT1_PSI: Field = 0x017131231dbfc29f6bdfb775d6e859c148b7379acc2844380ff9f824fa7073ad;

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

fn out_note(value: u128, note_type: Field, owner: Field, psi: Field) -> Note {
    Note {
        note_version: 1,
        asset_id: ASSET_ID,
        note_type,
        conditions_hash: 0,
        value,
        owner,
        psi,
        parents: 0,
    }
}

#[test(should_fail_with = "multisig change/self must be owned by the account gpk")]
fn audit_reject_off_gpk_change_owner_out1() {
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        dummy_r(),
        1,
        ms_input(100),
        0,
        [0; TREE_DEPTH],
        out_note(40, 1, gpk_owner() + 1, 0),
        15,
        out_note(60, 1, gpk_owner(), 0),
        20,
    );
}

#[test(should_fail_with = "multisig change/self must be owned by the account gpk")]
fn audit_reject_off_gpk_change_owner_out2() {
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        dummy_r(),
        1,
        ms_input(100),
        0,
        [0; TREE_DEPTH],
        out_note(40, 1, gpk_owner(), OUT1_PSI),
        15,
        out_note(60, 1, gpk_owner() + 1, 0),
        20,
    );
}

#[test(should_fail_with = "multisig self note must be MULTISIG")]
fn audit_reject_out_note_type_2() {
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        dummy_r(),
        1,
        ms_input(100),
        0,
        [0; TREE_DEPTH],
        out_note(40, 2, gpk_owner(), 0),
        15,
        out_note(60, 1, gpk_owner(), 0),
        20,
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
        ms_input(100),
        0,
        [0; TREE_DEPTH],
        out_note(40, 0, gpk_owner(), 0),
        15,
        out_note(60, 1, gpk_owner(), 0),
        20,
    );
}
