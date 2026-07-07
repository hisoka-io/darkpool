use ::ecdh::Point;
use ::shared::{conservation, mint, open_multisig_note, TREE_DEPTH};
use ::shared::frost::{msg_join, verify_frost_spend};
use ::shared::note::{assert_parents_bound, Note};
use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y};

fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    gpk_a: Point,
    frost_r_a: Point,
    frost_z_a: Field,
    note_a: Note,
    index_a: Field,
    path_a: [Field; TREE_DEPTH],
    gpk_b: Point,
    frost_r_b: Point,
    frost_z_b: Field,
    note_b: Note,
    index_b: Field,
    path_b: [Field; TREE_DEPTH],
    note_out: Note,
    eph_out: Field,
) -> pub (Field, Field, Field, Field, Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier_a, root_a) = open_multisig_note(note_a, gpk_a, index_a, path_a);
    let (nullifier_b, root_b) = open_multisig_note(note_b, gpk_b, index_b, path_b);
    assert(root_a == root_b, "inputs must share a root");
    assert(nullifier_a != nullifier_b, "cannot join a note with itself");
    assert(index_a.lt(index_b), "join inputs must be strictly index-ordered");

    // Same-account only: a cross-account join with an unbound output owner would let either signer redirect
    // the merged value out of the other's reach (deferred feature).
    assert((gpk_a.x == gpk_b.x) & (gpk_a.y == gpk_b.y), "join inputs must share one account gpk");

    assert(note_a.asset_id == note_b.asset_id, "input asset mismatch");
    assert(note_a.asset_id == note_out.asset_id, "output asset mismatch");
    conservation::assert_conserved([note_a.value, note_b.value], [note_out.value], 0);
    assert_parents_bound(note_out, [index_a, index_b]);

    let out = mint::mint_self_note_multisig(note_out, eph_out, compliance_pk, gpk_a);

    let m = msg_join(root_a, nullifier_a, nullifier_b, out.leaf, note_a.asset_id);
    verify_frost_spend(gpk_a, frost_r_a, frost_z_a, m);
    verify_frost_spend(gpk_b, frost_r_b, frost_z_b, m);

    (nullifier_a, nullifier_b, root_a, out.leaf, out.eph_pub.x, out.eph_pub.y, out.ciphertext)
}

// Output guards run before verify_frost_spend, so never-reached dummy (frost_r, frost_z) suffice.
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

fn gpk_b() -> Point {
    Point {
        x: 0x262d28e21d283e57d8add3efde5b0ef36d18af221efa12d686b50fdae23c0b53,
        y: 0x20dba1d0aa62eab7f32a1a9eb2f4cb382080c3ea369f7422f9e27c075b9db09d,
    }
}

fn join_input(value: u128, owner: Field, psi: Field) -> Note {
    Note {
        note_version: 1,
        asset_id: ASSET_ID,
        note_type: 1, // MULTISIG
        conditions_hash: 0,
        value,
        owner,
        psi,
        parents: 0,
    }
}

fn out_note(note_type: Field, owner: Field) -> Note {
    Note {
        note_version: 1,
        asset_id: ASSET_ID,
        note_type,
        conditions_hash: 0,
        value: 150,
        owner,
        psi: 0,
        parents: 0x100000000,
    }
}

#[test(should_fail_with = "multisig change/self must be owned by the account gpk")]
fn audit_reject_off_gpk_change_owner() {
    let note_a = join_input(100, gpk_owner(), 0x01);
    let note_b = join_input(50, gpk_owner(), 0x02);
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = note_b.leaf();
    let mut path_b = [0; TREE_DEPTH];
    path_b[0] = note_a.leaf();
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        gpk_b(),
        1,
        note_a,
        0,
        path_a,
        kat_gpk(),
        gpk_b(),
        1,
        note_b,
        1,
        path_b,
        out_note(1, gpk_owner() + 1),
        28,
    );
}

#[test(should_fail_with = "multisig self note must be MULTISIG")]
fn audit_reject_out_note_type_2() {
    let note_a = join_input(100, gpk_owner(), 0x01);
    let note_b = join_input(50, gpk_owner(), 0x02);
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = note_b.leaf();
    let mut path_b = [0; TREE_DEPTH];
    path_b[0] = note_a.leaf();
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        gpk_b(),
        1,
        note_a,
        0,
        path_a,
        kat_gpk(),
        gpk_b(),
        1,
        note_b,
        1,
        path_b,
        out_note(2, gpk_owner()),
        28,
    );
}

#[test(should_fail_with = "multisig self note must be MULTISIG")]
fn audit_reject_out_note_type_standard() {
    let note_a = join_input(100, gpk_owner(), 0x01);
    let note_b = join_input(50, gpk_owner(), 0x02);
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = note_b.leaf();
    let mut path_b = [0; TREE_DEPTH];
    path_b[0] = note_a.leaf();
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        gpk_b(),
        1,
        note_a,
        0,
        path_a,
        kat_gpk(),
        gpk_b(),
        1,
        note_b,
        1,
        path_b,
        out_note(0, gpk_owner()),
        28,
    );
}

#[test(should_fail_with = "join inputs must share one account gpk")]
fn audit_reject_cross_account_gpk() {
    let b = gpk_b();
    let owner_b = poseidon::poseidon2::Poseidon2::hash([b.x, b.y], 2);
    let note_a = join_input(100, gpk_owner(), 0x01);
    let note_b = join_input(50, owner_b, 0x02);
    let mut path_a = [0; TREE_DEPTH];
    path_a[0] = note_b.leaf();
    let mut path_b = [0; TREE_DEPTH];
    path_b[0] = note_a.leaf();
    let _ = main(
        CX,
        CY,
        kat_gpk(),
        gpk_b(),
        1,
        note_a,
        0,
        path_a,
        gpk_b(),
        gpk_b(),
        1,
        note_b,
        1,
        path_b,
        out_note(1, gpk_owner()),
        28,
    );
}
