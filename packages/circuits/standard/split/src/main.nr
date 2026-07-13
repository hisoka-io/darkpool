mod mutation_tests;

use ::ecdh::Point;
use ::shared::{conservation, mint, TREE_DEPTH, verify_spend};
use ::shared::note::{assert_parents_bound, Note};
use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, fixture_note};

fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    note_in: Note,
    spend_scalar: Field,
    index_in: Field,
    path_in: [Field; TREE_DEPTH],
    note_out_1: Note,
    eph_1: Field,
    note_out_2: Note,
    eph_2: Field,
) -> pub (Field, Field, Field, Field, [Field; 7], Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier, computed_root) = verify_spend(note_in, spend_scalar, index_in, path_in);

    assert(note_in.asset_id == note_out_1.asset_id, "out1 asset mismatch");
    assert(note_in.asset_id == note_out_2.asset_id, "out2 asset mismatch");
    assert(eph_1 != eph_2, "ephemerals must be distinct");
    conservation::assert_conserved([note_in.value], [note_out_1.value, note_out_2.value], 0);
    assert_parents_bound(note_out_1, [index_in, 0]);
    assert_parents_bound(note_out_2, [index_in, 0]);

    let out1 = mint::mint_self_note(note_out_1, eph_1, compliance_pk);
    let out2 = mint::mint_self_note(note_out_2, eph_2, compliance_pk);

    (
        nullifier, computed_root, out1.leaf, out1.eph_pub.x, out1.ciphertext, out2.leaf,
        out2.eph_pub.x, out2.ciphertext,
    )
}

fn note_in() -> Note {
    fixture_note()
}

fn out_note(value: u128, psi: Field) -> Note {
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

global CX: Field = FIXTURE_COMPLIANCE_X;
global CY: Field = FIXTURE_COMPLIANCE_Y;

// KAT: byte-identical to the TS/Solidity golden vector (eph 15, 20).
#[test]
fn test_split_kat() {
    let out1 = out_note(
        40,
        0x017131231dbfc29f6bdfb775d6e859c148b7379acc2844380ff9f824fa7073ad,
    );
    let out2 = out_note(
        60,
        0x1fc1420fa8dd294ee9feaa5067000d40945bdc796e47ce5dfbfa4cbb4210ef8d,
    );
    let (nf, root, l1, x1, ct1, l2, x2, ct2) = main(
        CX,
        CY,
        note_in(),
        789,
        0,
        [0; TREE_DEPTH],
        out1,
        15,
        out2,
        20,
    );
    assert(nf == 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e);
    assert(root == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
    assert(l1 == 0x0bd308584b129cd9d8a38aedd72cf9d96ae13c4170f583959403de31c48f557c);
    assert(x1 == 0x0d2c8ddcfdd735e9fdd0d51538022ba533cfa83b81d2acec70b17f505c17f048);
    assert(ct1[0] == 0x068ce47d657722bad36cdc4a62ea2eda509a4d750d3aed5a6217f6bac4126413);
    assert(l2 == 0x1bd6da937554b7ddf449746023c99357419ff8b2481d7a93391a7610958421e0);
    assert(x2 == 0x28f4a492bbfdf5eed5ad1b304b95fb96040be5e4281bd288b1955f61bfac0afa);
    assert(ct2[6] == 0x2169b27f06c7e58cd045788ab94ad891299566c4274efb8da2eccdc9985a02c2);
}

#[test(should_fail_with = "value not conserved")]
fn audit_reject_value_inflation() {
    let out1 = out_note(
        100,
        0x017131231dbfc29f6bdfb775d6e859c148b7379acc2844380ff9f824fa7073ad,
    );
    let out2 = out_note(
        60,
        0x1fc1420fa8dd294ee9feaa5067000d40945bdc796e47ce5dfbfa4cbb4210ef8d,
    );
    let _ = main(
        CX,
        CY,
        note_in(),
        789,
        0,
        [0; TREE_DEPTH],
        out1,
        15,
        out2,
        20,
    );
}

fn out1_valid() -> Note {
    out_note(
        40,
        0x017131231dbfc29f6bdfb775d6e859c148b7379acc2844380ff9f824fa7073ad,
    )
}

fn out2_valid() -> Note {
    out_note(
        60,
        0x1fc1420fa8dd294ee9feaa5067000d40945bdc796e47ce5dfbfa4cbb4210ef8d,
    )
}

#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn audit_reject_forged_out_parents() {
    let mut out1 = out1_valid();
    out1.parents = 0x100000000;
    let _ = main(
        CX,
        CY,
        note_in(),
        789,
        0,
        [0; TREE_DEPTH],
        out1,
        15,
        out2_valid(),
        20,
    );
}

#[test(should_fail_with = "out1 asset mismatch")]
fn audit_reject_out_asset_mismatch() {
    let mut out1 = out1_valid();
    out1.asset_id = 0x00000000000000000000000000000000000000ff;
    let _ = main(
        CX,
        CY,
        note_in(),
        789,
        0,
        [0; TREE_DEPTH],
        out1,
        15,
        out2_valid(),
        20,
    );
}

// Reusing one eph across outputs reuses the CEK (two-time pad).
#[test(should_fail_with = "ephemerals must be distinct")]
fn audit_reject_reused_ephemeral() {
    let _ = main(
        CX,
        CY,
        note_in(),
        789,
        0,
        [0; TREE_DEPTH],
        out1_valid(),
        15,
        out2_valid(),
        15,
    );
}

#[test(should_fail)]
fn audit_reject_non_membership() {
    let mut path = [0; TREE_DEPTH];
    path[0] = 0x0abc;
    let (_, root, _, _, _, _, _, _) = main(
        CX,
        CY,
        note_in(),
        789,
        0,
        path,
        out1_valid(),
        15,
        out2_valid(),
        20,
    );
    assert(root == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
}
