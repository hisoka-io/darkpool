use ::ecdh::Point;
use ::shared::{
    encrypt_note_for_compliance, lean_imt_inclusion_proof, Note, TREE_DEPTH, verify_spend,
};

fn main(
    withdraw_value: pub u128,
    _recipient: pub Field,
    merkle_root: pub Field,
    current_timestamp: pub Field,
    _intent_hash: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    old_note: Note,
    old_shared_secret: Field,
    old_note_index: Field,
    old_note_path: [Field; TREE_DEPTH],
    hashlock_preimage: Field,
    change_note: Note,
    change_ephemeral_sk: Field,
) -> pub (Field, Field, Field, [Field; 7], Field) {
    let (nullifier_hash, old_commitment) = verify_spend(
        old_note,
        old_shared_secret,
        old_note_index,
        current_timestamp,
        hashlock_preimage,
    );

    let computed_root = lean_imt_inclusion_proof(old_commitment, old_note_index, old_note_path);
    assert(computed_root == merkle_root);

    assert(old_note.value == withdraw_value + change_note.value);
    assert(old_note.asset_id == change_note.asset_id);

    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    let encrypted = encrypt_note_for_compliance(change_note, change_ephemeral_sk, compliance_pk);

    (nullifier_hash, encrypted.epk_x, encrypted.epk_y, encrypted.ciphertext, old_note.asset_id)
}

#[test]
fn test_withdraw_compile_check() {
    let withdraw_value: u128 = 40;
    let recipient = 0x1234567890123456789012345678901234567890;
    let merkle_root = 0x2b007edcbc06d28d57c351697d325087133d5a0aa0971c8384fa03c6a93b4a0a;
    let current_timestamp = 0;
    let intent_hash = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let old_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000064,
        nullifier: 0x00000000000000000000000000000000000000000000000000000000000000c8,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let old_shared_secret = 0x19712b8cf8a75a1bffabfc0c83238c273079cfe5fa59d693955977b5049d049b;
    let old_note_index = 0;
    let old_note_path = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
    ];
    let hashlock_preimage = 0;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000190,
        nullifier: 0x000000000000000000000000000000000000000000000000000000000000012c,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00c08605661c1ef6bad34085c2356c82102e5e46ecabebaa3939190f4e68b268;

    let exp_nf = 0x1330149830bb507a82c893814415ac88d36a2f8263dffffdb1956b3635a04fae;
    let exp_ct = [
        0x00f35ac9ea5690a6549faf5529fa73942349ab475d50507a9b2e84ebcc11816c,
        0x0009e10ba6dc87e2b2394bdd24698da85f9b1166e342902abd4a01286b1cc08a,
        0x00ca11082dc494e0aa40a9cdb3755fc203f76755249959b75b659a63b8a6ef09,
        0x002dc2e03bd67963bd86c0b12f3de7265d818573ca117b196ed7b897a8d79a66,
        0x003e9c2a5f6a91b7b6fa879f50e6f61eeed08c1c18bdb5570ffe2f36cfc3bebd,
        0x0006c91994b1a9ffa92d8708bc9fec47a986c3788eda4d55dd5d1f5144f2d5b9,
        0x00000000000000000000bbc66f344115611e559b010d78fc89ba2c0aedf19114,
    ];

    let (nf, _, _, ct, _) = main(
        withdraw_value,
        recipient,
        merkle_root,
        current_timestamp,
        intent_hash,
        compliance_pubkey_x,
        compliance_pubkey_y,
        old_note,
        old_shared_secret,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        change_note,
        change_ephemeral_sk,
    );

    assert(nf == exp_nf);
    assert(ct == exp_ct);
}
