use ::ecdh::{bjj::BJJ, ECDHTrait, Point};
use ::shared::{
    DLEQProof, encrypt_note, kdf_to_aes_key_iv, lean_imt_inclusion_proof, Note, pack_ciphertext,
    TREE_DEPTH, verify_dleq, verify_spend,
};
use edwards::{bjj::BabyJubJub, CurveTrait, ScalarField};

fn main(
    merkle_root: pub Field,
    current_timestamp: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    recipient_B: pub Point,
    recipient_P: pub Point,
    recipient_proof: DLEQProof,
    old_note: Note,
    old_shared_secret: Field,
    old_note_index: Field,
    old_note_path: [Field; TREE_DEPTH],
    hashlock_preimage: Field,
    memo_note: Note,
    memo_ephemeral_sk: Field,
    change_note: Note,
    change_ephemeral_sk: Field,
) -> pub (Field, Field, Field, [Field; 7], Point, Point, Field, Field, [Field; 7]) {
    let compliance_pk_temp = BabyJubJub::new(compliance_pubkey_x, compliance_pubkey_y);
    let recipient_B_temp = BabyJubJub::new(recipient_B.x, recipient_B.y);
    let recipient_P_temp = BabyJubJub::new(recipient_P.x, recipient_P.y);
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };

    verify_dleq(recipient_B_temp, compliance_pk_temp, recipient_P_temp, recipient_proof);

    assert(memo_ephemeral_sk != 0);
    assert(change_ephemeral_sk != 0);

    let (nullifier_hash, old_commitment) = verify_spend(
        old_note,
        old_shared_secret,
        old_note_index,
        current_timestamp,
        hashlock_preimage,
    );

    let computed_root = lean_imt_inclusion_proof(old_commitment, old_note_index, old_note_path);
    assert(computed_root == merkle_root);

    assert(old_note.value == memo_note.value + change_note.value);
    assert(old_note.asset_id == memo_note.asset_id);
    assert(old_note.asset_id == change_note.asset_id);

    let memo_scalar: ScalarField<64> = ScalarField::from(memo_ephemeral_sk);
    let S_point = recipient_P_temp.mul(memo_scalar);
    let (memo_key, memo_iv) = kdf_to_aes_key_iv(S_point.x);
    let memo_bytes = memo_note.serialize();
    let memo_ct = encrypt_note(memo_bytes, memo_iv, memo_key);
    let memo_packed = pack_ciphertext(memo_ct);
    let memo_epk = BJJ::new(memo_ephemeral_sk).derive_public_key();

    let int_bob_point = compliance_pk_temp.mul(memo_scalar);
    let int_bob = Point { x: int_bob_point.x, y: int_bob_point.y };

    let int_carol_point = recipient_B_temp.mul(memo_scalar);
    let int_carol = Point { x: int_carol_point.x, y: int_carol_point.y };

    let change_bjj = BJJ::new(change_ephemeral_sk);
    let change_epk = change_bjj.derive_public_key();
    let change_ss = change_bjj.derive_shared_key(compliance_pk);
    let (c_key, c_iv) = kdf_to_aes_key_iv(change_ss);
    let c_bytes = change_note.serialize();
    let c_ct = encrypt_note(c_bytes, c_iv, c_key);
    let c_packed = pack_ciphertext(c_ct);

    (
        nullifier_hash, memo_epk.x, memo_epk.y, memo_packed, int_bob, int_carol, change_epk.x,
        change_epk.y, c_packed,
    )
}

#[test]
fn test_transfer_compile_check() {
    let merkle_root = 0x2b007edcbc06d28d57c351697d325087133d5a0aa0971c8384fa03c6a93b4a0a;
    let current_timestamp = 0;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let recipient_B = Point {
        x: 0x0cf064598cbf9e0f91228a743567873ef0f2001edabb432b546f6ffa0a25afe5,
        y: 0x1209bec18717eb6499e330d9196458e04b91f995e16d76f2e4c322705c77242f,
    };
    let recipient_P = Point {
        x: 0x0464508630b85bedcc795e1f2f26a5fbd9c36b074cbbb0946c182f608ec975ab,
        y: 0x2d3d62b4b8421137315a7903873c39feba45e5520d585d43136d5f249588cff4,
    };
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x01ca63455d07899e43bdcd4abf36013172312c1b690c9a8a3f1b6242271a0150,
            y: 0x0ed865f3b0b8c53064058bb57420f5d98cbbd57fdcbd6c921e39b3e17572c832,
        },
        V: BabyJubJub {
            x: 0x17228803115038cdc19db7a91e3788e690774a8f57414206aafe2dcd609d272e,
            y: 0x2e7797d18f2966122424b83b6641f6a48007e18f5ddfa803747479ab057145f0,
        },
        z: 0x01da3994cac4354303f5c5333714983541ffa9863dfac26573738e13520daa38,
    };

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        nullifier: 0x0000000000000000000000000000000000000000000000000000000000000000,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        nullifier: 0x0000000000000000000000000000000000000000000000000000000000000190,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x0430b6a4988e13cb97ca501b50d78271c6f95bdcfa08d105f90bde66c1895467;

    let exp_nf = 0x1330149830bb507a82c893814415ac88d36a2f8263dffffdb1956b3635a04fae;
    let exp_m_ct = [
        0x009485dd78b67d09184e4c66cef16719ae98d0d1dce6d3dc0946ae4100c4e88b,
        0x002fa7932c3fea571011250345d30b53b59c6264c1631db4abdf10c311d01a75,
        0x00fbf65123d5eee1a233b88fd0dfe8c7165d02ded92699e7ded878b15ad0e8f4,
        0x0014288fb4f8159ccf29464362d7bd19ade4cfbe66eb2b0f2627bc7be9fa1fec,
        0x009ec600b2b03527b3402fbfc820363435d3804d24b6170c530b9908099a16a9,
        0x0069abc5f0c180fd67792f5d46b1c7de07c30e032194145d0e597d5de1a4993b,
        0x000000000000000000003e4c74a86915df0ca0c1d10960eb0f948712d8eb983a,
    ];
    let exp_ib = Point {
        x: 0x0e94d7f61c674a233b14b9b972d8fe81f5c14f1ef33e2568a2cb20be47ce2991,
        y: 0x13456c335391debe79e3b321a83523673e7e0f50ce7d19a8622a5efc91b034a9,
    };
    let exp_ic = Point {
        x: 0x198b0aedd4e9ad14380fd38f41fa622284755c3aa4b35234b9cf4cc54fb4c6ec,
        y: 0x2c75d4fd414aec4ae5f7539f156aa0f566888b5c6ebbc4c291e6ce04b0fa8d70,
    };

    let (nf, _, _, m_ct, ib, ic, _, _, _) = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        recipient_B,
        recipient_P,
        recipient_proof,
        old_note,
        old_shared_secret,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        memo_note,
        memo_ephemeral_sk,
        change_note,
        change_ephemeral_sk,
    );

    assert(nf == exp_nf);
    assert(m_ct == exp_m_ct);
    assert(ib == exp_ib);
    assert(ic == exp_ic);
}
