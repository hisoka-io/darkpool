use ::ecdh::{bjj::BJJ, ECDHTrait, Point};
use ::shared::{
    encrypt_note, kdf_to_aes_key_iv, lean_imt_inclusion_proof, Note, pack_ciphertext, TREE_DEPTH,
    verify_spend,
};

fn main(
    merkle_root: pub Field,
    current_timestamp: pub Field,
    payment_value: pub u128,
    payment_asset_id: pub Field,
    _relayer_address: pub Field,
    _execution_hash: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    old_note: Note,
    old_shared_secret: Field,
    old_note_index: Field,
    old_note_path: [Field; TREE_DEPTH],
    hashlock_preimage: Field,
    change_note: Note,
    change_ephemeral_sk: Field,
) -> pub (Field, Field, Field, [Field; 7]) {
    let (nullifier_hash, old_commitment) = verify_spend(
        old_note,
        old_shared_secret,
        old_note_index,
        current_timestamp,
        hashlock_preimage,
    );

    let computed_root = lean_imt_inclusion_proof(old_commitment, old_note_index, old_note_path);
    assert(computed_root == merkle_root);

    assert(old_note.asset_id == payment_asset_id);
    assert(change_note.asset_id == payment_asset_id);
    assert(old_note.value == payment_value + change_note.value);

    assert(change_ephemeral_sk != 0, "ephemeral secret key cannot be zero");
    let change_ephemeral_pk = BJJ::new(change_ephemeral_sk).derive_public_key();
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    let change_shared_ss = BJJ::new(change_ephemeral_sk).derive_shared_key(compliance_pk);
    let (change_key, change_iv) = kdf_to_aes_key_iv(change_shared_ss);

    let change_plaintext_bytes = change_note.serialize();
    let change_ciphertext = encrypt_note(change_plaintext_bytes, change_iv, change_key);
    let change_packed_ct = pack_ciphertext(change_ciphertext);

    (nullifier_hash, change_ephemeral_pk.x, change_ephemeral_pk.y, change_packed_ct)
}

#[test]
fn test_gas_payment_compile() {
    let merkle_root = 0x0ff0308384a3c8925230730c05830475189887fb31eda2d5f9b41508b7457289;
    let current_timestamp = 0;
    let payment_value: u128 = 10;
    let payment_asset_id = 0x0000000000000000000000001234567890123456789012345678901234567890;
    let relayer_address = 0x0000000000000000000000001111222233334444555566667777888899990000;
    let execution_hash = 0x000000000000000000000000000000000000000000000000abcdef1234567890;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let old_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x000000000000000000000000000000000000000000000000000000000000007b,
        nullifier: 0x00000000000000000000000000000000000000000000000000000000000001c8,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let old_shared_secret = 0x2d304122ed971f99abcbe36e64fbcd0e770267ad7005912908d66ee8089ccdbd;
    let old_note_index = 0;
    let old_note_path = [
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
    ];
    let hashlock_preimage = 0;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 90,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000315,
        nullifier: 0x00000000000000000000000000000000000000000000000000000000000003f3,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x009e0df938f67eb7d4f4fa0f9c25ed14e2b6e0712d086fb6c8d330ab44e25cf3;

    let exp_nullifier_hash = 0x2b5e2e032c8c028717d5c04dbc403bad8e40126798465625f58460fcd3e9d418;
    let exp_change_epk_x = 0x2ee2ede1573fde24114afe66be1f17ab11c778b6a9745613c8bda41d2494a8ed;
    let exp_change_epk_y = 0x080e4cc68fd214da6254485d6c92b95531db466075319cd462b2ce48ae6332d2;
    let exp_change_ct = [
        0x00cd76999e3e2db795e69d9e8fbac02e29ea4f70056d1929b8f3be78b897d762,
        0x0042d2b46d4e6327cbf4afb5dc0191e563651ab20039d4835384888cd5e61eb2,
        0x000c8ab774e94151c9a8e63c1d1d95216c9efa9ea31445b6c0e67db709349a6a,
        0x00cc881126418daf4a12c9d922f110c00d04f8148c009e4639cad6c5490fd06a,
        0x0048eecbc76d4f1c3b45f5243707134db33dc37a33c5ba16986a9d114d4bc113,
        0x00b0404a2a91308b5091428577ee6b5ed4758e1b69f98381518a43eb9c56a27c,
        0x0000000000000000000089061237adec51ccf1e8a477fcf0487db97c8dabd241,
    ];

    let (nf, epk_x, epk_y, ct) = main(
        merkle_root,
        current_timestamp,
        payment_value,
        payment_asset_id,
        relayer_address,
        execution_hash,
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

    assert(nf == exp_nullifier_hash);
    assert(epk_x == exp_change_epk_x);
    assert(epk_y == exp_change_epk_y);
    assert(ct == exp_change_ct);
}

#[test(should_fail_with = "ephemeral secret key cannot be zero")]
fn test_gas_payment_zero_ephemeral_sk() {
    let merkle_root = 0x0ff0308384a3c8925230730c05830475189887fb31eda2d5f9b41508b7457289;
    let current_timestamp = 0;
    let payment_value: u128 = 10;
    let payment_asset_id = 0x0000000000000000000000001234567890123456789012345678901234567890;
    let relayer_address = 0x0000000000000000000000001111222233334444555566667777888899990000;
    let execution_hash = 0x000000000000000000000000000000000000000000000000abcdef1234567890;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let old_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x000000000000000000000000000000000000000000000000000000000000007b,
        nullifier: 0x00000000000000000000000000000000000000000000000000000000000001c8,
        timelock: 0,
        hashlock: 0,
    };
    let old_shared_secret = 0x2d304122ed971f99abcbe36e64fbcd0e770267ad7005912908d66ee8089ccdbd;
    let old_note_index = 0;
    let old_note_path = [0; 32];
    let hashlock_preimage = 0;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 90,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000315,
        nullifier: 0x00000000000000000000000000000000000000000000000000000000000003f3,
        timelock: 0,
        hashlock: 0,
    };

    // zero sk  should fail
    let change_ephemeral_sk = 0;

    let _ = main(
        merkle_root,
        current_timestamp,
        payment_value,
        payment_asset_id,
        relayer_address,
        execution_hash,
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
}
