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
    nk: Field,
    old_note_index: Field,
    old_note_path: [Field; TREE_DEPTH],
    hashlock_preimage: Field,
    change_note: Note,
    change_ephemeral_sk: Field,
) -> pub (Field, Field, Field, [Field; 7], Field) {
    let (nullifier_hash, old_commitment) = verify_spend(
        old_note,
        old_shared_secret,
        nk,
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
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
    let current_timestamp = 0;
    let intent_hash = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let old_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000064,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let old_shared_secret = 0x1e3528427cde3826c2a9317e33b6bab18af005e3c17ad06f588fcf9379a6d109;
    let nk = 0x00000000000000000000000000000000000000000000000000000000000001c8;
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
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x039be029cb56876c17663612a723dfcb5cfffcb3f92bdc06331377df00d08be5;

    let exp_nf = 0x0e733fdbd526ed9faacdb6448985763d2281e5f829aedecdc234cddbb4b6b308;
    let exp_ct = [
        0x00aabdefe550527b6f7db57e3a1cd7292ab14a6240581423c4ba24eb4a49763a,
        0x00ecd83b8e477242b98dca0366107fd66801ca2dcfc90014d907df4d529d1ea1,
        0x0026f7f93a42f98ddac29592f47900f69693192e10373d08b7d830ec29b98008,
        0x000c10c18361b86b120780b1112399eec2f1229aba5706bacb296eb88368b2db,
        0x00c54b0b25304cd32df34b76b85cfbe9fd9f4e5cc87cddf7205a7035ef226766,
        0x00e7b9e91a0efa9e23afd3b5b955d03b2a264e05ff6f89dd47a42fc0f20e6234,
        0x00000000000000000000c4011f15160a694f92cb44db6300ceb53c3df73c91d3,
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
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        change_note,
        change_ephemeral_sk,
    );

    assert(nf == exp_nf);
    assert(ct == exp_ct);
}

#[test(should_fail_with = "non-canonical leaf index")]
fn audit_reject_noncanonical_index() {
    let withdraw_value: u128 = 40;
    let recipient = 0x1234567890123456789012345678901234567890;
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
    let current_timestamp = 0;
    let intent_hash = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let old_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000064,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let old_shared_secret = 0x1e3528427cde3826c2a9317e33b6bab18af005e3c17ad06f588fcf9379a6d109;
    let nk = 0x00000000000000000000000000000000000000000000000000000000000001c8;
    let old_note_index = 7;
    let old_note_path = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
    ];
    let hashlock_preimage = 0;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000190,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00c08605661c1ef6bad34085c2356c82102e5e46ecabebaa3939190f4e68b268;

    let _ = main(
        withdraw_value,
        recipient,
        merkle_root,
        current_timestamp,
        intent_hash,
        compliance_pubkey_x,
        compliance_pubkey_y,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        change_note,
        change_ephemeral_sk,
    );
}

// Knowing old_shared_secret (the ECDH secret) does not grant spend authority: only the holder
// of the recipient's nullifying key satisfies owner == Poseidon2(nk*B8).
#[test(should_fail_with = "spender does not own this note")]
fn audit_reject_sender_cannot_spend_received_note() {
    let withdraw_value: u128 = 40;
    let recipient = 0x1234567890123456789012345678901234567890;
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
    let current_timestamp = 0;
    let intent_hash = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    // owner = Poseidon2(789*B8) (recipient's spend key); the prover holds nk = 456 (sender).
    let old_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000064,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let old_shared_secret = 0x1e3528427cde3826c2a9317e33b6bab18af005e3c17ad06f588fcf9379a6d109;
    let nk = 0x00000000000000000000000000000000000000000000000000000000000001c8;
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
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x039be029cb56876c17663612a723dfcb5cfffcb3f92bdc06331377df00d08be5;

    let _ = main(
        withdraw_value,
        recipient,
        merkle_root,
        current_timestamp,
        intent_hash,
        compliance_pubkey_x,
        compliance_pubkey_y,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        change_note,
        change_ephemeral_sk,
    );
}
