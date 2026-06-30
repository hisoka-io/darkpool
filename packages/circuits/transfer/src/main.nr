use ::ecdh::{bjj::{BJJ, check_subgroup}, ECDHTrait, Point};
use ::poseidon::poseidon2::Poseidon2;
use ::shared::{
    assert_subgroup_scalar, DLEQProof, encrypt_note, kdf_to_aes_key_iv, lean_imt_inclusion_proof,
    Note, pack_ciphertext, TREE_DEPTH, verify_dleq, verify_spend, verify_spend_binding,
};
use edwards::{bjj::BabyJubJub, CurveTrait, ScalarField};

fn main(
    merkle_root: pub Field,
    current_timestamp: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    // recipient_B/recipient_P/recipient_owner are PRIVATE: a passive observer must not link payments to a
    // recipient. Every constraint they feed (DLEQ ivk-relation, Schnorr spend-binding, owner == Poseidon2(S))
    // still runs in-circuit below, so privacy does not relax soundness.
    recipient_B: Point,
    recipient_P: Point,
    recipient_owner: Field,
    recipient_proof: DLEQProof,
    recipient_S: Point,
    bind_R: Point,
    bind_s: Field,
    old_note: Note,
    old_shared_secret: Field,
    nk: Field,
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
    let recipient_S_temp = BabyJubJub::new(recipient_S.x, recipient_S.y);
    let bind_R_temp = BabyJubJub::new(bind_R.x, bind_R.y);
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };

    assert(check_subgroup(compliance_pk_temp), "compliance key not in prime-order subgroup");
    assert(check_subgroup(recipient_B_temp), "recipient_B not in prime-order subgroup");
    assert(check_subgroup(recipient_P_temp), "recipient_P not in prime-order subgroup");
    assert(check_subgroup(recipient_S_temp), "recipient_S not in prime-order subgroup");
    assert(check_subgroup(bind_R_temp), "bind_R not in prime-order subgroup");
    assert(!compliance_pk_temp.is_zero(), "compliance key must not be the identity");
    assert(!recipient_B_temp.is_zero(), "recipient_B must not be the identity");
    assert(!recipient_P_temp.is_zero(), "recipient_P must not be the identity");
    assert(!recipient_S_temp.is_zero(), "recipient_S must not be the identity");

    verify_dleq(
        recipient_B_temp,
        compliance_pk_temp,
        recipient_P_temp,
        recipient_proof,
    );

    assert(
        Poseidon2::hash([recipient_S.x, recipient_S.y], 2) == recipient_owner,
        "recipient_S is not the recipient_owner preimage",
    );
    assert(memo_note.owner == recipient_owner, "memo note owner must equal recipient_owner");
    verify_spend_binding(recipient_B_temp, recipient_S_temp, bind_R_temp, bind_s);

    assert_subgroup_scalar(memo_ephemeral_sk);
    assert_subgroup_scalar(change_ephemeral_sk);

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

    assert(old_note.value == memo_note.value + change_note.value);
    assert(old_note.asset_id == memo_note.asset_id);
    assert(old_note.asset_id == change_note.asset_id);

    assert(memo_note.hashlock == 0, "memo note hashlock must be zero");
    assert(memo_note.timelock == 0, "memo note timelock must be zero");

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
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
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
    let recipient_owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: BabyJubJub {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };
    let recipient_S = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let bind_R = Point {
        x: 0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        y: 0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    };
    let bind_s = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa760;

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00b33e006176aadb2f6f57e502e1cda95491d8b362d0ac15fc7962cd7be32805;

    let exp_nf = 0x0e733fdbd526ed9faacdb6448985763d2281e5f829aedecdc234cddbb4b6b308;
    let exp_m_ct = [
        0x9485dd78b67d09184e4c66cef16719ae98d0d1dce6d3dc0946ae4100c4e88b,
        0x2fa7932c3fea571011250345d30b53b59c6264c1631db4abdf10c311d01a75,
        0xfbf65123d5eee1a233b88fd0dfe8c7165d02ded92699e7ded878b15ad0e8f4,
        0x72db0e5cc9f3578b4e8b4817d28eb5e1a6cb19b0f2182338b66d6243fa1fec,
        0xb664cd005bf778b544de266ba74d3838567101cb2e96b268d4c93dccf86300,
        0x8f95f987db9ed3a890046cff2d0b6dd3b70d09c25882be18fa311314f0d7d1,
        0xc77c13953b8d0fea9dea130e0f1d52232c13d5de67b6,
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
        recipient_owner,
        recipient_proof,
        recipient_S,
        bind_R,
        bind_s,
        old_note,
        old_shared_secret,
        nk,
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

#[test(should_fail_with = "memo note hashlock must be zero")]
fn audit_reject_memo_hashlock() {
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
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
    let recipient_owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: BabyJubJub {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };
    let recipient_S = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let bind_R = Point {
        x: 0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        y: 0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    };
    let bind_s = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa760;

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000001,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00b33e006176aadb2f6f57e502e1cda95491d8b362d0ac15fc7962cd7be32805;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        recipient_B,
        recipient_P,
        recipient_owner,
        recipient_proof,
        recipient_S,
        bind_R,
        bind_s,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        memo_note,
        memo_ephemeral_sk,
        change_note,
        change_ephemeral_sk,
    );
}

#[test(should_fail_with = "memo note timelock must be zero")]
fn audit_reject_memo_timelock() {
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
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
    let recipient_owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: BabyJubJub {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };
    let recipient_S = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let bind_R = Point {
        x: 0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        y: 0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    };
    let bind_s = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa760;

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000001,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00b33e006176aadb2f6f57e502e1cda95491d8b362d0ac15fc7962cd7be32805;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        recipient_B,
        recipient_P,
        recipient_owner,
        recipient_proof,
        recipient_S,
        bind_R,
        bind_s,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        memo_note,
        memo_ephemeral_sk,
        change_note,
        change_ephemeral_sk,
    );
}

#[test(should_fail_with = "recipient_B not in prime-order subgroup")]
fn audit_reject_recipient_b_low_order() {
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
    let current_timestamp = 0;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let recipient_B = Point {
        x: 0x0000000000000000000000000000000000000000000000000000000000000000,
        y: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000,
    };
    let recipient_P = Point {
        x: 0x0464508630b85bedcc795e1f2f26a5fbd9c36b074cbbb0946c182f608ec975ab,
        y: 0x2d3d62b4b8421137315a7903873c39feba45e5520d585d43136d5f249588cff4,
    };
    let recipient_owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: BabyJubJub {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };
    let recipient_S = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let bind_R = Point {
        x: 0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        y: 0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    };
    let bind_s = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa760;

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00b33e006176aadb2f6f57e502e1cda95491d8b362d0ac15fc7962cd7be32805;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        recipient_B,
        recipient_P,
        recipient_owner,
        recipient_proof,
        recipient_S,
        bind_R,
        bind_s,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        memo_note,
        memo_ephemeral_sk,
        change_note,
        change_ephemeral_sk,
    );
}

#[test(should_fail_with = "memo note owner must equal recipient_owner")]
fn audit_reject_memo_owner_mismatch() {
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
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
    let recipient_owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: BabyJubJub {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };
    let recipient_S = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let bind_R = Point {
        x: 0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        y: 0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    };
    let bind_s = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa760;

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        owner: 0x00000000000000000000000000000000000000000000000000000000deadbeef,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00b33e006176aadb2f6f57e502e1cda95491d8b362d0ac15fc7962cd7be32805;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        recipient_B,
        recipient_P,
        recipient_owner,
        recipient_proof,
        recipient_S,
        bind_R,
        bind_s,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        memo_note,
        memo_ephemeral_sk,
        change_note,
        change_ephemeral_sk,
    );
}

#[test(should_fail_with = "spend binding invalid")]
fn audit_reject_forged_spend_binding() {
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
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
    let recipient_owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: BabyJubJub {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };
    let recipient_S = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let bind_R = Point {
        x: 0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        y: 0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    };
    let bind_s = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa761;

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00b33e006176aadb2f6f57e502e1cda95491d8b362d0ac15fc7962cd7be32805;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        recipient_B,
        recipient_P,
        recipient_owner,
        recipient_proof,
        recipient_S,
        bind_R,
        bind_s,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        memo_note,
        memo_ephemeral_sk,
        change_note,
        change_ephemeral_sk,
    );
}

#[test(should_fail_with = "recipient_B must not be the identity")]
fn audit_reject_identity_recipient_b() {
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
    let current_timestamp = 0;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let recipient_B = Point { x: 0, y: 1 };
    let recipient_P = Point {
        x: 0x0464508630b85bedcc795e1f2f26a5fbd9c36b074cbbb0946c182f608ec975ab,
        y: 0x2d3d62b4b8421137315a7903873c39feba45e5520d585d43136d5f249588cff4,
    };
    let recipient_owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: BabyJubJub {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };
    let recipient_S = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let bind_R = Point {
        x: 0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        y: 0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    };
    let bind_s = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa760;

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00b33e006176aadb2f6f57e502e1cda95491d8b362d0ac15fc7962cd7be32805;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        recipient_B,
        recipient_P,
        recipient_owner,
        recipient_proof,
        recipient_S,
        bind_R,
        bind_s,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        memo_note,
        memo_ephemeral_sk,
        change_note,
        change_ephemeral_sk,
    );
}

#[test(should_fail_with = "recipient_S must not be the identity")]
fn audit_reject_identity_recipient_s() {
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
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
    let recipient_owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: BabyJubJub {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };
    let recipient_S = Point { x: 0, y: 1 };
    let bind_R = Point {
        x: 0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        y: 0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    };
    let bind_s = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa760;

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00b33e006176aadb2f6f57e502e1cda95491d8b362d0ac15fc7962cd7be32805;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        recipient_B,
        recipient_P,
        recipient_owner,
        recipient_proof,
        recipient_S,
        bind_R,
        bind_s,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        memo_note,
        memo_ephemeral_sk,
        change_note,
        change_ephemeral_sk,
    );
}

// Option-A load-bearing check: recipient_B is now a PRIVATE witness, but it is NOT prover-chosen-forgeable.
// Substituting a valid-but-wrong recipient_B (here recipient_P's point) breaks the DLEQ ivk-relation
// (log_{B8}(B) == log_C(P)), so the spend still fails.
#[test(should_fail)]
fn audit_reject_substituted_recipient_b() {
    let merkle_root = 0x05c1a73fa9dcd01b4cec5d9209592a5629421d0534d3f1decc791a463d969a77;
    let current_timestamp = 0;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    // substituted: a valid subgroup point (recipient_P's) that is NOT the bound recipient_B.
    let recipient_B = Point {
        x: 0x0464508630b85bedcc795e1f2f26a5fbd9c36b074cbbb0946c182f608ec975ab,
        y: 0x2d3d62b4b8421137315a7903873c39feba45e5520d585d43136d5f249588cff4,
    };
    let recipient_P = Point {
        x: 0x0464508630b85bedcc795e1f2f26a5fbd9c36b074cbbb0946c182f608ec975ab,
        y: 0x2d3d62b4b8421137315a7903873c39feba45e5520d585d43136d5f249588cff4,
    };
    let recipient_owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    let recipient_proof = DLEQProof {
        U: BabyJubJub {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: BabyJubJub {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };
    let recipient_S = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let bind_R = Point {
        x: 0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        y: 0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    };
    let bind_s = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa760;

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

    let memo_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x0000000000000000000000000000000000000000000000000000000000000000,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let memo_ephemeral_sk = 0x0000000000000000000000000000000000000000000000000000000000000378;

    let change_note = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x000000000000000000000000000000000000000000000000000000000000012c,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let change_ephemeral_sk = 0x00b33e006176aadb2f6f57e502e1cda95491d8b362d0ac15fc7962cd7be32805;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        recipient_B,
        recipient_P,
        recipient_owner,
        recipient_proof,
        recipient_S,
        bind_R,
        bind_s,
        old_note,
        old_shared_secret,
        nk,
        old_note_index,
        old_note_path,
        hashlock_preimage,
        memo_note,
        memo_ephemeral_sk,
        change_note,
        change_ephemeral_sk,
    );
}
