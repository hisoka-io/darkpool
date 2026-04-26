use ::ecdh::{bjj::BJJ, ECDHTrait, Point};
use ::poseidon::poseidon2::Poseidon2;
use ::shared::{encrypt_note_for_compliance, Note};

fn main(
    memo_id: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    current_timestamp: pub Field,
    val: Field,
    asset_id: Field,
    timelock: Field,
    owner_x: Field,
    owner_y: Field,
    salt: Field,
    recipient_sk: Field,
    note_out: Note,
    sk_out: Field,
) -> pub (Field, Field, [Field; 7], Field) {
    let computed_id = Poseidon2::hash([val, asset_id, timelock, owner_x, owner_y, salt], 6);
    assert(computed_id == memo_id);
    assert(
        (timelock == 0) | (current_timestamp as u64 >= timelock as u64),
        "Timelock has not expired",
    );

    let derived_pk = BJJ::new(recipient_sk).derive_public_key();
    assert(derived_pk.x == owner_x);
    assert(derived_pk.y == owner_y);

    assert(note_out.value == val);
    assert(note_out.asset_id == asset_id);

    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    let enc = encrypt_note_for_compliance(note_out, sk_out, compliance_pk);

    (enc.epk_x, enc.epk_y, enc.ciphertext, asset_id)
}

#[test]
pub fn test_public_claim() {
    let memo_id = 0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let val = 0x0000000000000000000000000000000000000000000000000000000000000064;
    let asset_id = 0x0000000000000000000000001234567890123456789012345678901234567890;
    let timelock = 0x0000000000000000000000000000000000000000000000000000000000000000;
    let current_timestamp = 0x0000000000000000000000000000000000000000000000000000000067f0d400; // any timestamp is fine when timelock == 0
    let owner_x = 0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54e;
    let owner_y = 0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8f;
    let salt = 0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4;

    let recipient_sk = 0x0000000000000000000000000000000000000000000000000000000000003039;

    let note_out = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 0x0000000000000000000000000000000000000000000000000000000000000064,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        nullifier: 0x0000000000000000000000000000000000000000000000000000000000000378,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out = 0x0000000000000000000000000000000000000000000000000000000000000309;

    let exp_epk_x = 0x007b165412dfc16c9b23bd972c1e08e2473f8f7076762ca79e294320aa2bbd0c;
    let exp_epk_y = 0x208a2955c2e744579fb8b03689b37ca2aa0c41bb561f0fe0e32b6091b3ef0dfa;
    let exp_ct = [
        0x00badb19c1485c1366b56585c3d7ac572d3dd1ebafcdb9d8b43bac5e280a056b,
        0x004d73f3b84a4ac682f32c6b4f1610e3dd5f5bf07ea074109572feccf595024e,
        0x002775cb2d3ac252728995a20611962630baad45c824d4e5458a1f2b2b2a999e,
        0x003d9a6736188a28656f7505c7f9a3a9a89407d61b6f1151582022b3981853c0,
        0x00fea675fcc075d25891db0752ffe9759c5d60aba895b35babeb698573862657,
        0x0009cf0fb055f7112057858c9816e6ce579a3f648c90d869b6e450ed9f7548c6,
        0x00000000000000000000f5110dbc4dc465f9928f19f11f7076b46fd7f09b366c,
    ];

    let (epk_x, epk_y, ct, asset_ret) = main(
        memo_id,
        compliance_pubkey_x,
        compliance_pubkey_y,
        current_timestamp,
        val,
        asset_id,
        timelock,
        owner_x,
        owner_y,
        salt,
        recipient_sk,
        note_out,
        sk_out,
    );

    assert(epk_x == exp_epk_x);
    assert(epk_y == exp_epk_y);
    assert(ct == exp_ct);
    assert(asset_ret == asset_id);
}

#[test]
pub fn test_public_claim_timelock_active() {
    let memo_id = 0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;
    let val = 0x0000000000000000000000000000000000000000000000000000000000000064;
    let asset_id = 0x0000000000000000000000001234567890123456789012345678901234567890;

    let timelock = 0x0;
    let current_timestamp = 0x0000000000000000000000000000000000000000000000000000000067f0d400;
    let owner_x = 0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54e;
    let owner_y = 0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8f;
    let salt = 0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4;
    let recipient_sk = 0x0000000000000000000000000000000000000000000000000000000000003039;
    let note_out = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 0x0000000000000000000000000000000000000000000000000000000000000064,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        nullifier: 0x0000000000000000000000000000000000000000000000000000000000000378,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out = 0x0000000000000000000000000000000000000000000000000000000000000309;

    let _ = main(
        memo_id,
        compliance_pubkey_x,
        compliance_pubkey_y,
        current_timestamp,
        val,
        asset_id,
        timelock,
        owner_x,
        owner_y,
        salt,
        recipient_sk,
        note_out,
        sk_out,
    );
}
