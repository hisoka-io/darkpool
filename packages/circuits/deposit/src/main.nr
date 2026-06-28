use ::ecdh::Point;
use ::shared::{encrypt_note_for_compliance, Note};

fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    note_plaintext: Note,
    ephemeral_sk: Field,
) -> pub (Field, Field, Field, Field, [Field; 7]) {
    let _: [u8; 20] = note_plaintext.asset_id.to_be_bytes();

    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    let encrypted = encrypt_note_for_compliance(note_plaintext, ephemeral_sk, compliance_pk);

    (
        encrypted.epk_x, encrypted.epk_y, note_plaintext.value as Field, note_plaintext.asset_id,
        encrypted.ciphertext,
    )
}

#[test]
fn test_deposit_compile_check() {
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let note_plaintext = Note {
        asset_id: 0x0000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf1270,
        value: 100,
        secret: 0x000000000000000000000000000000000000000000000000000000000000007b,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let ephemeral_sk = 0x0178e49f6c3773df9ae9f433b0cdabc9473c85156d10d8017ad0cdbb6b27aae0;

    let exp_epk_x = 0x03cd3c013a82b3e9a5e460e7eedd6594365577b3e68803bf77642ee29bb6aaa1;
    let exp_epk_y = 0x157fea669cb4e5f724d8722bab1c14d709de22ceb136f511919b8ec8c5b868cf;
    let exp_ct = [
        0x00a1c5a084acf0b2e26482562982f71a1f667126aa0cdb52a3b8a892ee4545ef,
        0x00b70c58836e817de954b7150fa6513354d5a2c3b1625154659dd61d7c68c883,
        0x007c7b240dc5610519f96d3a11c7f36be54d767c21f87bfc48b8844ea7ec42a6,
        0x005be05492bb08891f33e559fbcb87ea2be82d7b1eb7594cb8c6ebfd0398eb9a,
        0x00666b4537ecf60310c2a84cfce9327b96b616c964015e8e42131521b027c5f1,
        0x00f3fdcb556420f34f2c8fb6ed026ca73c5167dc478acb890a41feb0f5efa6a6,
        0x000000000000000000003ebc0d93f1910b1703f31b332f31aba20a816671da8f,
    ];

    let (epk_x, epk_y, val, _, packed_ct) = main(
        compliance_pubkey_x,
        compliance_pubkey_y,
        note_plaintext,
        ephemeral_sk,
    );

    assert(epk_x == exp_epk_x);
    assert(epk_y == exp_epk_y);
    assert(val == note_plaintext.value as Field);
    assert(packed_ct == exp_ct);
}
