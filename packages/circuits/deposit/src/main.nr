use ::ecdh::Point;
use ::shared::{encrypt_note_for_compliance, Note};

fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    note_plaintext: Note,
    ephemeral_sk: Field,
) -> pub (Field, Field, Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    let encrypted = encrypt_note_for_compliance(note_plaintext, ephemeral_sk, compliance_pk);

    (
        encrypted.epk_x, encrypted.epk_y, note_plaintext.value, note_plaintext.asset_id,
        encrypted.ciphertext,
    )
}

#[test]
fn test_deposit_compile_check() {
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let note_plaintext = Note {
        asset_id: 0x0000000000000000000000000d500b1d8e8ef31e21c99d1db9a6444d3adf1270,
        value: 0x0000000000000000000000000000000000000000000000000000000000000064,
        secret: 0x000000000000000000000000000000000000000000000000000000000000007b,
        nullifier: 0x00000000000000000000000000000000000000000000000000000000000001c8,
        timelock: 0x0000000000000000000000000000000000000000000000000000000000000000,
        hashlock: 0x0000000000000000000000000000000000000000000000000000000000000000,
    };
    let ephemeral_sk = 0x03cf700a261c47a107a4c09e19d872edbb3fbb2cf49d5fd861550ee4b6fb476e;

    let exp_epk_x = 0x05aeddf5c49db2aa0a16ca23af6cc1c5f11faa4408177c276c042c7a917c9688;
    let exp_epk_y = 0x24fff8909e635b0fd91a935ef6dc0b0b91c283395fcc6c67d5e8bbad57166b6a;
    let exp_ct = [
        0x00c45e1a1b67b5fb3545c3328e77d83a0afff829713bd7d675a32857c48d3ad1,
        0x0086bcb787b6fc2a30a98a9ae9b12ada6e7106c4287549635f187a70d7d5a1bb,
        0x00242ff45c3b74efb8f8fc482e403f7430ab28e27adaa2ae8de35dc510eeac4c,
        0x002df0ebc2ea5a3e0775020598190bacae76a5d75ba04874d75c1a92844adf9a,
        0x008cf25bea8386af1c3c1db8888c48e6c15d7c123ba852692077fcdcb4b33e2b,
        0x00868afe85c908d27ecc257a9ed85a1b249b7b16d2d0d66c7aa3e598b2fd73bf,
        0x00000000000000000000f14176119f1657470cef170d7734e0693fa2f1310477,
    ];

    let (epk_x, epk_y, val, _, packed_ct) = main(
        compliance_pubkey_x,
        compliance_pubkey_y,
        note_plaintext,
        ephemeral_sk,
    );

    assert(epk_x == exp_epk_x);
    assert(epk_y == exp_epk_y);
    assert(val == note_plaintext.value);
    assert(packed_ct == exp_ct);
}
