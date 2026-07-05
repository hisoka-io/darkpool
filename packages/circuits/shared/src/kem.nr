use crate::assert_subgroup_scalar;
use ecdh::{bjj::BJJ, ECDHTrait, Point};
use edwards::CurveTrait;
use poseidon::poseidon2::Poseidon2;

// CEK = (eph * C).x, the compliance-shared content-encryption key.
pub fn derive_cek(eph: Field, compliance_pk: Point) -> Field {
    assert_subgroup_scalar(eph);
    BJJ::new(eph).derive_shared_key(compliance_pk)
}

// Incoming memo wrap: cek_wrap = cek + Poseidon2((eph*in_pub).x), mod p; unwrap subtracts the same pad.
pub fn wrap_cek(cek: Field, eph: Field, in_pub: Point) -> Field {
    assert_subgroup_scalar(eph);
    let pad = BJJ::new(eph).derive_shared_key(in_pub);
    cek + Poseidon2::hash([pad], 1)
}

// ECDH symmetry: (in_key*eph_pub).x == (eph*in_pub).x, so the recipient recovers wrap_cek's pad from
// in_key + on-chain eph_pub without eph.
pub fn unwrap_cek(cek_wrap: Field, in_key: Field, eph_pub: Point) -> Field {
    assert_subgroup_scalar(in_key);
    let pad = BJJ::new(in_key).derive_shared_key(eph_pub);
    cek_wrap - Poseidon2::hash([pad], 1)
}

// KAT: byte-identical to the TS mirror (packages/wallets/src/crypto/kem.ts) over the shared fixture
// (eph=456, in_key=789, compliance C). A drift here breaks note decryption across languages.
#[test]
fn kat_kem_roundtrip() {
    let compliance_pk = Point::new(
        0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
        0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
    );
    let in_pub = Point::new(
        0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    );
    let eph_pub = Point::new(
        0x06263d32df3940b1135a6a6b85bd84ea1dc0e4746a15a5d204efffec30a18010,
        0x13fdbd796de262a086329a56d29f53f98f8c9e52b16939652d27eeb9646efdd1,
    );
    let eph: Field = 456;
    let in_key: Field = 789;

    let cek = derive_cek(eph, compliance_pk);
    assert(cek == 0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bda);

    let sender_pad = BJJ::new(eph).derive_shared_key(in_pub);
    let recipient_pad = BJJ::new(in_key).derive_shared_key(eph_pub);
    assert(sender_pad == recipient_pad);
    assert(sender_pad == 0x028539d0d004555c2229a892bad5421c69d21fea344acc2a92c966ac29f70042);

    let wrapped = wrap_cek(cek, eph, in_pub);
    assert(wrapped == 0x182d1d3732b40259bccbc18575d03e2689a7e570137cde69e637355645707bd8);

    let recovered = unwrap_cek(wrapped, in_key, eph_pub);
    assert(recovered == cek);
}
