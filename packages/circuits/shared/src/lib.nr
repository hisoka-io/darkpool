mod dleq;
mod spend;
mod spend_binding;
mod harness;
use ecdh::{bjj::BJJ, ECDHTrait, Point};
use poseidon::poseidon2::Poseidon2;
use std;
pub use dleq::{DLEQProof, verify_dleq};
pub use spend::verify_spend;
pub use spend_binding::verify_spend_binding;

pub global TREE_DEPTH: u32 = 32;
pub global CIPHERTEXT_FIELDS: u32 = 7;

// label "hisoka.enc_key"
pub global KEY_PURPOSE: Field = 0x0281a8425bea84c419aa615997d24dd06616356a715c72dc95be25985fd32e8d;
// "hisoka.enc_iv"
pub global IV_PURPOSE: Field = 0x240f81dbabe617f804ce036eb97fb79d25005a52b2128ac6364b872889b4a48f;

// Domain-separation tag for the DLEQ challenge (keccak256("hisoka.dleq.v1") % BN254_Fr); prevents
// cross-protocol replay of a compliance DLEQ proof.
pub global DLEQ_DOMAIN: Field = 0x1570eff8f2295a2eb1f2cf6cea827909fd713f0446dcbd7f1647496d89273366;

// BabyJubJub prime-order subgroup order.
// https://docs.iden3.io/publications/pdfs/Baby-Jubjub.pdf
pub global SUBORDER: Field =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;

// Canonical subgroup scalar: non-zero and < SUBORDER. A BJJ scalar witness flows into a point (e.g.
// owner = nk*B8) but nk also seeds the nullifier hash; without this, nk and nk+SUBORDER share the point
// yet differ as a Poseidon preimage -> distinct nullifiers for one note (aliasing double-spend).
pub fn assert_subgroup_scalar(x: Field) {
    assert(x != 0, "scalar must be non-zero");
    assert(x.lt(SUBORDER), "scalar not in BabyJubJub prime-order subgroup");
}

pub struct EncryptedNote {
    pub epk_x: Field,
    pub epk_y: Field,
    pub ciphertext: [Field; CIPHERTEXT_FIELDS],
}

pub fn encrypt_note_for_compliance(
    note: Note,
    ephemeral_sk: Field,
    compliance_pk: Point,
) -> EncryptedNote {
    assert_subgroup_scalar(ephemeral_sk);

    let epk = BJJ::new(ephemeral_sk).derive_public_key();
    let shared_secret = BJJ::new(ephemeral_sk).derive_shared_key(compliance_pk);
    let (key, iv) = kdf_to_aes_key_iv(shared_secret);
    let plaintext = note.serialize();
    let ciphertext = encrypt_note(plaintext, iv, key);
    let packed = pack_ciphertext(ciphertext);

    EncryptedNote { epk_x: epk.x, epk_y: epk.y, ciphertext: packed }
}

pub struct Note {
    pub asset_id: Field,
    pub value: u128,
    pub secret: Field,
    pub owner: Field,
    pub timelock: Field,
    pub hashlock: Field,
}

impl Note {
    pub fn serialize(self) -> [u8; 192] {
        let mut bytes: [u8; 192] = [0; 192];

        let f0 = self.asset_id.to_be_bytes::<32>();
        let f1 = (self.value as Field).to_be_bytes::<32>();
        let f2 = self.secret.to_be_bytes::<32>();
        let f3 = self.owner.to_be_bytes::<32>();
        let f4 = self.timelock.to_be_bytes::<32>();
        let f5 = self.hashlock.to_be_bytes::<32>();

        for i in 0..32 {
            bytes[i] = f0[i];
            bytes[32 + i] = f1[i];
            bytes[64 + i] = f2[i];
            bytes[96 + i] = f3[i];
            bytes[128 + i] = f4[i];
            bytes[160 + i] = f5[i];
        }
        bytes
    }
}

pub fn kdf_to_aes_key_iv(shared_ss: Field) -> ([u8; 16], [u8; 16]) {
    let key_fr = Poseidon2::hash([shared_ss, KEY_PURPOSE], 2);
    let iv_fr = Poseidon2::hash([shared_ss, IV_PURPOSE], 2);
    let key_bytes: [u8; 32] = key_fr.to_be_bytes();
    let iv_bytes: [u8; 32] = iv_fr.to_be_bytes();
    let mut key = [0; 16];
    let mut iv = [0; 16];
    for i in 0..16 {
        key[i] = key_bytes[i + 16];
        iv[i] = iv_bytes[i + 16];
    }
    (key, iv)
}

pub fn encrypt_note(plaintext: [u8; 192], iv: [u8; 16], key: [u8; 16]) -> [u8; 208] {
    std::aes128::aes128_encrypt(plaintext, iv, key)
}

pub fn ciphertext_commitment(packed_ct: [Field; CIPHERTEXT_FIELDS]) -> Field {
    Poseidon2::hash(
        [
            packed_ct[0],
            packed_ct[1],
            packed_ct[2],
            packed_ct[3],
            packed_ct[4],
            packed_ct[5],
            packed_ct[6],
        ],
        CIPHERTEXT_FIELDS,
    )
}

pub fn pack_ciphertext(ct: [u8; 208]) -> [Field; CIPHERTEXT_FIELDS] {
    let mut packed: [Field; CIPHERTEXT_FIELDS] = [0; CIPHERTEXT_FIELDS];
    let mut idx = 0;
    for p in 0..CIPHERTEXT_FIELDS {
        let mut val: Field = 0;
        let bytes_in_this = if p < 6 { 31 } else { 22 };
        let mut power: Field = 1;
        for _ in 0..bytes_in_this {
            val += (ct[idx] as Field) * power;
            power *= 256;
            idx += 1;
        }
        packed[p] = val;
    }
    packed
}

pub fn lean_imt_inclusion_proof<let MAX_DEPTH: u32>(
    leaf: Field,
    leaf_index: Field,
    siblings: [Field; MAX_DEPTH],
) -> Field {
    let path_bits: [u1; MAX_DEPTH] = leaf_index.to_le_bits();
    let mut current = leaf;

    for i in 0..MAX_DEPTH {
        let sibling = siblings[i];
        if sibling != 0 {
            let path_bit = path_bits[i] as Field;
            let left = current + path_bit * (sibling - current);
            let right = sibling + path_bit * (current - sibling);
            current = Poseidon2::hash([left, right], 2);
        } else {
            // A leaf cannot be the right child of an absent left sibling, so the
            // index bit at every empty level must be 0. Without this the bits above
            // the populated height are free, yielding many valid indices for one leaf.
            assert(path_bits[i] == 0, "non-canonical leaf index: right child at empty level");
        }
    }
    current
}

#[test]
pub fn test_lean_imt_inclusion_proof() {
    let leaf: Field = (4 as u8).into();
    let leaf_index: Field = (3 as u8).into();
    let siblings: [Field; 8] = [
        3,
        0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
        0x232400b3cca0da78d26295f345d21e9bf8949238bee02b285140ebf183119982,
        0,
        0,
        0,
        0,
        0,
    ];
    let root = lean_imt_inclusion_proof(leaf, leaf_index, siblings);
    assert(root == 0x05d7e5aaddb74c086c24617065e8c97dea94b86fdae0eab7b498249e0dfee2a8);
}
