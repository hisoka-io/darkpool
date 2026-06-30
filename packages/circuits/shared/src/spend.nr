use crate::{
    assert_subgroup_scalar, ciphertext_commitment, encrypt_note, kdf_to_aes_key_iv, Note,
    pack_ciphertext, SUBORDER,
};
use ecdh::{bjj::BJJ, ECDHTrait};
use poseidon::poseidon2::Poseidon2;

pub fn verify_spend(
    note: Note,
    shared_secret: Field,
    nk: Field,
    note_index: Field,
    current_timestamp: Field,
    hashlock_preimage: Field,
) -> (Field, Field) {
    // nk seeds both the owner point and the nullifier preimage; it MUST be a canonical subgroup scalar,
    // else nk and nk+SUBORDER share the owner but yield different nullifiers (one note, many spends).
    assert_subgroup_scalar(nk);

    // asset_id is a 20-byte address; range-check it at the central spend consumer (conservation then
    // propagates the bound to every output note).
    let _: [u8; 20] = note.asset_id.to_be_bytes();

    let (key, iv) = kdf_to_aes_key_iv(shared_secret);
    let plaintext = note.serialize();
    let ciphertext = encrypt_note(plaintext, iv, key);
    let packed = pack_ciphertext(ciphertext);
    let commitment = ciphertext_commitment(packed);

    let pk = BJJ::new(nk).derive_public_key();
    assert(note.owner == Poseidon2::hash([pk.x, pk.y], 2), "spender does not own this note");

    if note.timelock != 0 {
        assert(current_timestamp as u64 >= note.timelock as u64);
    }

    if note.hashlock != 0 {
        let derived_hash = Poseidon2::hash([hashlock_preimage], 1);
        assert(derived_hash == note.hashlock);
    }

    let nullifier = Poseidon2::hash([nk, commitment, note_index], 3);

    (nullifier, commitment)
}

// nk_real + SUBORDER is < 2^252 (the old ScalarField<63> bound accepted it) yet shares nk_real's owner
// point while hashing to a DIFFERENT nullifier -> one note, many spends. The canonical range check now
// rejects the alias.
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn audit_nk_aliasing_double_spend() {
    let note =
        Note { asset_id: 0x1234, value: 100, secret: 0x64, owner: 0, timelock: 0, hashlock: 0 };
    let _ = verify_spend(note, 0, 5 + SUBORDER, 0, 0, 0);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn audit_nk_zero_rejected() {
    let note =
        Note { asset_id: 0x1234, value: 100, secret: 0x64, owner: 0, timelock: 0, hashlock: 0 };
    let _ = verify_spend(note, 0, 0, 0, 0, 0);
}
