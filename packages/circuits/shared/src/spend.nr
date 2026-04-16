use crate::{ciphertext_commitment, encrypt_note, kdf_to_aes_key_iv, Note, pack_ciphertext};
use poseidon::poseidon2::Poseidon2;

pub fn verify_spend(
    note: Note,
    shared_secret: Field,
    note_index: Field,
    current_timestamp: Field,
    hashlock_preimage: Field,
) -> (Field, Field) {
    let (key, iv) = kdf_to_aes_key_iv(shared_secret);
    let plaintext = note.serialize();
    let ciphertext = encrypt_note(plaintext, iv, key);
    let packed = pack_ciphertext(ciphertext);
    let commitment = ciphertext_commitment(packed);

    if note.timelock != 0 {
        assert(current_timestamp as u64 >= note.timelock as u64);
    }

    if note.hashlock != 0 {
        let derived_hash = Poseidon2::hash([hashlock_preimage], 1);
        assert(derived_hash == note.hashlock);
    }

    let nullifier = if note.nullifier == 0 {
        Poseidon2::hash([shared_secret, commitment, note_index], 3)
    } else {
        Poseidon2::hash([note.nullifier], 1)
    };

    (nullifier, commitment)
}
