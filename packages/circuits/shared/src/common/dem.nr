// Poseidon2 field-wise stream cipher. The field order k=0..6 and the encrypt-adds / decrypt-subtracts sign
// MUST match the TS mirror packages/wallets/src/crypto/dem.ts or notes are undecryptable.
use crate::domains::ENC_DOMAIN;
use poseidon::poseidon2::Poseidon2;

pub global DEM_FIELDS: u32 = 7;

pub fn dem_keystream(cek: Field, k: u32) -> Field {
    Poseidon2::hash([cek, ENC_DOMAIN, k as Field], 3)
}

pub fn dem_encrypt(cek: Field, plaintext: [Field; DEM_FIELDS]) -> [Field; DEM_FIELDS] {
    let mut ciphertext: [Field; DEM_FIELDS] = [0; DEM_FIELDS];
    for k in 0..DEM_FIELDS {
        ciphertext[k] = plaintext[k] + dem_keystream(cek, k);
    }
    ciphertext
}

pub fn dem_decrypt(cek: Field, ciphertext: [Field; DEM_FIELDS]) -> [Field; DEM_FIELDS] {
    let mut plaintext: [Field; DEM_FIELDS] = [0; DEM_FIELDS];
    for k in 0..DEM_FIELDS {
        plaintext[k] = ciphertext[k] - dem_keystream(cek, k);
    }
    plaintext
}

#[test]
fn dem_kat_encrypt_decrypt() {
    let cek: Field = 0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bda;
    let plaintext: [Field; DEM_FIELDS] = [
        1,
        0x1234567890123456789012345678901234567890,
        0,
        0,
        100,
        0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        0,
    ];
    let expected_ct: [Field; DEM_FIELDS] = [
        0x2731638e2a7a9820452856622ce83bb4ed875a995d5f28e09a9e2813d1472f67,
        0x17537f0cfa734af08271f104fe3a6b59c655a70ef150119205af625ab451b413,
        0x214d78fb170e5a1de97ded5727a834f29b94f4ed0d3ca29b36aa98b597051302,
        0x109dbab21c201fdac2cd7e0f59efdc423f18de696a918357c9fedea65869ff8e,
        0x2065a8ce6a9cdce89ca92cad5e9bc7a80f2413b893219f03e27365ebead75032,
        0x0124088cefa5b815b5213279cd8c7a7eef948183c37291e8740c9deccc202418,
        0x2971fe65daaac4e80629e73dfbd54bf6a38f9748d9728257ffefdc8b97686211,
    ];

    let ciphertext = dem_encrypt(cek, plaintext);
    for k in 0..DEM_FIELDS {
        assert(ciphertext[k] == expected_ct[k], "DEM ciphertext KAT mismatch");
    }

    let recovered = dem_decrypt(cek, ciphertext);
    for k in 0..DEM_FIELDS {
        assert(recovered[k] == plaintext[k], "DEM roundtrip mismatch");
    }
}

// A wrong CEK must not recover the plaintext: the subtracted keystream differs at every position.
#[test]
fn audit_dem_wrong_cek_garbles() {
    let ct: [Field; DEM_FIELDS] = [
        0x2731638e2a7a9820452856622ce83bb4ed875a995d5f28e09a9e2813d1472f67,
        0x17537f0cfa734af08271f104fe3a6b59c655a70ef150119205af625ab451b413,
        0x214d78fb170e5a1de97ded5727a834f29b94f4ed0d3ca29b36aa98b597051302,
        0x109dbab21c201fdac2cd7e0f59efdc423f18de696a918357c9fedea65869ff8e,
        0x2065a8ce6a9cdce89ca92cad5e9bc7a80f2413b893219f03e27365ebead75032,
        0x0124088cefa5b815b5213279cd8c7a7eef948183c37291e8740c9deccc202418,
        0x2971fe65daaac4e80629e73dfbd54bf6a38f9748d9728257ffefdc8b97686211,
    ];
    let cek: Field = 0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bda;
    let garbled = dem_decrypt(cek + 1, ct);
    assert(garbled[0] != 1, "a wrong CEK must not recover the plaintext");
}
