// The vendored sponge seeds its capacity element with `message_size * 2^64` (vendor/poseidon/src/poseidon2.nr,
// `hash_internal`), matching barretenberg's `FieldSponge::hash_internal` and the Solidity `LibPoseidon2Yul`. That
// length IV is what keeps hashes of different arities apart: without it `hash([a, b], 2)` and `hash([a, b, 0], 3)`
// enter the permutation as the same state. The Merkle path argument relies on it to keep an 8-input leaf, a 2-input
// genesis leaf and a 3-input node from standing in for one another.
use crate::common::dem::dem_keystream;
use crate::common::domains::{ENC_DOMAIN, PSI_DOMAIN};
use crate::common::note::Note;
use crate::common::note_nullifier::{nullifier, psi};
use crate::common::owner::pubkey_owner;
use crate::lean_imt_inclusion_proof;
use ecdh::Point;
use edwards::CurveTrait;
use poseidon::poseidon2::Poseidon2;
use std::hash::poseidon2_permutation;

global TWO_POW_64: Field = 18446744073709551616;

fn length_iv(len: Field) -> Field {
    len * TWO_POW_64
}

fn sponge_1(m: Field) -> Field {
    poseidon2_permutation([m, 0, 0, length_iv(1)])[0]
}

fn sponge_2(m: [Field; 2]) -> Field {
    poseidon2_permutation([m[0], m[1], 0, length_iv(2)])[0]
}

fn sponge_3(m: [Field; 3]) -> Field {
    poseidon2_permutation([m[0], m[1], m[2], length_iv(3)])[0]
}

fn sponge_8(m: [Field; 8]) -> Field {
    let mut s = poseidon2_permutation([m[0], m[1], m[2], length_iv(8)]);
    s[0] += m[3];
    s[1] += m[4];
    s[2] += m[5];
    s = poseidon2_permutation(s);
    s[0] += m[6];
    s[1] += m[7];
    poseidon2_permutation(s)[0]
}

fn assert_capacity_is_length_iv() {
    let a = 0x0c0ffee;
    let b = 0x2a5de47ed300af27b706aaa14762fc468f5cfc16cd8116eb6b09b0f2643ca2b9;
    let m8 = [a, b, 3, 4, 5, 6, 7, 0];
    assert(Poseidon2::hash([a], 1) == sponge_1(a), "1-input capacity is not 1 * 2^64");
    assert(Poseidon2::hash([a, b], 2) == sponge_2([a, b]), "2-input capacity is not 2 * 2^64");
    assert(
        Poseidon2::hash([a, b, 0], 3) == sponge_3([a, b, 0]),
        "3-input capacity is not 3 * 2^64",
    );
    assert(Poseidon2::hash(m8, 8) == sponge_8(m8), "8-input capacity is not 8 * 2^64");
}

#[test]
fn capacity_is_length_iv_constrained() {
    assert_capacity_is_length_iv();
}

#[test]
unconstrained fn capacity_is_length_iv_unconstrained() {
    assert_capacity_is_length_iv();
}

#[test]
fn trailing_zeros_do_not_alias_a_shorter_message() {
    let a = 0x0c0ffee;
    let b = 0x2a5de47ed300af27b706aaa14762fc468f5cfc16cd8116eb6b09b0f2643ca2b9;
    let h1 = Poseidon2::hash([a], 1);
    let h2 = Poseidon2::hash([a, b], 2);
    let h2_padded = Poseidon2::hash([a, 0], 2);
    let h3 = Poseidon2::hash([a, b, 0], 3);
    let h8 = Poseidon2::hash([a, b, 0, 0, 0, 0, 0, 0], 8);
    assert(h1 != h2_padded);
    assert(h2 != h3);
    assert(h2 != h8);
    assert(h3 != h8);
    assert(poseidon2_permutation([a, b, 0, 0])[0] != h2);
    assert(poseidon2_permutation([a, b, 0, 0])[0] != h3);
}

// The IV follows `message_size`, not the array length, so every call site must pass the two equal.
#[test]
fn message_size_sets_the_iv_and_drops_the_tail() {
    let a = 0x0c0ffee;
    let b = 0x2a5de47ed300af27b706aaa14762fc468f5cfc16cd8116eb6b09b0f2643ca2b9;
    assert(Poseidon2::hash([a, b, 9], 2) == Poseidon2::hash([a, b], 2));
    assert(Poseidon2::hash([a, b, 0], 2) != Poseidon2::hash([a, b, 0], 3));
}

#[test]
fn protocol_hashes_absorb_their_own_length() {
    let cek = 0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bda;
    let note_psi = psi(cek);
    assert(note_psi == sponge_2([cek, PSI_DOMAIN]));
    assert(nullifier(note_psi, 3) == sponge_2([note_psi, 3]));
    assert(dem_keystream(cek, 4) == sponge_3([cek, ENC_DOMAIN, 4]));

    let pk = Point::new(
        0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    );
    assert(pubkey_owner(pk) == sponge_2([pk.x, pk.y]));

    let note = Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 100,
        owner: pubkey_owner(pk),
        psi: note_psi,
        parents: 0,
    };
    let leaf = note.leaf();
    assert(
        leaf
            == sponge_8([
                note.note_version,
                note.asset_id,
                note.note_type,
                note.conditions_hash,
                note.value as Field,
                note.owner,
                note.psi,
                note.parents,
            ]),
    );

    let sibling = 0x0738cba9a9f3e94b55b9a591c0f0dbd3567358ec0c204e21f565c9d3a744fc3c;
    assert(lean_imt_inclusion_proof(leaf, 0, [sibling]) == sponge_3([leaf, sibling, 0]));
    assert(lean_imt_inclusion_proof(leaf, 1, [sibling]) == sponge_3([sibling, leaf, 0]));
    let one_up = lean_imt_inclusion_proof(leaf, 2, [0, sibling]);
    assert(one_up == sponge_3([sibling, leaf, 1]));
}

// Byte-identical to wallets/src/__tests__/Poseidon2Arity.test.ts.
#[test]
fn kat_arity_vectors() {
    assert(
        Poseidon2::hash([1], 1)
            == 0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373,
    );
    assert(
        Poseidon2::hash([1, 2], 2)
            == 0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383,
    );
    assert(
        Poseidon2::hash([1, 2, 0], 3)
            == 0x14e2032f272084a8bcdf0b4af5042a5f11ed8c734d21e906a81adde7da3a9dcd,
    );
    assert(
        Poseidon2::hash([1, 2, 0, 0, 0, 0, 0, 0], 8)
            == 0x16baf281357237ed43d8d518ce9266e45a7f77fe0fcda9de69bbdcc3701090dc,
    );
    assert(
        Poseidon2::hash([1, 2, 3, 4, 5, 6, 7, 8], 8)
            == 0x01dec21c6e1b30609eda618d7e35e5d9d6152f8fa67320d939c1a89603647142,
    );
    assert(
        poseidon2_permutation([1, 2, 0, 0])[0]
            == 0x299bfccd7daf3c917e51291383929049ec0eaed800af245056cbf135f7dea636,
    );
}
