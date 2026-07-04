//! Differential-soundness harness for the spend primitives: each `audit_*` case takes a valid witness,
//! mutates ONE load-bearing input, and asserts the constraint system rejects it. Covers the shared
//! `verify_spend` / `verify_spend_binding` / `verify_dleq` layer; the mains carry the value-conservation
//! and merkle-binding negatives.

use crate::{DLEQProof, Note, SUBORDER, verify_dleq, verify_spend, verify_spend_binding};
use edwards::{bjj::BabyJubJub, CurveTrait};

// owner == Poseidon2(VALID_NK * Base8); reused across the withdraw/split/join test vectors.
global VALID_OWNER: Field = 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27;
global VALID_NK: Field = 0x1c8;
// A note's ECDH-to-compliance secret. Decryption power; must NOT grant spend authority.
global KNOWN_SHARED_SECRET: Field =
    0x1e3528427cde3826c2a9317e33b6bab18af005e3c17ad06f588fcf9379a6d109;

fn valid_note() -> Note {
    Note {
        asset_id: 0x1234567890123456789012345678901234567890,
        value: 100,
        secret: 0x64,
        owner: VALID_OWNER,
        timelock: 0,
        hashlock: 0,
    }
}

#[test]
fn test_harness_valid_spend_accepts() {
    let _ = verify_spend(valid_note(), KNOWN_SHARED_SECRET, VALID_NK, 0, 0, 0);
}

// Holding the ECDH shared_secret (decryption power) does not confer spend authority: ownership binds to
// nk via owner == Poseidon2(nk*Base8), so a decryptor lacking nk cannot spend.
#[test(should_fail_with = "spender does not own this note")]
fn audit_decrypt_without_nk_cannot_spend() {
    let _ = verify_spend(valid_note(), KNOWN_SHARED_SECRET, 0x2a, 0, 0, 0);
}

#[test(should_fail_with = "spender does not own this note")]
fn audit_mutated_owner_rejected() {
    let mut note = valid_note();
    note.owner = 0xdeadbeef;
    let _ = verify_spend(note, KNOWN_SHARED_SECRET, VALID_NK, 0, 0, 0);
}

fn valid_recipient_b() -> BabyJubJub {
    BabyJubJub::new(
        0x0cf064598cbf9e0f91228a743567873ef0f2001edabb432b546f6ffa0a25afe5,
        0x1209bec18717eb6499e330d9196458e04b91f995e16d76f2e4c322705c77242f,
    )
}

fn valid_recipient_s() -> BabyJubJub {
    BabyJubJub::new(
        0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    )
}

fn valid_bind_r() -> BabyJubJub {
    BabyJubJub::new(
        0x09dbdcd7d2f82bdddc16c4c9584959e728cfb25af5a7bdd34b47024dc860e03b,
        0x2d581991fae71f7965a585e267b2fba577aeedaf82aeafaa4346051f2818189a,
    )
}

global VALID_BIND_S: Field = 0x00c19c4ad9b681323f7c7499e66cad7cf387dd060d89a990cd7338b4bfdaa760;

#[test]
fn test_harness_valid_binding_accepts() {
    verify_spend_binding(
        valid_recipient_b(),
        valid_recipient_s(),
        valid_bind_r(),
        VALID_BIND_S,
    );
}

#[test(should_fail_with = "spend binding invalid")]
fn audit_forged_binding_scalar_rejected() {
    verify_spend_binding(
        valid_recipient_b(),
        valid_recipient_s(),
        valid_bind_r(),
        VALID_BIND_S + 1,
    );
}

// Substituting a different spend pubkey S while keeping the signature: the challenge e = H(R,B,S)
// changes, so s*Base8 != R + e*B. This stops a sender pairing the recipient's B with an attacker-chosen S.
#[test(should_fail_with = "spend binding invalid")]
fn audit_binding_substituted_s_rejected() {
    verify_spend_binding(
        valid_recipient_b(),
        valid_recipient_b(),
        valid_bind_r(),
        VALID_BIND_S,
    );
}

fn dleq_b() -> BabyJubJub {
    BabyJubJub::new(
        0x0cf064598cbf9e0f91228a743567873ef0f2001edabb432b546f6ffa0a25afe5,
        0x1209bec18717eb6499e330d9196458e04b91f995e16d76f2e4c322705c77242f,
    )
}

fn dleq_c() -> BabyJubJub {
    BabyJubJub::new(
        0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
        0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
    )
}

fn dleq_p() -> BabyJubJub {
    BabyJubJub::new(
        0x0464508630b85bedcc795e1f2f26a5fbd9c36b074cbbb0946c182f608ec975ab,
        0x2d3d62b4b8421137315a7903873c39feba45e5520d585d43136d5f249588cff4,
    )
}

fn valid_dleq_proof() -> DLEQProof {
    DLEQProof {
        U: BabyJubJub::new(
            0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        ),
        V: BabyJubJub::new(
            0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        ),
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    }
}

#[test]
fn test_harness_valid_dleq_accepts() {
    verify_dleq(dleq_b(), dleq_c(), dleq_p(), valid_dleq_proof());
}

#[test(should_fail)]
fn audit_dleq_bad_response_rejected() {
    let mut proof = valid_dleq_proof();
    proof.z += 1;
    verify_dleq(dleq_b(), dleq_c(), dleq_p(), proof);
}

// z + SUBORDER shares the response's discrete-log yet is a non-canonical scalar; assert_subgroup_scalar(z)
// must reject it, matching the circuit's canonical-scalar contract.
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn audit_dleq_noncanonical_response_rejected() {
    let mut proof = valid_dleq_proof();
    proof.z = proof.z + SUBORDER;
    verify_dleq(dleq_b(), dleq_c(), dleq_p(), proof);
}

// A note under an unexpired timelock cannot be spent before its unlock time.
#[test(should_fail)]
fn audit_timelock_not_expired_rejected() {
    let mut note = valid_note();
    note.timelock = 1000;
    let _ = verify_spend(note, KNOWN_SHARED_SECRET, VALID_NK, 0, 0, 0);
}

// A hashlocked note cannot be spent without a preimage that hashes to the lock.
#[test(should_fail)]
fn audit_hashlock_wrong_preimage_rejected() {
    let mut note = valid_note();
    note.hashlock = 0x123;
    let _ = verify_spend(note, KNOWN_SHARED_SECRET, VALID_NK, 0, 0, 0);
}

// asset_id must fit 20 bytes; an oversized value is rejected so notes stay fungible with clean tokens.
#[test(should_fail)]
fn audit_oversized_asset_id_rejected() {
    let mut note = valid_note();
    note.asset_id = 0x010000000000000000000000000000000000000000;
    let _ = verify_spend(note, KNOWN_SHARED_SECRET, VALID_NK, 0, 0, 0);
}
