use crate::assert_subgroup_scalar;
use ecdh::{bjj::BJJ, ECDHTrait};
use edwards::{bjj::BabyJubJub, CurveTrait, ScalarField};
use poseidon::poseidon2::Poseidon2;

pub fn verify_spend_binding(
    recipient_B: BabyJubJub,
    recipient_S: BabyJubJub,
    bind_R: BabyJubJub,
    bind_s: Field,
) {
    assert_subgroup_scalar(bind_s);
    let e = Poseidon2::hash(
        [bind_R.x, bind_R.y, recipient_B.x, recipient_B.y, recipient_S.x, recipient_S.y],
        6,
    );
    let e_scalar: ScalarField<64> = ScalarField::from(e);
    let lhs = BJJ::new(bind_s).derive_public_key();
    let rhs = bind_R + recipient_B.mul(e_scalar);
    assert(lhs.x == rhs.x, "spend binding invalid");
    assert(lhs.y == rhs.y, "spend binding invalid");
}

// No standard spend path uses this yet; kept live by these vectors so a soundness regression cannot land
// silently.
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
fn test_valid_binding_accepts() {
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

// Substituting S while keeping the signature changes e = H(R,B,S), so s*Base8 != R + e*B: stops a sender
// pairing the recipient's B with an attacker-chosen S.
#[test(should_fail_with = "spend binding invalid")]
fn audit_binding_substituted_s_rejected() {
    verify_spend_binding(
        valid_recipient_b(),
        valid_recipient_b(),
        valid_bind_r(),
        VALID_BIND_S,
    );
}
