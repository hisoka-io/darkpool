use crate::assert_subgroup_scalar;
use ecdh::{bjj::BJJ, ECDHTrait};
use edwards::{bjj::BabyJubJub, CurveTrait, ScalarField};
use poseidon::poseidon2::Poseidon2;

// Schnorr over BabyJubJub binding recipient_S (spend pubkey) to recipient_B (viewing key).
// e via ScalarField<64> (full field element); the mul wraps mod curve order == TS mod-suborder e.
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
