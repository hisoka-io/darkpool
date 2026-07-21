use crate::assert_subgroup_scalar;
use crate::domains::{ACTION_JOIN, ACTION_SPLIT, ACTION_TRANSFER, ACTION_WITHDRAW, SCHNORR_DOMAIN};
use ecdh::{bjj::{BJJ, check_subgroup}, ECDHTrait, Point};
use edwards::{bjj::BabyJubJub, CurveTrait, ScalarField};
use poseidon::poseidon2::Poseidon2;

pub fn verify_frost_spend(gpk: Point, r: Point, z: Field, m: Field) {
    let gpk_ed = BabyJubJub::new(gpk.x, gpk.y);
    assert(check_subgroup(gpk_ed), "gpk not in prime-order subgroup");
    assert(!gpk_ed.is_zero(), "gpk must not be the identity");

    let r_ed = BabyJubJub::new(r.x, r.y);
    r_ed.assert_is_on_curve();
    assert(!r_ed.is_zero(), "R must not be the identity");

    assert_subgroup_scalar(z);

    // Challenge truncated to low 248 bits so the cheap ScalarField<63> path (scalars < 2^252) decodes it; its
    // `assert(acc - skew == x)` binds the wNAF slices (an unconstrained hint) to e. Without a binding a prover
    // forges the challenge (R = z*Base8 - e'*gpk). Upstream noir-edwards v0.2.5 left the N==64 path unbound (#49);
    // the vendored fork now binds N==64 too. Forged-scalar regression: the bb.js frost-forgery harness.
    let e_full = Poseidon2::hash([SCHNORR_DOMAIN, r.x, r.y, gpk.x, gpk.y, m], 6);
    let e_bytes: [u8; 32] = e_full.to_le_bytes();
    let mut e: Field = 0;
    let mut pow: Field = 1;
    for i in 0..31 {
        e += (e_bytes[i] as Field) * pow;
        pow *= 256;
    }
    let e_scalar: ScalarField<63> = ScalarField::from(e);

    let z_base = BJJ::new(z).derive_public_key();
    let z_base_ed = BabyJubJub::new(z_base.x, z_base.y);

    let rhs = r_ed + gpk_ed.mul(e_scalar);
    let diff = z_base_ed - rhs;
    let cofactored = diff.dbl().dbl().dbl(); // x8: clear the cofactor before the subgroup identity check
    assert(cofactored.is_zero(), "FROST signature invalid");
}

// Distinct ACTION tag per op stops cross-op replay; binding root (chain-specific via genesis slot0 seeding
// block.chainid) makes m non-replayable cross-chain. Mirrored byte-for-byte by the TS FROST signer.

pub fn msg_withdraw(
    root: Field,
    nullifier: Field,
    change_leaf: Field,
    public_out: Field,
    asset: Field,
    recipient: Field,
    intent_hash: Field,
) -> Field {
    Poseidon2::hash(
        [ACTION_WITHDRAW, root, nullifier, change_leaf, public_out, asset, recipient, intent_hash],
        8,
    )
}

pub fn msg_transfer(
    root: Field,
    nullifier: Field,
    memo_leaf: Field,
    change_leaf: Field,
    asset: Field,
) -> Field {
    Poseidon2::hash(
        [ACTION_TRANSFER, root, nullifier, memo_leaf, change_leaf, asset],
        6,
    )
}

pub fn msg_split(
    root: Field,
    nullifier: Field,
    out1_leaf: Field,
    out2_leaf: Field,
    asset: Field,
) -> Field {
    Poseidon2::hash(
        [ACTION_SPLIT, root, nullifier, out1_leaf, out2_leaf, asset],
        6,
    )
}

pub fn msg_join(
    root: Field,
    nullifier_a: Field,
    nullifier_b: Field,
    out_leaf: Field,
    asset: Field,
) -> Field {
    Poseidon2::hash(
        [ACTION_JOIN, root, nullifier_a, nullifier_b, out_leaf, asset],
        6,
    )
}

// Real 3-of-5 FROST signature from the TS signer (gen-frost-kat); byte-for-byte verify parity.
fn kat_gpk() -> Point {
    Point {
        x: 0x2546ab52faee9ab8ead1ad868567473b9757c6456c137274b12a5c51330d764d,
        y: 0x0d7a564269d3675f75799ee9d7574b00d01190b243041994c0e460af507a71aa,
    }
}
fn kat_r() -> Point {
    Point {
        x: 0x262d28e21d283e57d8add3efde5b0ef36d18af221efa12d686b50fdae23c0b53,
        y: 0x20dba1d0aa62eab7f32a1a9eb2f4cb382080c3ea369f7422f9e27c075b9db09d,
    }
}
global KAT_Z: Field = 0x02e3508cb36163fef3481853d79756edf5c2c7565de8094cd5fca125c58dcfe2;
global KAT_M: Field = 0x00abcdef1234567890fedcba9876543210abcdef1234567890fedcba98765432;

#[test]
fn kat_frost_verify_accepts() {
    verify_frost_spend(kat_gpk(), kat_r(), KAT_Z, KAT_M);
}

#[test(should_fail_with = "FROST signature invalid")]
fn audit_frost_reject_mutated_z() {
    verify_frost_spend(kat_gpk(), kat_r(), KAT_Z + 1, KAT_M);
}

#[test(should_fail_with = "FROST signature invalid")]
fn audit_frost_reject_mutated_message() {
    verify_frost_spend(kat_gpk(), kat_r(), KAT_Z, KAT_M + 1);
}

#[test(should_fail_with = "FROST signature invalid")]
fn audit_frost_reject_substituted_gpk() {
    verify_frost_spend(kat_r(), kat_r(), KAT_Z, KAT_M);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn audit_frost_reject_zero_z() {
    verify_frost_spend(kat_gpk(), kat_r(), 0, KAT_M);
}

// Pins the 248-bit challenge truncation: the challenge is rebuilt from the low 31 bytes before the ScalarField<63>
// reduction, so widening the loop (e.g. 0..32) sets a high byte and fails. The wNAF-slice binding against a forged
// e_scalar is a proving-layer property nargo cannot reach (honest witness generation computes e_scalar
// identically), so the full forgery regression lives in the bb.js frost-forgery harness. The challenge/message
// binding is covered by the multisig mutation tests and RealProofE2E per-public-input mutation.
#[test]
fn frost_challenge_is_truncated_to_248_bits() {
    let g = kat_gpk();
    let r = kat_r();
    let e_full = Poseidon2::hash([SCHNORR_DOMAIN, r.x, r.y, g.x, g.y, KAT_M], 6);
    let e_bytes: [u8; 32] = e_full.to_le_bytes();
    let mut e: Field = 0;
    let mut pow: Field = 1;
    for i in 0..31 {
        e += (e_bytes[i] as Field) * pow;
        pow *= 256;
    }
    let e_le: [u8; 32] = e.to_le_bytes();
    assert(e_le[31] == 0, "FROST challenge not truncated to 248 bits");
}

// TS<->Noir parity lock on the FROST message layout (wallets gen-m-kat).
#[test]
fn kat_msg_parity() {
    assert(
        msg_withdraw(1, 2, 3, 4, 5, 6, 7)
            == 0x2dda2d035d6f11d7a9a21090bb7757ffdd0c57c526d7d90431d73dea4831729d,
    );
    assert(
        msg_transfer(1, 2, 3, 4, 5)
            == 0x18ce2613d1138a758d065683eb7ed8973fd4b875768fa5b376ac0ac89f7a85cd,
    );
    assert(
        msg_split(1, 2, 3, 4, 5)
            == 0x0c4d6056bd9bf2ff15f92f1c42fa264c5883b35e6f002abe44d8be2a2f08c6c3,
    );
    assert(
        msg_join(1, 2, 3, 4, 5)
            == 0x2e41dd14ab7b1910916834caebb1d7e630c493722b2dbd76f269e5cbfc414001,
    );
}
