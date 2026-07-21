// FROST forged-scalar regression harness (TEST-ONLY; not a production circuit).
//
// WHAT IT PROVES. `verify_frost_spend` (circuits/shared/src/multisig/frost.nr:29) decodes the Schnorr
// challenge with `ScalarField<63>::from(e)`. The wNAF slices come from an UNCONSTRAINED hint, so a prover
// chooses them freely; the only thing forcing them to encode `e` is the width-63 binding
// `assert(acc - skew == x)`. If that binding is absent, a forger who knows no secret picks any `z` and any
// `e_forge`, sets `R = z*Base8 - e_forge*gpk`, and the verify equation `z*Base8 == R + e_forge*gpk` holds by
// construction: a signature forgery on any message, i.e. a drain of any multisig account.
//
// nargo's own FROST tests cannot reach this: they build the witness honestly, so the slices always encode `e`
// and the binding is never attacked. This harness attacks it.
//
// COPIED REGION + PROVENANCE. `check_binding` / `check_binding_ablated` reproduce the constrained region of
// `From<Field> for ScalarField<N>::from` (packages/circuits/vendor/noir-edwards/src/scalar_field.nr:87-142 at
// darkpool da11582), and the unconstrained hint helpers are copied from the same file. `check-byte-identity.sh`
// re-derives the vendored region and fails on any drift, so a future edit to the real `from` cannot silently
// desync this mirror (the prior edw-sf64 harness had no such guard).
//
// The two documented textual deviations from the vendored body:
//   1. the hint is a parameter instead of `unsafe { get_wnaf_slices(x) }` -- this IS the injection point;
//   2. the final 4-bit loop reads `slices[i]` instead of `result.base4_slices[i]` (identical values; this
//      crate cannot construct a `ScalarField`, whose fields are `pub(crate)` to edwards).
//
// FAITHFULNESS NOTE. Because `ScalarField`'s fields are `pub(crate)`, an external crate cannot hand forged
// slices to edwards' `mul`. So the production single call `from(e)`-with-a-malicious-hint is split here into
// its two effects: (a) the binding constraints run against `e` over the forged decomposition
// (`check_binding(wnaf(e_forge), e)`), and (b) `mul` consumes a scalar encoding `e_forge`
// (`ScalarField::from(e_forge)`). `get_wnaf_slices` is deterministic and both sides call it on the same input,
// so the array the binding is attacked with is bit-identical to the one `mul` consumes. The extra honest
// binding in (b) is satisfied in every variant and adds no reject path.
//
// A CONSEQUENCE, stated plainly: on the ACCEPT side the ablated-body call is causally inert -- deleting it
// would not change the outcome, because the forged slices reach `mul` through (b). So
// `ablated_binding_body_raises_no_objection_63` is NOT the differential. The differential is
// `forged_witness_passes_every_guard_except_the_binding`, which runs the forged witness through the entire
// relation with the binding absent and shows every other guard accepts it. Read the three together:
//   - the forged (R, z) is NOT a signature      -> control_forged_r_fails_under_the_honest_scalar
//   - every guard EXCEPT the binding accepts it -> forged_witness_passes_every_guard_except_the_binding
//   - the binding rejects it, at the binding    -> forgery_rejected_by_binding_63
// The group equation being satisfied by construction is not a defect of the rig: constructing R to satisfy it
// IS the attack. The security content is that nothing else objects.

use ecdh::{bjj::{BJJ, check_subgroup}, ECDHTrait, Point};
use edwards::{bjj::BabyJubJub, CurveTrait, ScalarField};
use poseidon::poseidon2::Poseidon2;

// keccak256("hisoka.frost.v1") % BN254_Fr -- circuits/shared/src/common/domains.nr
global SCHNORR_DOMAIN: Field = 0x2107179dff41b3dd7a3f1dafc51478ba9cf2daee14867e12f614e781f5aeba85;
// BabyJubJub prime-order subgroup order -- circuits/shared/src/lib.nr
global SUBORDER: Field = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

// copied from vendored scalar_field.nr
global TWO_POW_128: Field = 0x100000000000000000000000000000000;
global PLO: Field = 0x2833e84879b9709143e1f593f0000001;
global PHI: Field = 0x30644e72e131a029b85045b68181585d;

// unconstrained hint helpers, copied from vendored scalar_field.nr

unconstrained fn to_le_radix_16<let N: u32>(value: Field) -> [u8; N] {
    let bytes = value.to_le_bytes::<(N + 1) / 2>();
    let mut result: [u8; N] = [0; N];
    for index in 0..(N / 2) {
        result[index * 2] = bytes[index] & 0x0F;
        result[index * 2 + 1] = (bytes[index] >> 4);
    }
    if (N & 1) == 1 {
        let last_nibble = bytes[bytes.len() - 1];
        (last_nibble as Field).assert_max_bit_size::<4>();
        result[N - 1] = last_nibble;
    }
    result
}

unconstrained fn get_wnaf_slices<let N: u32>(x: Field) -> ([u8; N], bool) {
    let mut result: [u8; N] = [0; N];
    let mut nibbles: [u8; N] = to_le_radix_16(x);

    let skew: bool = nibbles[0] & 1 == 0;
    nibbles[0] += skew as u8;
    result[N - 1] = (nibbles[0] + 15) / 2;
    for i in 1..N {
        let mut nibble: u8 = nibbles[i];
        result[N - 1 - i] = (nibble + 15) / 2;
        if (nibble & 1 == 0) {
            result[N - 1 - i] += 1;
            result[N - i] -= 8;
        }
    }
    (result, skew)
}

unconstrained fn get_borrow_flag(lhs_lo: Field, rhs_lo: Field) -> bool {
    lhs_lo.lt(rhs_lo + 1)
}

// the constrained region of `from`, WITH the binding (production behaviour)

fn check_binding<let N: u32>(slices: [u8; N], skew: bool, x: Field) {
    if (N < 64) {
        let mut acc: Field = (slices[0] as Field) * 2 - 15;
        for i in 1..N {
            acc *= 16;
            acc += (slices[i] as Field) * 2 - 15;
        }
        assert(acc - skew as Field == x);
    } else {
        let mut lo: Field = 0;
        let mut hi: Field = 0;

        for i in 0..32 {
            lo *= 16;
            lo += (slices[32 + i] as Field) * 2 - 15;
            hi *= 16;
            hi += (slices[i] as Field) * 2 - 15;
        }

        lo -= skew as Field;

        // Safety: mirrors the vendored body; bound by the range constraints below.
        let is_positive: bool = unsafe { get_borrow_flag(lo, TWO_POW_128) };

        let abs_lo = (is_positive as Field) * lo + (1 - is_positive as Field) * (-lo);

        abs_lo.assert_max_bit_size::<128>();
        // Safety: mirrors the vendored body; bound by the range constraints below.
        let borrow = unsafe { get_borrow_flag(PLO, abs_lo) as Field };
        let rlo = is_positive as Field * (PLO - lo + borrow * TWO_POW_128 - 1)
            + (1 - is_positive as Field) * (-lo);
        // Safety: mirrors the vendored body; bound by the range constraint below.
        let threshold_flag: bool = unsafe { get_borrow_flag(abs_lo + PLO, TWO_POW_128) };
        (threshold_flag as Field * (abs_lo + PLO)).assert_max_bit_size::<128>();
        let rhi = is_positive as Field * (PHI - hi - borrow)
            + (1 - is_positive as Field) * (PHI - hi + threshold_flag as Field);
        rlo.assert_max_bit_size::<128>();
        rhi.assert_max_bit_size::<128>();

        assert(hi * TWO_POW_128 + lo == x);
    }
    for i in 0..N {
        (slices[i] as Field).assert_max_bit_size::<4>();
    }
}

// identical, with ONLY the two binding asserts removed (the ablation)

fn check_binding_ablated<let N: u32>(slices: [u8; N], skew: bool, x: Field) {
    if (N < 64) {
        let mut acc: Field = (slices[0] as Field) * 2 - 15;
        for i in 1..N {
            acc *= 16;
            acc += (slices[i] as Field) * 2 - 15;
        }
        assert(acc - acc == 0); // binding `assert(acc - skew as Field == x)` REMOVED
    } else {
        let mut lo: Field = 0;
        let mut hi: Field = 0;

        for i in 0..32 {
            lo *= 16;
            lo += (slices[32 + i] as Field) * 2 - 15;
            hi *= 16;
            hi += (slices[i] as Field) * 2 - 15;
        }

        lo -= skew as Field;

        // Safety: mirrors the vendored body; bound by the range constraints below.
        let is_positive: bool = unsafe { get_borrow_flag(lo, TWO_POW_128) };

        let abs_lo = (is_positive as Field) * lo + (1 - is_positive as Field) * (-lo);

        abs_lo.assert_max_bit_size::<128>();
        // Safety: mirrors the vendored body; bound by the range constraints below.
        let borrow = unsafe { get_borrow_flag(PLO, abs_lo) as Field };
        let rlo = is_positive as Field * (PLO - lo + borrow * TWO_POW_128 - 1)
            + (1 - is_positive as Field) * (-lo);
        // Safety: mirrors the vendored body; bound by the range constraint below.
        let threshold_flag: bool = unsafe { get_borrow_flag(abs_lo + PLO, TWO_POW_128) };
        (threshold_flag as Field * (abs_lo + PLO)).assert_max_bit_size::<128>();
        let rhi = is_positive as Field * (PHI - hi - borrow)
            + (1 - is_positive as Field) * (PHI - hi + threshold_flag as Field);
        rlo.assert_max_bit_size::<128>();
        rhi.assert_max_bit_size::<128>();

        // binding `assert(hi * TWO_POW_128 + lo == x)` REMOVED
        assert(x == x);
    }
    for i in 0..N {
        (slices[i] as Field).assert_max_bit_size::<4>();
    }
}

// the FROST relation (mirrors verify_frost_spend, scalar source parametrised)

fn assert_subgroup_scalar(x: Field) {
    assert(x != 0, "scalar must be non-zero");
    assert(x.lt(SUBORDER), "scalar not in BabyJubJub prime-order subgroup");
}

// frost.nr:21-28: challenge truncated to the low 248 bits.
fn challenge(r: Point, gpk: Point, m: Field) -> Field {
    let e_full = Poseidon2::hash([SCHNORR_DOMAIN, r.x, r.y, gpk.x, gpk.y, m], 6);
    let e_bytes: [u8; 32] = e_full.to_le_bytes();
    let mut e: Field = 0;
    let mut pow: Field = 1;
    for i in 0..31 {
        e += (e_bytes[i] as Field) * pow;
        pow *= 256;
    }
    e
}

// frost.nr:8-37 with the multiplied scalar supplied by the caller (production: the value the slices encode).
fn verify_group_equation(gpk: Point, r: Point, z: Field, mul_scalar: Field) {
    let gpk_ed = BabyJubJub::new(gpk.x, gpk.y);
    assert(check_subgroup(gpk_ed), "gpk not in prime-order subgroup");
    assert(!gpk_ed.is_zero(), "gpk must not be the identity");

    let r_ed = BabyJubJub::new(r.x, r.y);
    r_ed.assert_is_on_curve();
    assert(!r_ed.is_zero(), "R must not be the identity");

    assert_subgroup_scalar(z);

    let e_scalar: ScalarField<63> = ScalarField::from(mul_scalar);

    let z_base = BJJ::new(z).derive_public_key();
    let z_base_ed = BabyJubJub::new(z_base.x, z_base.y);

    let rhs = r_ed + gpk_ed.mul(e_scalar);
    let diff = z_base_ed - rhs;
    let cofactored = diff.dbl().dbl().dbl();
    assert(cofactored.is_zero(), "FROST signature invalid");
}

// The forgery: R = z*Base8 - e_forge*gpk. Needs no secret.
fn forge_r(gpk: Point, z: Field, e_forge: Field) -> Point {
    let gpk_ed = BabyJubJub::new(gpk.x, gpk.y);
    let z_base = BJJ::new(z).derive_public_key();
    let z_base_ed = BabyJubJub::new(z_base.x, z_base.y);
    let e_scalar: ScalarField<63> = ScalarField::from(e_forge);
    z_base_ed - gpk_ed.mul(e_scalar)
}

// fixtures: a real 3-of-5 FROST signature (frost.nr:98-111)

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

// An arbitrary attacker-chosen challenge, != the honest e for any R (it is fixed before R exists).
global E_FORGE: Field = 0x00deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe;

// CONTROL

// The rig accepts a genuine signature: honest hint (slices encode the true e) under the production binding.
#[test]
fn control_honest_kat_accepts_under_binding_63() {
    let e = challenge(kat_r(), kat_gpk(), KAT_M);
    // Safety: honest hint, bound by check_binding below.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(e) };
    check_binding::<63>(slices, skew, e);
    verify_group_equation(kat_gpk(), kat_r(), KAT_Z, e);
}

// The forged R is a REAL forgery: under the HONEST scalar it does not verify, so the forger holds no
// signature. Without this, "the forgery verifies" would be circular.
#[test(should_fail_with = "FROST signature invalid")]
fn control_forged_r_fails_under_the_honest_scalar() {
    let gpk = kat_gpk();
    let r = forge_r(gpk, KAT_Z, E_FORGE);
    let e = challenge(r, gpk, KAT_M);
    verify_group_equation(gpk, r, KAT_Z, e);
}

// REJECT (production)

// The forged decomposition is rejected by the width-63 binding: slices encode E_FORGE, the binding asserts
// they encode the honest e. This is the guard that stands between a forger and every multisig account.
#[test(should_fail)]
fn forgery_rejected_by_binding_63() {
    let gpk = kat_gpk();
    let r = forge_r(gpk, KAT_Z, E_FORGE);
    let e = challenge(r, gpk, KAT_M);
    // Safety: MALICIOUS hint -- slices encode E_FORGE, not e.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(E_FORGE) };
    check_binding::<63>(slices, skew, e);
    verify_group_equation(gpk, r, KAT_Z, E_FORGE);
}

// The vendored width-64 BINDING also rejects it: `assert(hi * TWO_POW_128 + lo == x)` (PR#53, vendored) binds
// mod p, so a forged e_forge != e is caught there too. Scope: this exercises the width-64 binding only; the
// relation itself always muls through ScalarField<63>, matching production.
#[test(should_fail)]
fn forgery_rejected_by_binding_64() {
    let gpk = kat_gpk();
    let r = forge_r(gpk, KAT_Z, E_FORGE);
    let e = challenge(r, gpk, KAT_M);
    // Safety: MALICIOUS hint.
    let (slices, skew): ([u8; 64], bool) = unsafe { get_wnaf_slices(E_FORGE) };
    check_binding::<64>(slices, skew, e);
    verify_group_equation(gpk, r, KAT_Z, E_FORGE);
}

// DIFFERENTIAL: nothing but the binding objects

// THE load-bearing differential. The forged witness is run through the ENTIRE relation with the binding
// simply not present -- every other guard still executes: check_subgroup, assert_is_on_curve, both identity
// checks, assert_subgroup_scalar(z), the honest binding of wnaf(E_FORGE) to E_FORGE, the 4-bit range loop and
// the cofactored group equation. It PASSES. Combined with `forgery_rejected_by_binding_63` (the binding
// rejects it, at the binding assert) and `control_forged_r_fails_under_the_honest_scalar` (the forged pair is
// not a signature), this is what establishes that the binding is the SOLE guard between a forger and a drain.
//
// The group equation here is satisfied by construction -- that IS the attack, the forger builds R to satisfy
// it. The evidential content is that no other constraint objects.
#[test]
fn forged_witness_passes_every_guard_except_the_binding() {
    let gpk = kat_gpk();
    let r = forge_r(gpk, KAT_Z, E_FORGE);
    verify_group_equation(gpk, r, KAT_Z, E_FORGE);
}

// The mirrored body with ONLY the binding asserts replaced by no-ops. NOTE: with the pub(crate) split this
// call is causally inert on the accept side (the forged slices reach `mul` via the honest
// `ScalarField::from(E_FORGE)` inside verify_group_equation, not through this call), so this test is NOT the
// differential -- `forged_witness_passes_every_guard_except_the_binding` above is. It is retained because it
// is the provable `main` shape and it pins that the ablated body itself introduces no new rejection.
#[test]
fn ablated_binding_body_raises_no_objection_63() {
    let gpk = kat_gpk();
    let r = forge_r(gpk, KAT_Z, E_FORGE);
    let e = challenge(r, gpk, KAT_M);
    // Safety: MALICIOUS hint.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(E_FORGE) };
    check_binding_ablated::<63>(slices, skew, e);
    verify_group_equation(gpk, r, KAT_Z, E_FORGE);
}

// NOT VACUOUS

// The ablated rig is not simply "accept everything": an honest signature still verifies through it.
#[test]
fn ablated_rig_still_accepts_the_honest_kat() {
    let e = challenge(kat_r(), kat_gpk(), KAT_M);
    // Safety: honest hint.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(e) };
    check_binding_ablated::<63>(slices, skew, e);
    verify_group_equation(kat_gpk(), kat_r(), KAT_Z, e);
}

// And the ablated rig still rejects a signature that is wrong for a reason OTHER than the binding, so the
// group equation is genuinely being enforced.
#[test(should_fail_with = "FROST signature invalid")]
fn ablated_rig_still_rejects_a_mutated_z() {
    let e = challenge(kat_r(), kat_gpk(), KAT_M);
    // Safety: honest hint.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(e) };
    check_binding_ablated::<63>(slices, skew, e);
    verify_group_equation(kat_gpk(), kat_r(), KAT_Z + 1, e);
}

// bb proving target

// The ABLATED forgery as a provable circuit: `nargo execute` + `bb prove` + `bb verify` on this must produce a
// VERIFYING proof, which is the gold-standard evidence that the forgery is real and not a test-interpreter
// artifact. The production (bound) variant is proven by rejection at execute time instead.
fn main(gpk_x: pub Field, gpk_y: pub Field, m: pub Field, z: Field, e_forge: Field) {
    let gpk = Point { x: gpk_x, y: gpk_y };
    let r = forge_r(gpk, z, e_forge);
    let e = challenge(r, gpk, m);
    // Safety: MALICIOUS hint -- the attacker-controlled decomposition.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(e_forge) };
    check_binding_ablated::<63>(slices, skew, e);
    verify_group_equation(gpk, r, z, e_forge);
}
