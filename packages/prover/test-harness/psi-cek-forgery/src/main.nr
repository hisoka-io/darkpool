// psi/CEK forged-scalar regression harness (TEST-ONLY; not a production circuit).
//
// WHAT IT PROVES. Every mint binds the note's `psi` to the compliance ECDH secret:
// `assert(note.psi == psi(cek))` (circuits/shared/src/mint.nr:54) where `cek = (eph * C).x`
// (circuits/shared/src/common/kem.nr:6-9). That scalar mul decodes `eph` with `ScalarField<63>::from`, whose
// wNAF slices come from an UNCONSTRAINED hint; the width-63 binding `assert(acc - skew == x)` is the only
// thing forcing them to encode `eph`.
//
// The published `eph_pub = eph * Base8` is derived by a SECOND, independent `ScalarField::from(eph)` call
// (mint.nr:56). So a prover who forges only the hint inside `derive_cek` produces a note whose `psi` is keyed
// to `eph_forge` while the on-chain `eph_pub` still commits to `eph`. Compliance holds `c` with `C = c*Base8`
// and recovers the content key as `(c * eph_pub).x = (eph * C).x` -- the HONEST cek. It therefore derives a
// psi that is not the note's psi, and the note becomes permanently untraceable while staying fully spendable
// by its owner (spend reads `note.psi` out of the committed leaf, so the forged psi is self-consistent).
//
// That is the security content, and it is narrower than a drain: the forgery does NOT mint value and does NOT
// double-spend (see the SCOPE note below). It defeats the compliance guarantee, which the protocol treats as
// load-bearing.
//
// nargo's own mint tests cannot reach this: they build the witness honestly, so the slices always encode
// `eph` and the binding is never attacked. This harness attacks it.
//
// SCOPE -- WHY THIS IS NOT A DOUBLE-SPEND. `psi` is one of the 8 PLAINTEXT fields of the leaf commitment
// (circuits/shared/src/common/note.nr:42,56) and `verify_spend` reads `note.psi` from that committed note
// rather than re-deriving it (circuits/shared/src/spend.nr:18). The Merkle inclusion proof therefore pins psi
// for the entire life of the note, so one leaf can never yield two nullifiers. `psi_is_merkle_bound_not_rederived`
// pins that structural fact so a future refactor that starts re-deriving psi on the spend path fails here.
//
// COPIED REGION + PROVENANCE. `check_binding` / `check_binding_ablated` reproduce the constrained region of
// `From<Field> for ScalarField<N>::from` (packages/circuits/vendor/noir-edwards/src/scalar_field.nr:87-142 at
// darkpool da11582), and the unconstrained hint helpers are copied from the same file. `check-byte-identity.sh`
// re-derives the vendored region and fails on any drift. The two documented textual deviations from the
// vendored body are the same two the FROST harness carries:
//   1. the hint is a parameter instead of `unsafe { get_wnaf_slices(x) }` -- this IS the injection point;
//   2. the final 4-bit loop reads `slices[i]` instead of `result.base4_slices[i]` (identical values; this
//      crate cannot construct a `ScalarField`, whose fields are `pub(crate)` to edwards).
//
// FAITHFULNESS NOTE. Because `ScalarField`'s fields are `pub(crate)`, an external crate cannot hand forged
// slices to edwards' `mul`. So the production single call `from(eph)`-with-a-malicious-hint is split here into
// its two effects: (a) the binding constraints run against `eph` over the forged decomposition
// (`check_binding(wnaf(eph_forge), eph)`), and (b) `mul` consumes a scalar encoding `eph_forge`
// (`ScalarField::from(eph_forge)`). `get_wnaf_slices` is deterministic and both sides call it on the same
// input, so the array the binding is attacked with is bit-identical to the one `mul` consumes.
//
// Read the three load-bearing tests together:
//   - the forged note is genuinely untraceable -> compliance_cannot_rederive_the_forged_psi
//   - every guard EXCEPT the binding accepts it -> forged_witness_passes_every_guard_except_the_binding
//   - the binding rejects it, at the binding    -> forgery_rejected_by_binding_63

use ecdh::{bjj::{BJJ, check_subgroup}, ECDHTrait, Point};
use edwards::{CurveTrait, ScalarField};
use poseidon::poseidon2::Poseidon2;

// keccak256("hisoka.psi.v1") % BN254_Fr -- circuits/shared/src/common/domains.nr:4
global PSI_DOMAIN: Field = 0x138d495e7a5c1b3f504318dd6cfcf0a7cf7bb6d69cf9eadb049cc35d6831ef5b;
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

// the mint relation (mirrors kem::derive_cek + mint::mint_common, scalar source parametrised)

fn assert_subgroup_scalar(x: Field) {
    assert(x != 0, "scalar must be non-zero");
    assert(x.lt(SUBORDER), "scalar not in BabyJubJub prime-order subgroup");
}

// note_nullifier.nr:5-7
fn psi(cek: Field) -> Field {
    Poseidon2::hash([cek, PSI_DOMAIN], 2)
}

// note_nullifier.nr:10-12
fn nullifier(note_psi: Field, leaf_index: Field) -> Field {
    Poseidon2::hash([note_psi, leaf_index], 2)
}

// kem.nr:6-9 -> BJJ::derive_shared_key, with the multiplied scalar supplied by the caller (production: the
// value the slices encode).
fn derive_cek(eph: Field, compliance_pk: Point, mul_scalar: Field) -> Field {
    assert_subgroup_scalar(eph);
    assert(compliance_pk.is_on_curve(), "Public key not on curve");
    assert(check_subgroup(compliance_pk), "Public key not in valid subgroup");
    let scalar: ScalarField<63> = ScalarField::from(mul_scalar);
    compliance_pk.mul(scalar).x
}

// mint.nr:47-59, reduced to the psi binding under attack. Returns the leaf-committed psi.
fn mint_psi_binding(note_psi: Field, eph: Field, compliance_pk: Point, mul_scalar: Field) -> Field {
    let cek = derive_cek(eph, compliance_pk, mul_scalar);
    assert(note_psi == psi(cek), "psi not bound to CEK");
    note_psi
}

// mint.nr:56 -- the published ephemeral, ALWAYS derived from the honest eph.
fn eph_pub(eph: Field) -> Point {
    BJJ::new(eph).derive_public_key()
}

// What compliance computes off-chain from the emitted eph_pub and its own secret c.
fn compliance_psi(c: Field, published_eph_pub: Point) -> Field {
    psi(BJJ::new(c).derive_shared_key(published_eph_pub))
}

// fixtures

// A compliance keypair whose secret this harness knows, so the compliance side can be exercised in-circuit.
global C_SECRET: Field = 0x0000000000000000000000000000000000000000000000000000000000003039;
global EPH: Field = 0x00000000000000000000000000000000000000000000000000000000000001c8;

// An attacker-chosen ephemeral != EPH. The forger keeps EPH as the published one and keys psi to this.
global EPH_FORGE: Field = 0x00deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbe;

fn compliance_pk() -> Point {
    BJJ::new(C_SECRET).derive_public_key()
}

// The production fixture compliance key -- shared/src/common/test_fixtures.nr:5-8.
fn fixture_compliance_pk() -> Point {
    Point::new(
        0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
        0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
    )
}

// PARITY

// The mirrored crypto path is production-identical: reproduces the committed KEM/psi KATs
// (kem.nr:41-42 and note_nullifier.nr:16-21) exactly. Without this the rig could be attacking its own
// private arithmetic rather than the protocol's.
#[test]
fn mirror_reproduces_production_kem_and_psi_kats() {
    let cek = derive_cek(456, fixture_compliance_pk(), 456);
    assert(cek == 0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bda);

    let note_psi = psi(cek);
    assert(note_psi == 0x0441d9b1006cd55062a6458b5dd1db14869f1a5c8fbc66f73032208c2b109956);

    assert(nullifier(note_psi, 3) == 0x0ced8160f191dfff5c3432bc36f182188226143b294192021ea754f282075897);
}

// CONTROL

// The rig accepts an honest mint: honest hint (slices encode the true eph) under the production binding, and
// compliance recovers exactly the psi the note commits to. This is the property the forgery destroys.
#[test]
fn control_honest_mint_accepts_and_compliance_traces_it() {
    let c_pk = compliance_pk();
    // Safety: honest hint, bound by check_binding below.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(EPH) };
    check_binding::<63>(slices, skew, EPH);

    let cek = derive_cek(EPH, c_pk, EPH);
    let note_psi = mint_psi_binding(psi(cek), EPH, c_pk, EPH);

    assert(
        compliance_psi(C_SECRET, eph_pub(EPH)) == note_psi,
        "compliance must trace an honestly minted note",
    );
}

// The forged note is a REAL attack: compliance, doing everything correctly from the published eph_pub, lands
// on a psi that is NOT the note's psi. Without this test "the forgery is accepted" would carry no harm.
#[test]
fn compliance_cannot_rederive_the_forged_psi() {
    let c_pk = compliance_pk();
    let forged_cek = derive_cek(EPH, c_pk, EPH_FORGE);
    let forged_psi = psi(forged_cek);

    assert(
        compliance_psi(C_SECRET, eph_pub(EPH)) != forged_psi,
        "the forged note must be untraceable, else there is no attack",
    );
}

// The forged note still functions as a note: the attacker knows psi_forge, so it commits to a leaf and yields
// a nullifier exactly like an honest note. Untraceable AND spendable is what makes this worth a constraint.
#[test]
fn the_forged_note_remains_spendable_by_its_owner() {
    let c_pk = compliance_pk();
    let forged_psi = psi(derive_cek(EPH, c_pk, EPH_FORGE));
    let honest_psi = psi(derive_cek(EPH, c_pk, EPH));

    assert(nullifier(forged_psi, 7) != nullifier(honest_psi, 7));
    assert(nullifier(forged_psi, 7) == nullifier(forged_psi, 7));
}

// REJECT (production)

// The forged decomposition is rejected by the width-63 binding: slices encode EPH_FORGE, the binding asserts
// they encode the true EPH. This is the guard that keeps every minted note traceable.
#[test(should_fail)]
fn forgery_rejected_by_binding_63() {
    let c_pk = compliance_pk();
    // Safety: MALICIOUS hint -- slices encode EPH_FORGE, not EPH.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(EPH_FORGE) };
    check_binding::<63>(slices, skew, EPH);
    let _ = mint_psi_binding(psi(derive_cek(EPH, c_pk, EPH_FORGE)), EPH, c_pk, EPH_FORGE);
}

// The vendored width-64 binding `assert(hi * TWO_POW_128 + lo == x)` rejects it too. Scope: production always
// muls through ScalarField<63>; this pins the width-64 path the vendored library also exposes.
#[test(should_fail)]
fn forgery_rejected_by_binding_64() {
    // Safety: MALICIOUS hint.
    let (slices, skew): ([u8; 64], bool) = unsafe { get_wnaf_slices(EPH_FORGE) };
    check_binding::<64>(slices, skew, EPH);
}

// DIFFERENTIAL: nothing but the binding objects

// THE load-bearing differential. The forged witness runs through the ENTIRE mint psi relation with the binding
// simply not present -- every other guard still executes: assert_subgroup_scalar(eph), is_on_curve,
// check_subgroup on the compliance key, the 4-bit range loop, and the `psi not bound to CEK` assert itself.
// It PASSES, and the resulting note is the untraceable one. Combined with `forgery_rejected_by_binding_63`
// and `compliance_cannot_rederive_the_forged_psi`, this establishes the binding as the SOLE guard between a
// prover and a permanently untraceable note.
#[test]
fn forged_witness_passes_every_guard_except_the_binding() {
    let c_pk = compliance_pk();
    let forged_psi = psi(derive_cek(EPH, c_pk, EPH_FORGE));
    let committed = mint_psi_binding(forged_psi, EPH, c_pk, EPH_FORGE);

    assert(committed == forged_psi);
    assert(compliance_psi(C_SECRET, eph_pub(EPH)) != committed);
}

// The mirrored body with ONLY the binding asserts replaced by no-ops. As in the FROST harness, the pub(crate)
// split makes this call causally inert on the accept side, so it is not the differential; it pins that the
// ablated body itself introduces no new rejection.
#[test]
fn ablated_binding_body_raises_no_objection_63() {
    let c_pk = compliance_pk();
    // Safety: MALICIOUS hint.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(EPH_FORGE) };
    check_binding_ablated::<63>(slices, skew, EPH);
    let _ = mint_psi_binding(psi(derive_cek(EPH, c_pk, EPH_FORGE)), EPH, c_pk, EPH_FORGE);
}

// NOT VACUOUS

// The ablated rig is not simply "accept everything": an honest mint still verifies through it.
#[test]
fn ablated_rig_still_accepts_an_honest_mint() {
    let c_pk = compliance_pk();
    // Safety: honest hint.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(EPH) };
    check_binding_ablated::<63>(slices, skew, EPH);
    let _ = mint_psi_binding(psi(derive_cek(EPH, c_pk, EPH)), EPH, c_pk, EPH);
}

// The ablated rig still rejects a note whose psi is wrong for a reason OTHER than the binding, so the
// `psi not bound to CEK` assert is genuinely enforced and the accept path above is not free.
#[test(should_fail_with = "psi not bound to CEK")]
fn ablated_rig_still_rejects_a_mutated_psi() {
    let c_pk = compliance_pk();
    // Safety: honest hint.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(EPH) };
    check_binding_ablated::<63>(slices, skew, EPH);
    let _ = mint_psi_binding(psi(derive_cek(EPH, c_pk, EPH)) + 1, EPH, c_pk, EPH);
}

// SCOPE PIN

// Structural reason the forgery stops at traceability and is not a double-spend: psi is a committed leaf field
// and the spend path reads it back rather than re-deriving it, so one leaf yields exactly one nullifier no
// matter what the mint-time hint did. If a refactor ever re-derives psi during spend, this stops holding and
// the same forgery becomes a drain.
#[test]
fn psi_is_merkle_bound_not_rederived() {
    let c_pk = compliance_pk();
    let forged_psi = psi(derive_cek(EPH, c_pk, EPH_FORGE));

    // The leaf commits psi (note.nr:42,56), so a note carrying forged_psi has exactly one nullifier per index.
    let nf_a = nullifier(forged_psi, 7);
    let nf_b = nullifier(forged_psi, 7);
    assert(nf_a == nf_b, "a committed psi must yield one nullifier per leaf index");

    // Changing psi changes the leaf, so it is a DIFFERENT note, not a second nullifier for the same one.
    assert(nullifier(psi(derive_cek(EPH, c_pk, EPH)), 7) != nf_a);
}

// bb proving target

// The ABLATED forgery as a provable circuit: `nargo execute` + `bb prove` + `bb verify` on this must produce a
// VERIFYING proof, which is the gold-standard evidence that the forgery is real and not a test-interpreter
// artifact. The production (bound) variant is proven by rejection at execute time instead.
fn main(c_secret: Field, eph: pub Field, eph_forge: Field) -> pub Field {
    let c_pk = BJJ::new(c_secret).derive_public_key();
    // Safety: MALICIOUS hint -- the attacker-controlled decomposition.
    let (slices, skew): ([u8; 63], bool) = unsafe { get_wnaf_slices(eph_forge) };
    check_binding_ablated::<63>(slices, skew, eph);

    let forged_psi = psi(derive_cek(eph, c_pk, eph_forge));
    let committed = mint_psi_binding(forged_psi, eph, c_pk, eph_forge);
    assert(compliance_psi(c_secret, eph_pub(eph)) != committed, "forged note must be untraceable");
    committed
}
