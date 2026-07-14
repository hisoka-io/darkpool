//! Mutation harness: prove the real 3-of-5 FROST KAT (one multisig note in -> two multisig-self notes out)
//! then mutate one soundness-relevant witness / signed public input and require rejection with the specific
//! guard. The FROST message m binds root, nullifier, out1.leaf, out2.leaf and asset, so any signed leaf
//! changed with no earlier guard is caught last by the signature equation.

use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;
use shared::TREE_DEPTH;

// Mirror the golden KAT witness in `kat_multisig_split_accepts`: input 100 -> out1 60 (eph 4) + out2 40 (eph 5).
global IN_VALUE: u128 = 100;
global OUT1_VALUE: u128 = 60;
global OUT2_VALUE: u128 = 40;
global EPH_1: Field = 4;
global EPH_2: Field = 5;

fn gpk() -> ecdh::Point {
    super::kat_gpk()
}
fn r() -> ecdh::Point {
    super::kat_frost_r()
}
fn inp() -> Note {
    super::ms_input(IN_VALUE)
}
fn o1() -> Note {
    super::out_note(OUT1_VALUE, 1, super::gpk_owner(), super::KAT_PSI1)
}
fn o2() -> Note {
    super::out_note(OUT2_VALUE, 1, super::gpk_owner(), super::KAT_PSI2)
}

// Full-override entry; path is always the trivial all-zero inclusion proof (root == leaf at index 0).
fn run(
    cx: Field,
    cy: Field,
    g: ecdh::Point,
    fr: ecdh::Point,
    z: Field,
    note_in: Note,
    idx: Field,
    a1: Note,
    e1: Field,
    a2: Note,
    e2: Field,
) {
    let _ = super::main(
        cx,
        cy,
        g,
        fr,
        z,
        note_in,
        idx,
        [0; TREE_DEPTH],
        a1,
        e1,
        a2,
        e2,
    );
}
fn v(
    g: ecdh::Point,
    fr: ecdh::Point,
    z: Field,
    note_in: Note,
    idx: Field,
    a1: Note,
    e1: Field,
    a2: Note,
    e2: Field,
) {
    run(super::CX, super::CY, g, fr, z, note_in, idx, a1, e1, a2, e2);
}

#[test]
fn m_valid_accepts() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}

#[test(should_fail_with = "gpk must not be the identity")]
fn m_gpk_identity() {
    v(
        mutation::bad_identity(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail)]
fn m_gpk_off_curve() {
    v(
        mutation::bad_off_curve(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_small_order() {
    v(
        mutation::bad_small_order(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_non_subgroup() {
    v(
        mutation::bad_non_subgroup(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
// a valid subgroup point that is NOT the account gpk -> the in-circuit owner pin rejects before FROST
#[test(should_fail_with = "spender does not own this multisig note")]
fn m_gpk_wrong_valid() {
    v(
        r(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}

// R carries only on-curve + non-identity; the equation binds the rest, checked last.
#[test(should_fail_with = "R must not be the identity")]
fn m_frost_r_identity() {
    v(
        gpk(),
        mutation::bad_identity(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail)]
fn m_frost_r_off_curve() {
    v(
        gpk(),
        mutation::bad_off_curve(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_r_non_subgroup() {
    v(
        gpk(),
        mutation::bad_non_subgroup(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_r_mutated() {
    v(
        gpk(),
        gpk(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}

#[test(should_fail_with = "scalar must be non-zero")]
fn m_frost_z_zero() {
    v(gpk(), r(), 0, inp(), 0, o1(), EPH_1, o2(), EPH_2);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_frost_z_ge_suborder() {
    v(gpk(), r(), SUBORDER, inp(), 0, o1(), EPH_1, o2(), EPH_2);
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_z_mutated() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z + 1,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}

// A value-preserving shift across the two signed outputs moves both leaves, so the recomputed m no longer
// matches; conservation still holds (61 + 39 == 100) and psi is value-independent, so control reaches FROST.
#[test(should_fail_with = "FROST signature invalid")]
fn m_signed_out_value_shift() {
    let mut a1 = o1();
    a1.value = 61;
    let mut a2 = o2();
    a2.value = 39;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        a1,
        EPH_1,
        a2,
        EPH_2,
    );
}

#[test(should_fail_with = "spender does not own this multisig note")]
fn m_old_owner_mutated() {
    let mut n = inp();
    n.owner = n.owner + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        n,
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "unexpected note type")]
fn m_old_note_type() {
    let mut n = inp();
    n.note_type = 0;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        n,
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_old_note_version() {
    let mut n = inp();
    n.note_version = 2;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        n,
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
// the input asset stays canonical (20 bytes) so it clears assert_asset_id and trips the out1 equality check
#[test(should_fail_with = "out1 asset mismatch")]
fn m_old_asset_mismatch() {
    let mut n = inp();
    n.asset_id = super::ASSET_ID + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        n,
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "non-canonical leaf index")]
fn m_noncanonical_leaf_index() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        7,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}

#[test(should_fail_with = "value not conserved")]
fn m_value_not_conserved() {
    let mut a1 = o1();
    a1.value = 61; // 61 + 40 = 101 != 100
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        a1,
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "attempt to add with overflow")]
fn m_value_output_overflow() {
    let mut a1 = o1();
    a1.value = 0xffffffffffffffffffffffffffffffff; // u128 max; max + out2 overflows the output sum
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        a1,
        EPH_1,
        o2(),
        EPH_2,
    );
}

#[test(should_fail_with = "multisig change/self must be owned by the account gpk")]
fn m_out1_owner_off_gpk() {
    let mut a1 = o1();
    a1.owner = a1.owner + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        a1,
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "multisig self note must be MULTISIG")]
fn m_out1_note_type_standard() {
    let mut a1 = o1();
    a1.note_type = 0;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        a1,
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_out1_note_version() {
    let mut a1 = o1();
    a1.note_version = 2;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        a1,
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_out1_conditions_hash() {
    let mut a1 = o1();
    a1.conditions_hash = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        a1,
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_out1_psi_unbound() {
    let mut a1 = o1();
    a1.psi = a1.psi + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        a1,
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_out1_parents_forged() {
    let mut a1 = o1();
    a1.parents = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        a1,
        EPH_1,
        o2(),
        EPH_2,
    );
}

// out1 mints fully with its golden self psi so control reaches the out2 mint guards.
#[test(should_fail_with = "multisig change/self must be owned by the account gpk")]
fn m_out2_owner_off_gpk() {
    let mut a2 = o2();
    a2.owner = a2.owner + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        a2,
        EPH_2,
    );
}
#[test(should_fail_with = "multisig self note must be MULTISIG")]
fn m_out2_note_type_standard() {
    let mut a2 = o2();
    a2.note_type = 0;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        a2,
        EPH_2,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_out2_note_version() {
    let mut a2 = o2();
    a2.note_version = 2;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        a2,
        EPH_2,
    );
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_out2_conditions_hash() {
    let mut a2 = o2();
    a2.conditions_hash = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        a2,
        EPH_2,
    );
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_out2_psi_unbound() {
    let mut a2 = o2();
    a2.psi = a2.psi + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        a2,
        EPH_2,
    );
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_out2_parents_forged() {
    let mut a2 = o2();
    a2.parents = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        a2,
        EPH_2,
    );
}

// A shared eph reuses the discovery tag across both outputs.
#[test(should_fail_with = "ephemerals must be distinct")]
fn m_eph_equal() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_1,
    );
}

#[test(should_fail_with = "scalar must be non-zero")]
fn m_eph_1_zero() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        0,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_eph_1_ge_suborder() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        SUBORDER,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "scalar must be non-zero")]
fn m_eph_2_zero() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        0,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_eph_2_ge_suborder() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        SUBORDER,
    );
}

#[test(should_fail_with = "compliance key must not be the identity")]
fn m_compliance_identity() {
    let p = mutation::bad_identity();
    run(
        p.x,
        p.y,
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_non_subgroup() {
    let p = mutation::bad_non_subgroup();
    run(
        p.x,
        p.y,
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        o1(),
        EPH_1,
        o2(),
        EPH_2,
    );
}
