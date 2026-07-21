//! Mutation harness: prove the FROST KAT, mutate one witness/signed input, assert the specific rejection.

use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;
use shared::TREE_DEPTH;

fn gpk() -> ecdh::Point {
    super::kat_gpk()
}
fn r() -> ecdh::Point {
    super::kat_frost_r()
}
fn inp() -> Note {
    super::ms_input(super::KAT_OLD_VALUE)
}
fn out() -> Note {
    super::out_note(
        super::KAT_CHANGE_VALUE,
        1,
        super::gpk_owner(),
        super::KAT_CHANGE_PSI,
    )
}

fn run(
    wval: u128,
    recip: Field,
    intent: Field,
    cx: Field,
    cy: Field,
    g: ecdh::Point,
    fr: ecdh::Point,
    z: Field,
    o: Note,
    idx: Field,
    ch: Note,
    eph: Field,
) {
    let _ = super::main(
        wval,
        recip,
        intent,
        cx,
        cy,
        g,
        fr,
        z,
        o,
        idx,
        [0; TREE_DEPTH],
        ch,
        eph,
    );
}
fn v(g: ecdh::Point, fr: ecdh::Point, z: Field, o: Note, idx: Field, ch: Note, eph: Field) {
    run(
        super::KAT_WITHDRAW_VALUE,
        super::KAT_RECIPIENT,
        super::KAT_INTENT_HASH,
        super::CX,
        super::CY,
        g,
        fr,
        z,
        o,
        idx,
        ch,
        eph,
    );
}

#[test]
fn m_valid_accepts() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}

#[test(should_fail_with = "gpk must not be the identity")]
fn m_gpk_identity() {
    let p = mutation::bad_identity();
    v(
        p,
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail)]
fn m_gpk_off_curve() {
    let p = mutation::bad_off_curve();
    v(
        p,
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_small_order() {
    let p = mutation::bad_small_order();
    v(
        p,
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_non_subgroup() {
    let p = mutation::bad_non_subgroup();
    v(
        p,
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
// valid non-gpk point: owner pin rejects before FROST
#[test(should_fail_with = "spender does not own this multisig note")]
fn m_gpk_wrong_valid() {
    v(
        r(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}

#[test(should_fail_with = "R must not be the identity")]
fn m_frost_r_identity() {
    v(
        gpk(),
        mutation::bad_identity(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
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
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_r_non_subgroup() {
    // R carries only an on-curve + non-identity check; a non-subgroup R must still fail the signature equation
    v(
        gpk(),
        mutation::bad_non_subgroup(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
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
        out(),
        super::KAT_CHANGE_EPH,
    );
}

// ScalarField<63> challenge is derived from m, not a free witness.
#[test(should_fail_with = "scalar must be non-zero")]
fn m_frost_z_zero() {
    v(gpk(), r(), 0, inp(), 0, out(), super::KAT_CHANGE_EPH);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_frost_z_ge_suborder() {
    v(gpk(), r(), SUBORDER, inp(), 0, out(), super::KAT_CHANGE_EPH);
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_z_mutated() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z + 1,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
// recipient+intent have no earlier guard; only the FROST equation binds them
#[test(should_fail_with = "FROST signature invalid")]
fn m_signed_recipient() {
    run(
        super::KAT_WITHDRAW_VALUE,
        super::KAT_RECIPIENT + 1,
        super::KAT_INTENT_HASH,
        super::CX,
        super::CY,
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_signed_intent_hash() {
    run(
        super::KAT_WITHDRAW_VALUE,
        super::KAT_RECIPIENT,
        super::KAT_INTENT_HASH + 1,
        super::CX,
        super::CY,
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}

#[test(should_fail_with = "spender does not own this multisig note")]
fn m_old_owner_mutated() {
    let mut o = inp();
    o.owner = o.owner + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        o,
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "unexpected note type")]
fn m_old_note_type() {
    let mut o = inp();
    o.note_type = 0;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        o,
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_old_note_version() {
    let mut o = inp();
    o.note_version = 2;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        o,
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "asset mismatch")]
fn m_old_asset_mismatch() {
    let mut o = inp();
    o.asset_id = super::ASSET_ID + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        o,
        0,
        out(),
        super::KAT_CHANGE_EPH,
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
        out(),
        super::KAT_CHANGE_EPH,
    );
}

#[test(should_fail_with = "value not conserved")]
fn m_value_not_conserved() {
    run(
        super::KAT_WITHDRAW_VALUE + 1,
        super::KAT_RECIPIENT,
        super::KAT_INTENT_HASH,
        super::CX,
        super::CY,
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "attempt to add with overflow")]
fn m_value_output_overflow() {
    let mut ch = out();
    ch.value = 0xffffffffffffffffffffffffffffffff;
    run(
        1,
        super::KAT_RECIPIENT,
        super::KAT_INTENT_HASH,
        super::CX,
        super::CY,
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        ch,
        super::KAT_CHANGE_EPH,
    );
}

#[test(should_fail_with = "multisig change/self must be owned by the account gpk")]
fn m_change_owner_off_gpk() {
    let mut ch = out();
    ch.owner = ch.owner + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "multisig self note must be MULTISIG")]
fn m_change_note_type_standard() {
    let mut ch = out();
    ch.note_type = 0;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_change_note_version() {
    let mut ch = out();
    ch.note_version = 2;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_change_conditions_hash() {
    let mut ch = out();
    ch.conditions_hash = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_change_psi_unbound() {
    let mut ch = out();
    ch.psi = ch.psi + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_change_parents_forged() {
    let mut ch = out();
    ch.parents = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        ch,
        super::KAT_CHANGE_EPH,
    );
}

#[test(should_fail_with = "compliance key must not be the identity")]
fn m_compliance_identity() {
    let p = mutation::bad_identity();
    run(
        super::KAT_WITHDRAW_VALUE,
        super::KAT_RECIPIENT,
        super::KAT_INTENT_HASH,
        p.x,
        p.y,
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_non_subgroup() {
    let p = mutation::bad_non_subgroup();
    run(
        super::KAT_WITHDRAW_VALUE,
        super::KAT_RECIPIENT,
        super::KAT_INTENT_HASH,
        p.x,
        p.y,
        gpk(),
        r(),
        super::KAT_FROST_Z,
        inp(),
        0,
        out(),
        super::KAT_CHANGE_EPH,
    );
}

#[test(should_fail_with = "scalar must be non-zero")]
fn m_change_eph_zero() {
    v(gpk(), r(), super::KAT_FROST_Z, inp(), 0, out(), 0);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_change_eph_ge_suborder() {
    v(gpk(), r(), super::KAT_FROST_Z, inp(), 0, out(), SUBORDER);
}
