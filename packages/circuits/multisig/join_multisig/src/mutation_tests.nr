//! Mutation harness: 2-in-1-out same-account FROST KAT; mutate one witness/signed input, assert the specific
//! rejection. Both spends + both verifies are probed (b-side isolates the second verify).

use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;
use shared::TREE_DEPTH;

global Z: Field = super::KAT_FROST_Z;
global EPH: Field = 4;

fn gpk() -> ecdh::Point {
    super::kat_gpk()
}
fn r() -> ecdh::Point {
    super::kat_frost_r()
}
fn note_a_v() -> Note {
    super::join_input(100, super::gpk_owner(), 0x01)
}
fn note_b_v() -> Note {
    super::join_input(50, super::gpk_owner(), 0x02)
}
fn out_v() -> Note {
    super::kat_out_note()
}

// paths rebuilt from the (mutated) leaves as a 2-leaf tree so mutations reach their intended guard, not shared-root
fn run(
    cx: Field,
    cy: Field,
    ga: ecdh::Point,
    ra: ecdh::Point,
    za: Field,
    na: Note,
    ia: Field,
    gb: ecdh::Point,
    rb: ecdh::Point,
    zb: Field,
    nb: Note,
    ib: Field,
    out: Note,
    eph: Field,
) {
    let mut pa = [0; TREE_DEPTH];
    pa[0] = nb.leaf();
    let mut pb = [0; TREE_DEPTH];
    pb[0] = na.leaf();
    let _ = super::main(
        cx,
        cy,
        ga,
        ra,
        za,
        na,
        ia,
        pa,
        gb,
        rb,
        zb,
        nb,
        ib,
        pb,
        out,
        eph,
    );
}

#[test]
fn m_valid_accepts() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
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
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
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
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}

#[test(should_fail_with = "gpk must not be the identity")]
fn m_gpk_a_identity() {
    run(
        super::CX,
        super::CY,
        mutation::bad_identity(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail)]
fn m_gpk_a_off_curve() {
    run(
        super::CX,
        super::CY,
        mutation::bad_off_curve(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_a_small_order() {
    run(
        super::CX,
        super::CY,
        mutation::bad_small_order(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_a_non_subgroup() {
    run(
        super::CX,
        super::CY,
        mutation::bad_non_subgroup(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
// valid non-gpk point: owner pin rejects before FROST
#[test(should_fail_with = "spender does not own this multisig note")]
fn m_gpk_a_wrong_valid() {
    run(
        super::CX,
        super::CY,
        r(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}

// A valid so B's open is what rejects
#[test(should_fail_with = "gpk must not be the identity")]
fn m_gpk_b_identity() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        mutation::bad_identity(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail)]
fn m_gpk_b_off_curve() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        mutation::bad_off_curve(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_b_small_order() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        mutation::bad_small_order(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_b_non_subgroup() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        mutation::bad_non_subgroup(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "spender does not own this multisig note")]
fn m_gpk_b_wrong_valid() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        r(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}

#[test(should_fail_with = "spender does not own this multisig note")]
fn m_note_a_owner() {
    let mut na = note_a_v();
    na.owner = na.owner + 1;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        na,
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "unexpected note type")]
fn m_note_a_note_type() {
    let mut na = note_a_v();
    na.note_type = 0;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        na,
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_note_a_version() {
    let mut na = note_a_v();
    na.note_version = 2;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        na,
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "non-canonical leaf index")]
fn m_note_a_noncanonical_index() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        7,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}

// A valid so note_b membership rejects
#[test(should_fail_with = "spender does not own this multisig note")]
fn m_note_b_owner() {
    let mut nb = note_b_v();
    nb.owner = nb.owner + 1;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        nb,
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "unexpected note type")]
fn m_note_b_note_type() {
    let mut nb = note_b_v();
    nb.note_type = 0;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        nb,
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_note_b_version() {
    let mut nb = note_b_v();
    nb.note_version = 2;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        nb,
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "non-canonical leaf index")]
fn m_note_b_noncanonical_index() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        7,
        out_v(),
        EPH,
    );
}

#[test(should_fail_with = "inputs must share a root")]
fn m_inputs_share_root() {
    let na = note_a_v();
    let nb = note_b_v();
    let mut pa = [0; TREE_DEPTH];
    pa[0] = nb.leaf();
    let mut pb = [0; TREE_DEPTH];
    pb[0] = na.leaf() + 1; // wrong sibling -> note_b reconstructs a different root
    let _ = super::main(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        na,
        0,
        pa,
        gpk(),
        r(),
        Z,
        nb,
        1,
        pb,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "cannot join a note with itself")]
fn m_join_with_itself() {
    // same note+index both sides: roots match, identical nullifier trips the self-join guard before conservation
    let note = note_a_v();
    let empty = [0; TREE_DEPTH];
    let _ = super::main(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note,
        0,
        empty,
        gpk(),
        r(),
        Z,
        note,
        0,
        empty,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "join inputs must be strictly index-ordered")]
fn m_index_not_ordered() {
    // a@1,b@0: valid shared tree, so the index-order guard (not membership) rejects
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        1,
        gpk(),
        r(),
        Z,
        note_b_v(),
        0,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "join inputs must share one account gpk")]
fn m_cross_account_gpk() {
    // distinct-gpk notes pass their owner pins; only the cross-account guard stops the merge
    let b = super::gpk_b();
    let owner_b = poseidon::poseidon2::Poseidon2::hash([b.x, b.y], 2);
    let nb = super::join_input(50, owner_b, 0x02);
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        b,
        r(),
        Z,
        nb,
        1,
        out_v(),
        EPH,
    );
}

#[test(should_fail_with = "input asset mismatch")]
fn m_input_asset_mismatch() {
    let mut na = note_a_v();
    na.asset_id = super::ASSET_ID + 1;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        na,
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "output asset mismatch")]
fn m_output_asset_mismatch() {
    let mut out = out_v();
    out.asset_id = super::ASSET_ID + 1;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out,
        EPH,
    );
}

#[test(should_fail_with = "value not conserved")]
fn m_value_not_conserved() {
    let mut out = out_v();
    out.value = 151;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out,
        EPH,
    );
}
#[test(should_fail_with = "attempt to add with overflow")]
fn m_value_input_overflow() {
    let mut na = note_a_v();
    na.value = 0xffffffffffffffffffffffffffffffff;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        na,
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}

#[test(should_fail_with = "multisig change/self must be owned by the account gpk")]
fn m_out_owner_off_gpk() {
    let mut out = out_v();
    out.owner = out.owner + 1;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out,
        EPH,
    );
}
#[test(should_fail_with = "multisig self note must be MULTISIG")]
fn m_out_note_type_standard() {
    let mut out = out_v();
    out.note_type = 0;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out,
        EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_out_version() {
    let mut out = out_v();
    out.note_version = 2;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out,
        EPH,
    );
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_out_conditions_hash() {
    let mut out = out_v();
    out.conditions_hash = 1;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out,
        EPH,
    );
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_out_psi_unbound() {
    let mut out = out_v();
    out.psi = out.psi + 1;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out,
        EPH,
    );
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_out_parents_forged() {
    let mut out = out_v();
    out.parents = 1;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out,
        EPH,
    );
}

#[test(should_fail_with = "scalar must be non-zero")]
fn m_eph_zero() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        0,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_eph_ge_suborder() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        SUBORDER,
    );
}

// Only R carries the on-curve + non-identity check; the equation catches the rest.
#[test(should_fail_with = "R must not be the identity")]
fn m_frost_r_a_identity() {
    run(
        super::CX,
        super::CY,
        gpk(),
        mutation::bad_identity(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail)]
fn m_frost_r_a_off_curve() {
    run(
        super::CX,
        super::CY,
        gpk(),
        mutation::bad_off_curve(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_r_a_non_subgroup() {
    run(
        super::CX,
        super::CY,
        gpk(),
        mutation::bad_non_subgroup(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_r_a_mutated() {
    run(
        super::CX,
        super::CY,
        gpk(),
        gpk(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "R must not be the identity")]
fn m_frost_r_b_identity() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        mutation::bad_identity(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail)]
fn m_frost_r_b_off_curve() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        mutation::bad_off_curve(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_r_b_non_subgroup() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        mutation::bad_non_subgroup(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_r_b_mutated() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        gpk(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}

#[test(should_fail_with = "scalar must be non-zero")]
fn m_frost_z_a_zero() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        0,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_frost_z_a_ge_suborder() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        SUBORDER,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_z_a_mutated() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z + 1,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
// b-side scalars: verify(a) passes, verify(b) rejects
#[test(should_fail_with = "scalar must be non-zero")]
fn m_frost_z_b_zero() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        0,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_frost_z_b_ge_suborder() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        SUBORDER,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_z_b_mutated() {
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z + 1,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}

// psi has no pre-FROST guard; it flows into the nullifier in m, so mutating it invalidates the signature
#[test(should_fail_with = "FROST signature invalid")]
fn m_signed_nullifier_a() {
    let mut na = note_a_v();
    na.psi = na.psi + 0x1000;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        na,
        0,
        gpk(),
        r(),
        Z,
        note_b_v(),
        1,
        out_v(),
        EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_signed_nullifier_b() {
    let mut nb = note_b_v();
    nb.psi = nb.psi + 0x1000;
    run(
        super::CX,
        super::CY,
        gpk(),
        r(),
        Z,
        note_a_v(),
        0,
        gpk(),
        r(),
        Z,
        nb,
        1,
        out_v(),
        EPH,
    );
}
