//! Additive mutation harness for the `join` circuit (Layer-1, constraint-level). Prove-then-mutate-then-reject:
//! from the valid KAT witness, flip ONE soundness-relevant asserted field and require the constraint system to
//! reject with the SPECIFIC guard message (a wrong-reason failure would not match `should_fail_with`). join
//! consumes TWO input notes (a, b) into ONE self output, so every input guard is covered on BOTH a and b, plus
//! the three two-input binding asserts (shared root, distinct nullifier, strict index order). Fields bound to a
//! public OUTPUT (nullifiers/root) are covered at the deployed-verifier layer, not here. No circuit logic touched.

use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;
use shared::TREE_DEPTH;

global ASSET: Field = 0x1234567890123456789012345678901234567890;
global SCALAR: Field = 789;
global EPH: Field = 28;
global PSI_A: Field = 0x271c8cc2341079e393fa781a5e7b4664b27b649d4f0277a53110b7937ed9fada;
global PSI_B: Field = 0x22c2ddd73188e4c766c528228312ae28595623aba1a5c5341a8f7154943842d3;
global PSI_OUT: Field = 0x09fb1bde9d635c97fa5a0884a8a38d961cec75db95e76629aabec8b63baec84a;
global PARENTS_OUT: Field = 0x100000000;

fn note_a() -> Note {
    super::note(100, PSI_A)
}
fn note_b() -> Note {
    super::note(50, PSI_B)
}
fn note_out() -> Note {
    let mut n = super::note(150, PSI_OUT);
    n.parents = PARENTS_OUT;
    n
}

// Sibling wiring for the frozen two-leaf KAT tree: a at index 0 (sibling = b's leaf), b at index 1 (sibling = a's leaf).
fn kat_paths() -> ([Field; TREE_DEPTH], [Field; TREE_DEPTH]) {
    let mut pa = [0; TREE_DEPTH];
    pa[0] = super::LEAF_B;
    let mut pb = [0; TREE_DEPTH];
    pb[0] = super::LEAF_A;
    (pa, pb)
}

fn run(
    cx: Field,
    cy: Field,
    na: Note,
    sa: Field,
    ia: Field,
    pa: [Field; TREE_DEPTH],
    nb: Note,
    sb: Field,
    ib: Field,
    pb: [Field; TREE_DEPTH],
    no: Note,
    eph: Field,
) {
    let _ = super::main(cx, cy, na, sa, ia, pa, nb, sb, ib, pb, no, eph);
}

// The byte-identical golden transaction; every should_fail test below overrides exactly one field off this.
fn valid(cx: Field, cy: Field) {
    let (pa, pb) = kat_paths();
    run(
        cx,
        cy,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}

#[test]
fn m_valid_accepts() {
    valid(super::CX, super::CY);
}

// compliance key: BJJ curve-op entry (identity / off-curve / small-order / non-subgroup)
#[test(should_fail_with = "compliance key must not be the identity")]
fn m_compliance_identity() {
    let p = mutation::bad_identity();
    let (pa, pb) = kat_paths();
    run(
        p.x,
        p.y,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail)]
fn m_compliance_off_curve() {
    let p = mutation::bad_off_curve();
    let (pa, pb) = kat_paths();
    run(
        p.x,
        p.y,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_small_order() {
    let p = mutation::bad_small_order();
    let (pa, pb) = kat_paths();
    run(
        p.x,
        p.y,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_non_subgroup() {
    let p = mutation::bad_non_subgroup();
    let (pa, pb) = kat_paths();
    run(
        p.x,
        p.y,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}

// input A: spend scalar / ownership / membership fields
#[test(should_fail_with = "spender does not own this note")]
fn m_a_scalar_wrong() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        0x2a,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "scalar must be non-zero")]
fn m_a_scalar_zero() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        0,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_a_scalar_ge_suborder() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        SUBORDER,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "spender does not own this note")]
fn m_a_owner_mutated() {
    let (pa, pb) = kat_paths();
    let mut na = note_a();
    na.owner = 0xdeadbeef;
    run(
        super::CX,
        super::CY,
        na,
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "unexpected note type")]
fn m_a_note_type() {
    let (pa, pb) = kat_paths();
    let mut na = note_a();
    na.note_type = 1;
    run(
        super::CX,
        super::CY,
        na,
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_a_version() {
    let (pa, pb) = kat_paths();
    let mut na = note_a();
    na.note_version = 2;
    run(
        super::CX,
        super::CY,
        na,
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
// asset is committed in the leaf, so a lone asset flip diverges the reconstructed root before the a==b asset
// assert; the reachable guard is the shared-root bind. "input asset mismatch" is exercised in m_input_asset_mismatch.
#[test(should_fail_with = "inputs must share a root")]
fn m_a_asset_binds_root() {
    let (pa, pb) = kat_paths();
    let mut na = note_a();
    na.asset_id = ASSET + 1;
    run(
        super::CX,
        super::CY,
        na,
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "non-canonical leaf index")]
fn m_a_noncanonical_index() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        7,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}

// input B: same guards on the second spend
#[test(should_fail_with = "spender does not own this note")]
fn m_b_scalar_wrong() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        0x2a,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "scalar must be non-zero")]
fn m_b_scalar_zero() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        0,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_b_scalar_ge_suborder() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SUBORDER,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "spender does not own this note")]
fn m_b_owner_mutated() {
    let (pa, pb) = kat_paths();
    let mut nb = note_b();
    nb.owner = 0xdeadbeef;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        nb,
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "unexpected note type")]
fn m_b_note_type() {
    let (pa, pb) = kat_paths();
    let mut nb = note_b();
    nb.note_type = 1;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        nb,
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_b_version() {
    let (pa, pb) = kat_paths();
    let mut nb = note_b();
    nb.note_version = 2;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        nb,
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "inputs must share a root")]
fn m_b_asset_binds_root() {
    let (pa, pb) = kat_paths();
    let mut nb = note_b();
    nb.asset_id = ASSET + 1;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        nb,
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "non-canonical leaf index")]
fn m_b_noncanonical_index() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        7,
        pb,
        note_out(),
        EPH,
    );
}

// two-input binding asserts (join-specific)
#[test(should_fail_with = "inputs must share a root")]
fn m_root_mismatch() {
    let (pa, _pb) = kat_paths();
    let mut pb = [0; TREE_DEPTH];
    pb[0] = 0x0abc;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "cannot join a note with itself")]
fn m_self_join() {
    // Same note at the same index in both slots: roots still agree, so the distinct-nullifier guard is the one that fires.
    let mut pa = [0; TREE_DEPTH];
    pa[0] = super::LEAF_B;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_a(),
        SCALAR,
        0,
        pa,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "join inputs must be strictly index-ordered")]
fn m_unordered_inputs() {
    // b at index 1 in slot A, a at index 0 in slot B: roots agree and nullifiers differ, so only the ordering assert fails.
    let mut pa = [0; TREE_DEPTH];
    pa[0] = super::LEAF_A;
    let mut pb = [0; TREE_DEPTH];
    pb[0] = super::LEAF_B;
    run(
        super::CX,
        super::CY,
        note_b(),
        SCALAR,
        1,
        pa,
        note_a(),
        SCALAR,
        0,
        pb,
        note_out(),
        EPH,
    );
}

// asset binding across the join (a==b, a==out)
#[test(should_fail_with = "input asset mismatch")]
fn m_input_asset_mismatch() {
    // Both inputs legitimately in the tree but carrying different assets: recompute siblings so the roots agree,
    // which is the only way to reach the a==b asset assert past the shared-root bind.
    let mut na = note_a();
    na.asset_id = ASSET + 1;
    let nb = note_b();
    let mut pa = [0; TREE_DEPTH];
    pa[0] = nb.leaf();
    let mut pb = [0; TREE_DEPTH];
    pb[0] = na.leaf();
    run(
        super::CX,
        super::CY,
        na,
        SCALAR,
        0,
        pa,
        nb,
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}
#[test(should_fail_with = "output asset mismatch")]
fn m_output_asset_mismatch() {
    let (pa, pb) = kat_paths();
    let mut no = note_out();
    no.asset_id = ASSET + 1;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        no,
        EPH,
    );
}

// value conservation / u128 overflow
#[test(should_fail_with = "value not conserved")]
fn m_value_not_conserved() {
    let (pa, pb) = kat_paths();
    let mut no = note_out();
    no.value = 151;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        no,
        EPH,
    );
}
#[test(should_fail_with = "attempt to add with overflow")]
fn m_value_overflow() {
    // Both inputs near 2^127 so total_in wraps u128; recompute siblings so membership still binds to reach conservation.
    let mut na = note_a();
    na.value = 0x80000000000000000000000000000000;
    let mut nb = note_b();
    nb.value = 0x80000000000000000000000000000000;
    let mut pa = [0; TREE_DEPTH];
    pa[0] = nb.leaf();
    let mut pb = [0; TREE_DEPTH];
    pb[0] = na.leaf();
    run(
        super::CX,
        super::CY,
        na,
        SCALAR,
        0,
        pa,
        nb,
        SCALAR,
        1,
        pb,
        note_out(),
        EPH,
    );
}

// self output note (mint_self_note)
#[test(should_fail_with = "note owner must be non-zero")]
fn m_out_owner_zero() {
    let (pa, pb) = kat_paths();
    let mut no = note_out();
    no.owner = 0;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        no,
        EPH,
    );
}
#[test(should_fail_with = "self note must be STANDARD")]
fn m_out_note_type() {
    let (pa, pb) = kat_paths();
    let mut no = note_out();
    no.note_type = 1;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        no,
        EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_out_version() {
    let (pa, pb) = kat_paths();
    let mut no = note_out();
    no.note_version = 2;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        no,
        EPH,
    );
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_out_conditions_hash() {
    let (pa, pb) = kat_paths();
    let mut no = note_out();
    no.conditions_hash = 1;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        no,
        EPH,
    );
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_out_psi() {
    let (pa, pb) = kat_paths();
    let mut no = note_out();
    no.psi = PSI_OUT + 1;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        no,
        EPH,
    );
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_out_parents() {
    let (pa, pb) = kat_paths();
    let mut no = note_out();
    no.parents = 0;
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        no,
        EPH,
    );
}

// output ephemeral scalar (feeds the ECDH mul)
#[test(should_fail_with = "scalar must be non-zero")]
fn m_eph_zero() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        0,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_eph_ge_suborder() {
    let (pa, pb) = kat_paths();
    run(
        super::CX,
        super::CY,
        note_a(),
        SCALAR,
        0,
        pa,
        note_b(),
        SCALAR,
        1,
        pb,
        note_out(),
        SUBORDER,
    );
}
