use ecdh::Point;
use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;
use shared::TREE_DEPTH;

global SCALAR: Field = 789;
global MEPH: Field = 15;
global CEPH: Field = 9;
global ASSET: Field = 0x1234567890123456789012345678901234567890;

// Odd-y recipient key: the wallet rolls its ephemeral until the discovery tag is even, so odd-y must reject.
global ODD_RECIPIENT_X: Field = 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764;
global ODD_RECIPIENT_Y: Field = 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101;
global ODD_RECIPIENT_OWNER: Field =
    0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;

fn rin() -> Point {
    super::recipient_in_pub()
}
fn old() -> Note {
    super::spent_note()
}
fn memo() -> Note {
    super::memo_note()
}
fn change() -> Note {
    super::change_note()
}

fn run(
    cx: Field,
    cy: Field,
    r: Point,
    o: Note,
    s: Field,
    idx: Field,
    m: Note,
    meph: Field,
    ch: Note,
    ceph: Field,
) {
    let _ = super::main(cx, cy, r, r, o, s, idx, [0; TREE_DEPTH], m, meph, ch, ceph);
}

fn v(r: Point, o: Note, s: Field, idx: Field, m: Note, meph: Field, ch: Note, ceph: Field) {
    run(super::CX, super::CY, r, o, s, idx, m, meph, ch, ceph);
}

#[test]
fn m_valid_accepts() {
    v(rin(), old(), SCALAR, 0, memo(), MEPH, change(), CEPH);
}

// psi rebound to eph=6's CEK so the psi guard passes and the incoming even-y guard is the one that fires.
#[test(should_fail_with = "incoming eph tag must be even-y")]
fn m_memo_odd_y_eph() {
    let mut m = memo();
    m.psi = 0x28c44d31081da1455b5f66d1dc6114bcced5e4e571e81b77a3dc9405b09145bf;
    v(rin(), old(), SCALAR, 0, m, 6, change(), CEPH);
}

#[test(should_fail_with = "compliance key must not be the identity")]
fn m_compliance_identity() {
    let p = mutation::bad_identity();
    run(
        p.x,
        p.y,
        rin(),
        old(),
        SCALAR,
        0,
        memo(),
        MEPH,
        change(),
        CEPH,
    );
}
#[test(should_fail)]
fn m_compliance_off_curve() {
    let p = mutation::bad_off_curve();
    run(
        p.x,
        p.y,
        rin(),
        old(),
        SCALAR,
        0,
        memo(),
        MEPH,
        change(),
        CEPH,
    );
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_small_order() {
    let p = mutation::bad_small_order();
    run(
        p.x,
        p.y,
        rin(),
        old(),
        SCALAR,
        0,
        memo(),
        MEPH,
        change(),
        CEPH,
    );
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_non_subgroup() {
    let p = mutation::bad_non_subgroup();
    run(
        p.x,
        p.y,
        rin(),
        old(),
        SCALAR,
        0,
        memo(),
        MEPH,
        change(),
        CEPH,
    );
}

#[test(should_fail_with = "spender does not own this note")]
fn m_spend_scalar_wrong() {
    v(rin(), old(), 0x2a, 0, memo(), MEPH, change(), CEPH);
}
#[test(should_fail_with = "scalar must be non-zero")]
fn m_spend_scalar_zero() {
    v(rin(), old(), 0, 0, memo(), MEPH, change(), CEPH);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_spend_scalar_ge_suborder() {
    v(rin(), old(), SUBORDER, 0, memo(), MEPH, change(), CEPH);
}
#[test(should_fail_with = "spender does not own this note")]
fn m_old_owner_mutated() {
    let mut o = old();
    o.owner = 0xdeadbeef;
    v(rin(), o, SCALAR, 0, memo(), MEPH, change(), CEPH);
}

#[test(should_fail_with = "unexpected note type")]
fn m_old_note_type() {
    let mut o = old();
    o.note_type = 1;
    v(rin(), o, SCALAR, 0, memo(), MEPH, change(), CEPH);
}
#[test(should_fail_with = "unexpected note version")]
fn m_old_note_version() {
    let mut o = old();
    o.note_version = 2;
    v(rin(), o, SCALAR, 0, memo(), MEPH, change(), CEPH);
}
#[test(should_fail_with = "memo asset mismatch")]
fn m_old_asset_mismatch() {
    let mut o = old();
    o.asset_id = ASSET + 1;
    v(rin(), o, SCALAR, 0, memo(), MEPH, change(), CEPH);
}
#[test(should_fail_with = "non-canonical leaf index")]
fn m_noncanonical_leaf_index() {
    v(rin(), old(), SCALAR, 7, memo(), MEPH, change(), CEPH);
}

#[test(should_fail_with = "value not conserved")]
fn m_value_not_conserved() {
    let mut o = old();
    o.value += 1;
    v(rin(), o, SCALAR, 0, memo(), MEPH, change(), CEPH);
}
#[test(should_fail_with = "attempt to add with overflow")]
fn m_value_output_overflow() {
    let mut ch = change();
    ch.value = 0xffffffffffffffffffffffffffffffff;
    v(rin(), old(), SCALAR, 0, memo(), MEPH, ch, CEPH);
}

#[test(should_fail_with = "ephemerals must be distinct")]
fn m_ephemerals_equal() {
    v(rin(), old(), SCALAR, 0, memo(), MEPH, change(), MEPH);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn m_memo_eph_zero() {
    v(rin(), old(), SCALAR, 0, memo(), 0, change(), CEPH);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_memo_eph_ge_suborder() {
    v(rin(), old(), SCALAR, 0, memo(), SUBORDER, change(), CEPH);
}

#[test(should_fail_with = "scalar must be non-zero")]
fn m_change_eph_zero() {
    v(rin(), old(), SCALAR, 0, memo(), MEPH, change(), 0);
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_change_eph_ge_suborder() {
    v(rin(), old(), SCALAR, 0, memo(), MEPH, change(), SUBORDER);
}

#[test(should_fail_with = "memo spend key must not be the identity")]
fn m_recipient_identity() {
    v(
        mutation::bad_identity(),
        old(),
        SCALAR,
        0,
        memo(),
        MEPH,
        change(),
        CEPH,
    );
}
#[test(should_fail)]
fn m_recipient_off_curve() {
    v(
        mutation::bad_off_curve(),
        old(),
        SCALAR,
        0,
        memo(),
        MEPH,
        change(),
        CEPH,
    );
}
#[test(should_fail_with = "memo spend key not in prime-order subgroup")]
fn m_recipient_small_order() {
    v(
        mutation::bad_small_order(),
        old(),
        SCALAR,
        0,
        memo(),
        MEPH,
        change(),
        CEPH,
    );
}
#[test(should_fail_with = "memo spend key not in prime-order subgroup")]
fn m_recipient_non_subgroup() {
    v(
        mutation::bad_non_subgroup(),
        old(),
        SCALAR,
        0,
        memo(),
        MEPH,
        change(),
        CEPH,
    );
}

#[test(should_fail_with = "STANDARD memo must collapse spend/view; MULTISIG must decouple them")]
fn m_memo_note_type() {
    let mut m = memo();
    m.note_type = 1;
    v(rin(), old(), SCALAR, 0, m, MEPH, change(), CEPH);
}
#[test(should_fail_with = "incoming memo note_type must be STANDARD or MULTISIG")]
fn m_memo_note_type_conditional() {
    let mut m = memo();
    m.note_type = 2;
    v(rin(), old(), SCALAR, 0, m, MEPH, change(), CEPH);
}
#[test(should_fail_with = "memo owner must be the recipient owner")]
fn m_memo_owner_mismatch() {
    let mut m = memo();
    m.owner = 0xdeadbeef;
    v(rin(), old(), SCALAR, 0, m, MEPH, change(), CEPH);
}
#[test(should_fail_with = "unexpected note version")]
fn m_memo_note_version() {
    let mut m = memo();
    m.note_version = 2;
    v(rin(), old(), SCALAR, 0, m, MEPH, change(), CEPH);
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_memo_conditions_hash() {
    let mut m = memo();
    m.conditions_hash = 1;
    v(rin(), old(), SCALAR, 0, m, MEPH, change(), CEPH);
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_memo_psi_unbound() {
    let mut m = memo();
    m.psi = m.psi + 1;
    v(rin(), old(), SCALAR, 0, m, MEPH, change(), CEPH);
}
#[test(should_fail_with = "memo parents must be hidden sentinel")]
fn m_memo_parents_forged() {
    let mut m = memo();
    m.parents = 1;
    v(rin(), old(), SCALAR, 0, m, MEPH, change(), CEPH);
}
#[test(should_fail_with = "incoming discovery tag must be even-y")]
fn m_memo_odd_y_recipient() {
    let odd = Point { x: ODD_RECIPIENT_X, y: ODD_RECIPIENT_Y };
    let mut m = memo();
    m.owner = ODD_RECIPIENT_OWNER;
    v(odd, old(), SCALAR, 0, m, MEPH, change(), CEPH);
}

#[test(should_fail_with = "note owner must be non-zero")]
fn m_change_owner_zero() {
    let mut ch = change();
    ch.owner = 0;
    v(rin(), old(), SCALAR, 0, memo(), MEPH, ch, CEPH);
}
#[test(should_fail_with = "self note must be STANDARD")]
fn m_change_note_type() {
    let mut ch = change();
    ch.note_type = 1;
    v(rin(), old(), SCALAR, 0, memo(), MEPH, ch, CEPH);
}
#[test(should_fail_with = "unexpected note version")]
fn m_change_note_version() {
    let mut ch = change();
    ch.note_version = 2;
    v(rin(), old(), SCALAR, 0, memo(), MEPH, ch, CEPH);
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_change_conditions_hash() {
    let mut ch = change();
    ch.conditions_hash = 1;
    v(rin(), old(), SCALAR, 0, memo(), MEPH, ch, CEPH);
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_change_psi_unbound() {
    let mut ch = change();
    ch.psi = ch.psi + 1;
    v(rin(), old(), SCALAR, 0, memo(), MEPH, ch, CEPH);
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_change_parents_forged() {
    let mut ch = change();
    ch.parents = 1;
    v(rin(), old(), SCALAR, 0, memo(), MEPH, ch, CEPH);
}

// Relocation: the honest sibling sequence moved into a different order-preserving choice of levels, index bits set
// to match. Absorbing the level into every tree hash is what keeps the two roots apart; without it one note proves
// membership at many indexes and Poseidon2(psi, leaf_index) mints a fresh nullifier under each.
#[test]
fn m_relocated_index_moves_root_and_nullifier() {
    let mut low = [0; TREE_DEPTH];
    low[0] = 7;
    low[1] = 11;
    let mut high = [0; TREE_DEPTH];
    high[2] = 7;
    high[3] = 11;
    let mut ch_low = change();
    ch_low.parents = 3;
    let mut ch_high = change();
    ch_high.parents = 12;
    let r = rin();
    let (nf_low, root_low, _, _, _, _, _, _, _, _) = super::main(
        super::CX,
        super::CY,
        r,
        r,
        old(),
        SCALAR,
        3,
        low,
        memo(),
        MEPH,
        ch_low,
        CEPH,
    );
    let (nf_high, root_high, _, _, _, _, _, _, _, _) = super::main(
        super::CX,
        super::CY,
        r,
        r,
        old(),
        SCALAR,
        12,
        high,
        memo(),
        MEPH,
        ch_high,
        CEPH,
    );
    assert(root_low != root_high, "relocated siblings reproduced the root");
    assert(nf_low != nf_high, "relocated index left the nullifier unchanged");
}
