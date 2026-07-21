//! Flip one witness from the valid KAT (spend -> incoming memo + self change); guards asserted by message. Public-output fields covered at the verifier layer.

use ecdh::Point;
use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;
use shared::TREE_DEPTH;

global SCALAR: Field = 789;
global MEPH: Field = 15;
global CEPH: Field = 9;
global ASSET: Field = 0x1234567890123456789012345678901234567890;

// Odd-y recipient key (proven odd in even_y KAT, owner in owner KAT) to reach the incoming even-y tag guard;
// the wallet rolls its ephemeral until the discovery tag is even, so an odd-y in_pub must be rejected.
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
    let _ = super::main(cx, cy, r, o, s, idx, [0; TREE_DEPTH], m, meph, ch, ceph);
}

fn v(r: Point, o: Note, s: Field, idx: Field, m: Note, meph: Field, ch: Note, ceph: Field) {
    run(super::CX, super::CY, r, o, s, idx, m, meph, ch, ceph);
}

#[test]
fn m_valid_accepts() {
    v(rin(), old(), SCALAR, 0, memo(), MEPH, change(), CEPH);
}

// meph=6 -> odd-y eph_pub; psi rebound to eph=6's CEK so the psi check passes and the incoming even-y eph guard
// (mint.nr) is the assert that fires. Covers the memo eph tag path distinct from the odd-y in_pub tag test.
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
// old asset flips against the memo asset first (both must equal the spent asset).
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

// Reusing one eph reuses the CEK (two-time pad).
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

#[test(should_fail_with = "recipient key must not be the identity")]
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
#[test(should_fail_with = "recipient key not in prime-order subgroup")]
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
#[test(should_fail_with = "recipient key not in prime-order subgroup")]
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

#[test(should_fail_with = "incoming memo must be STANDARD")]
fn m_memo_note_type() {
    let mut m = memo();
    m.note_type = 1;
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
// Odd-y recipient; memo.owner co-set so the owner pin passes and the even-y guard fires.
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
