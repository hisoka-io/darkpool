//! Additive mutation harness for the `transfer_multisig` circuit (Layer-1). Prove (real 3-of-5 FROST KAT)
//! then mutate one soundness-relevant witness / signed field and require rejection with the specific guard.
//! Adds the FROST surface (gpk / R / z / m) on top of the shared open+mint+conservation surface, plus the
//! transfer-only INCOMING memo (mint_incoming_note) and recipient-key checks.
//! Guard order: assert_valid_compliance_pk -> open_multisig_note(gpk subgroup/identity, owner, note_type,
//! version/asset, membership) -> asset/ephemerals-distinct/conservation/parents -> mint_incoming_note(memo)
//! -> mint_self_note_multisig(change) -> verify_frost_spend(gpk, R, z, m).

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
fn rin() -> ecdh::Point {
    super::recipient_in_pub()
}
fn oldn() -> Note {
    super::ms_input(100)
}
fn memon() -> Note {
    super::kat_memo_note(40)
}
fn chgn() -> Note {
    super::kat_change_note(60)
}

// Valid transaction as defaults; each test overrides exactly one axis. `run` also exposes the compliance key.
fn run(
    cx: Field,
    cy: Field,
    g: ecdh::Point,
    fr: ecdh::Point,
    z: Field,
    rp: ecdh::Point,
    o: Note,
    idx: Field,
    mo: Note,
    me: Field,
    ch: Note,
    ce: Field,
) {
    let _ = super::main(
        cx,
        cy,
        g,
        fr,
        z,
        rp,
        o,
        idx,
        [0; TREE_DEPTH],
        mo,
        me,
        ch,
        ce,
    );
}
fn v(
    g: ecdh::Point,
    fr: ecdh::Point,
    z: Field,
    rp: ecdh::Point,
    o: Note,
    idx: Field,
    mo: Note,
    me: Field,
    ch: Note,
    ce: Field,
) {
    run(super::CX, super::CY, g, fr, z, rp, o, idx, mo, me, ch, ce);
}

#[test]
fn m_valid_accepts() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}

// FROST: gpk (feeds the multisig owner pin in open_multisig_note AND the FROST verify)
#[test(should_fail_with = "gpk must not be the identity")]
fn m_gpk_identity() {
    v(
        mutation::bad_identity(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail)]
fn m_gpk_off_curve() {
    v(
        mutation::bad_off_curve(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_small_order() {
    v(
        mutation::bad_small_order(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "gpk not in prime-order subgroup")]
fn m_gpk_non_subgroup() {
    v(
        mutation::bad_non_subgroup(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
// r() is a valid subgroup point but not the account gpk -> the in-circuit owner pin rejects before FROST.
#[test(should_fail_with = "spender does not own this multisig note")]
fn m_gpk_wrong_valid() {
    v(
        r(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}

// FROST: R
#[test(should_fail_with = "R must not be the identity")]
fn m_frost_r_identity() {
    v(
        gpk(),
        mutation::bad_identity(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail)]
fn m_frost_r_off_curve() {
    v(
        gpk(),
        mutation::bad_off_curve(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
// R carries only on-curve + non-identity checks; a non-subgroup R must still fail the signature equation.
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_r_non_subgroup() {
    v(
        gpk(),
        mutation::bad_non_subgroup(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_r_mutated() {
    v(
        gpk(),
        gpk(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}

// FROST: z + challenge/message binding (ScalarField<63> is derived, not a free witness)
#[test(should_fail_with = "scalar must be non-zero")]
fn m_frost_z_zero() {
    v(
        gpk(),
        r(),
        0,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_frost_z_ge_suborder() {
    v(
        gpk(),
        r(),
        SUBORDER,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "FROST signature invalid")]
fn m_frost_z_mutated() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z + 1,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
// transfer's m carries no free public scalar; a value-conserving swap (41 + 59 == 100) shifts the memo/change
// LEAVES that m binds, so control reaches verify_frost_spend and the recomputed challenge rejects. Confirms
// the ScalarField<63> challenge binds m (the truncation FOOTGUN guard in frost.nr).
#[test(should_fail_with = "FROST signature invalid")]
fn m_signed_value_swap() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        super::kat_memo_note(41),
        super::KAT_MEMO_EPH,
        super::kat_change_note(59),
        super::KAT_CHANGE_EPH,
    );
}

// spent multisig note (open_multisig_note membership)
#[test(should_fail_with = "spender does not own this multisig note")]
fn m_old_owner_mutated() {
    let mut o = oldn();
    o.owner = o.owner + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        o,
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "unexpected note type")]
fn m_old_note_type() {
    let mut o = oldn();
    o.note_type = 0;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        o,
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_old_note_version() {
    let mut o = oldn();
    o.note_version = 2;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        o,
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
// asset_id stays a valid 20-byte value (passes assert_asset_id) but breaks old==memo before the mints.
#[test(should_fail_with = "memo asset mismatch")]
fn m_old_asset_mismatch() {
    let mut o = oldn();
    o.asset_id = super::ASSET_ID + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        o,
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "non-canonical leaf index")]
fn m_noncanonical_leaf_index() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        7,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}

// asset binding of the two outputs
#[test(should_fail_with = "change asset mismatch")]
fn m_change_asset_mismatch() {
    let mut ch = chgn();
    ch.asset_id = super::ASSET_ID + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        ch,
        super::KAT_CHANGE_EPH,
    );
}

// value conservation / overflow
#[test(should_fail_with = "value not conserved")]
fn m_value_not_conserved() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        super::kat_memo_note(41),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "attempt to add with overflow")]
fn m_value_output_overflow() {
    let mut ch = chgn();
    ch.value = 0xffffffffffffffffffffffffffffffff;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        super::kat_memo_note(1),
        super::KAT_MEMO_EPH,
        ch,
        super::KAT_CHANGE_EPH,
    );
}

// ephemerals must be distinct
#[test(should_fail_with = "ephemerals must be distinct")]
fn m_ephemerals_equal() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_MEMO_EPH,
    );
}

// minted INCOMING memo note (mint_incoming_note)
#[test(should_fail_with = "incoming memo must be STANDARD")]
fn m_memo_note_type() {
    let mut mo = memon();
    mo.note_type = 2;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        mo,
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "memo owner must be the recipient owner")]
fn m_memo_owner_mismatch() {
    let mut mo = memon();
    mo.owner = mo.owner + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        mo,
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_memo_note_version() {
    let mut mo = memon();
    mo.note_version = 2;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        mo,
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_memo_conditions_hash() {
    let mut mo = memon();
    mo.conditions_hash = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        mo,
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_memo_psi_unbound() {
    let mut mo = memon();
    mo.psi = mo.psi + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        mo,
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_memo_parents_forged() {
    let mut mo = memon();
    mo.parents = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        mo,
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
// Odd-y recipient key (odd proven in even_y::test_is_even_y_kat; its owner proven in owner::kat_pubkey_owner):
// it passes note-type / subgroup / owner / psi, so the incoming discovery-tag even-y assert is what rejects.
#[test(should_fail_with = "incoming discovery tag must be even-y")]
fn m_memo_incoming_odd_y() {
    let odd = ecdh::Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    let mut mo = memon();
    mo.owner = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        odd,
        oldn(),
        0,
        mo,
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}

// minted multisig CHANGE note (mint_self_note_multisig)
#[test(should_fail_with = "multisig self note must be MULTISIG")]
fn m_change_note_type_standard() {
    let mut ch = chgn();
    ch.note_type = 0;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "multisig change/self must be owned by the account gpk")]
fn m_change_owner_off_gpk() {
    let mut ch = chgn();
    ch.owner = ch.owner + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_change_note_version() {
    let mut ch = chgn();
    ch.note_version = 2;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_change_conditions_hash() {
    let mut ch = chgn();
    ch.conditions_hash = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_change_psi_unbound() {
    let mut ch = chgn();
    ch.psi = ch.psi + 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        ch,
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "output parents not bound to consumed inputs")]
fn m_change_parents_forged() {
    let mut ch = chgn();
    ch.parents = 1;
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        ch,
        super::KAT_CHANGE_EPH,
    );
}

// recipient key: BJJ curve-op entry (mint_incoming_note::assert_valid_recipient_key)
#[test(should_fail_with = "recipient key must not be the identity")]
fn m_recipient_identity() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        mutation::bad_identity(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail)]
fn m_recipient_off_curve() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        mutation::bad_off_curve(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "recipient key not in prime-order subgroup")]
fn m_recipient_small_order() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        mutation::bad_small_order(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "recipient key not in prime-order subgroup")]
fn m_recipient_non_subgroup() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        mutation::bad_non_subgroup(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}

// compliance key: BJJ curve-op entry (assert_valid_compliance_pk)
#[test(should_fail_with = "compliance key must not be the identity")]
fn m_compliance_identity() {
    let p = mutation::bad_identity();
    run(
        p.x,
        p.y,
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
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
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}

// ephemeral scalars (memo_eph, change_eph)
#[test(should_fail_with = "scalar must be non-zero")]
fn m_memo_eph_zero() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        0,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_memo_eph_ge_suborder() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        SUBORDER,
        chgn(),
        super::KAT_CHANGE_EPH,
    );
}
#[test(should_fail_with = "scalar must be non-zero")]
fn m_change_eph_zero() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        0,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_change_eph_ge_suborder() {
    v(
        gpk(),
        r(),
        super::KAT_FROST_Z,
        rin(),
        oldn(),
        0,
        memon(),
        super::KAT_MEMO_EPH,
        chgn(),
        SUBORDER,
    );
}
