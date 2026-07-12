//! Additive mutation harness for the `public_claim` circuit (Layer-1, constraint-level). Prove-then-mutate-
//! then-reject: from the valid KAT witness, flip ONE soundness-relevant asserted witness and require the
//! constraint system to reject with the SPECIFIC guard message (a wrong-reason failure would not match
//! `should_fail_with`, so a test only passes if the intended guard fired). This circuit is a public/
//! conditional-memo claim, structurally unlike the spend circuits: it binds a memo commitment (memo_id =
//! Poseidon2 over val/asset/timelock/owner-point/salt), a maturity timelock vs current_timestamp, and the
//! recipient's spend authority (recipient_sk -> owner point), before minting the claimed self-note. No
//! circuit logic is touched.

use poseidon::poseidon2::Poseidon2;
use shared::mutation;
use shared::note::Note;
use shared::SUBORDER;

// Valid KAT witness (byte-identical to the golden vector in main.nr's test_public_claim_kat).
global MEMO_ID: Field = 0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93;
global VAL: Field = 100;
global ASSET: Field = 0x1234567890123456789012345678901234567890;
global TIMELOCK: Field = 0;
global OWNER_X: Field = 0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54e;
global OWNER_Y: Field = 0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8f;
global SALT: Field = 0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4;
global RECIPIENT_SK: Field = 0x3039;
global EPH: Field = 31;

fn note() -> Note {
    super::note_out()
}

fn memo(val: Field, asset: Field, timelock: Field, ox: Field, oy: Field, salt: Field) -> Field {
    Poseidon2::hash([val, asset, timelock, ox, oy, salt], 6)
}

// Full-arg runner with the valid KAT as defaults; each test overrides exactly one witness (or, for the
// memo-bound fields, a coordinated pair so the intended downstream guard is the one that fires).
fn run(
    memo_id: Field,
    cx: Field,
    cy: Field,
    ts: Field,
    val: Field,
    asset: Field,
    timelock: Field,
    ox: Field,
    oy: Field,
    salt: Field,
    sk: Field,
    n: Note,
    eph: Field,
) {
    let _ = super::main(
        memo_id,
        cx,
        cy,
        ts,
        val,
        asset,
        timelock,
        ox,
        oy,
        salt,
        sk,
        n,
        eph,
    );
}

fn valid() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}

#[test]
fn m_valid_accepts() {
    valid();
}

// Boundary accept: a matured timelock (current_timestamp == timelock) with a memo that commits to it.
#[test]
fn m_timelock_matured_accepts() {
    let id = memo(VAL, ASSET, 1000, OWNER_X, OWNER_Y, SALT);
    run(
        id,
        super::CX,
        super::CY,
        1000,
        VAL,
        ASSET,
        1000,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}

// memo binding: memo_id = Poseidon2([val, asset, timelock, owner_x, owner_y, salt])
// Mutating any single committed field while holding memo_id fixed breaks the FIRST guard.
#[test(should_fail_with = "memo id mismatch")]
fn m_memo_id_mutated() {
    run(
        MEMO_ID + 1,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "memo id mismatch")]
fn m_memo_val_field() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL + 1,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "memo id mismatch")]
fn m_memo_asset_field() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET + 1,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "memo id mismatch")]
fn m_memo_timelock_field() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        5,
        VAL,
        ASSET,
        1,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "memo id mismatch")]
fn m_memo_owner_x_field() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X + 1,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "memo id mismatch")]
fn m_memo_owner_y_field() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y + 1,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "memo id mismatch")]
fn m_memo_salt_field() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT + 1,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}

// timelock maturity: reject a premature claim (current_timestamp < timelock) with a matching memo
#[test(should_fail_with = "Timelock has not expired")]
fn m_timelock_premature() {
    let id = memo(VAL, ASSET, 1000, OWNER_X, OWNER_Y, SALT);
    run(
        id,
        super::CX,
        super::CY,
        999,
        VAL,
        ASSET,
        1000,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}

// recipient spend authority: recipient_sk -> owner point
#[test(should_fail_with = "scalar must be non-zero")]
fn m_recipient_sk_zero() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        0,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_recipient_sk_ge_suborder() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        SUBORDER,
        note(),
        EPH,
    );
}
// A valid-but-wrong scalar derives a different point than the committed owner.
#[test(should_fail_with = "recipient key mismatch")]
fn m_recipient_sk_wrong() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK + 1,
        note(),
        EPH,
    );
}

// owner-point binding: even with a forged (matching) memo, the point must equal derive(recipient_sk)
#[test(should_fail_with = "recipient key mismatch")]
fn m_owner_x_rebound() {
    let id = memo(VAL, ASSET, TIMELOCK, OWNER_X + 1, OWNER_Y, SALT);
    run(
        id,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X + 1,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "recipient key mismatch")]
fn m_owner_y_rebound() {
    let id = memo(VAL, ASSET, TIMELOCK, OWNER_X, OWNER_Y + 1, SALT);
    run(
        id,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y + 1,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}

// claimed note reconstruction: note_out must restate the memo-committed value/asset and carry no parents -
#[test(should_fail_with = "claim value mismatch")]
fn m_claim_value_mismatch() {
    let mut n = note();
    n.value = VAL as u128 + 1;
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        n,
        EPH,
    );
}
#[test(should_fail_with = "claim asset mismatch")]
fn m_claim_asset_mismatch() {
    let mut n = note();
    n.asset_id = ASSET + 1;
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        n,
        EPH,
    );
}
#[test(should_fail_with = "claim output parents must be zero")]
fn m_claim_parents_nonzero() {
    let mut n = note();
    n.parents = 1;
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        n,
        EPH,
    );
}

// minted self-note guards (mint_self_note / mint_common)
#[test(should_fail_with = "self note must be STANDARD")]
fn m_note_type_not_standard() {
    let mut n = note();
    n.note_type = 1;
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        n,
        EPH,
    );
}
#[test(should_fail_with = "note owner must be non-zero")]
fn m_note_owner_zero() {
    let mut n = note();
    n.owner = 0;
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        n,
        EPH,
    );
}
#[test(should_fail_with = "unexpected note version")]
fn m_note_version() {
    let mut n = note();
    n.note_version = 2;
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        n,
        EPH,
    );
}
#[test(should_fail_with = "note conditions_hash must be zero")]
fn m_note_conditions_hash() {
    let mut n = note();
    n.conditions_hash = 1;
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        n,
        EPH,
    );
}
#[test(should_fail_with = "psi not bound to CEK")]
fn m_note_psi_unbound() {
    let mut n = note();
    n.psi = n.psi + 1;
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        n,
        EPH,
    );
}

// ephemeral scalar (feeds the compliance ECDH mul)
#[test(should_fail_with = "scalar must be non-zero")]
fn m_eph_zero() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        0,
    );
}
#[test(should_fail_with = "scalar not in BabyJubJub prime-order subgroup")]
fn m_eph_ge_suborder() {
    run(
        MEMO_ID,
        super::CX,
        super::CY,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        SUBORDER,
    );
}

// compliance key: BJJ curve-op entry (identity / off-curve / small-order / non-subgroup)
#[test(should_fail_with = "compliance key must not be the identity")]
fn m_compliance_identity() {
    let p = mutation::bad_identity();
    run(
        MEMO_ID,
        p.x,
        p.y,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail)]
fn m_compliance_off_curve() {
    let p = mutation::bad_off_curve();
    run(
        MEMO_ID,
        p.x,
        p.y,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_small_order() {
    let p = mutation::bad_small_order();
    run(
        MEMO_ID,
        p.x,
        p.y,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
#[test(should_fail_with = "compliance key not in prime-order subgroup")]
fn m_compliance_non_subgroup() {
    let p = mutation::bad_non_subgroup();
    run(
        MEMO_ID,
        p.x,
        p.y,
        0,
        VAL,
        ASSET,
        TIMELOCK,
        OWNER_X,
        OWNER_Y,
        SALT,
        RECIPIENT_SK,
        note(),
        EPH,
    );
}
