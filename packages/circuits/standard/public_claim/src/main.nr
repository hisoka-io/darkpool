mod mutation_tests;

use ::ecdh::{bjj::BJJ, ECDHTrait, Point};
use ::poseidon::poseidon2::Poseidon2;
use ::shared::{assert_subgroup_scalar, mint};
use ::shared::note::Note;
use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y};

// note_out.owner is a private witness, so the claim does not leak its destination.
fn main(
    memo_id: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    current_timestamp: pub Field,
    val: Field,
    asset_id: Field,
    timelock: Field,
    owner_x: Field,
    owner_y: Field,
    salt: Field,
    recipient_sk: Field,
    note_out: Note,
    eph: Field,
) -> pub (Field, Field, [Field; 7]) {
    let computed_id = Poseidon2::hash([val, asset_id, timelock, owner_x, owner_y, salt], 6);
    assert(computed_id == memo_id, "memo id mismatch");
    assert(
        (timelock == 0) | (current_timestamp as u64 >= timelock as u64),
        "Timelock has not expired",
    );

    assert_subgroup_scalar(recipient_sk);
    let derived = BJJ::new(recipient_sk).derive_public_key();
    assert(derived.x == owner_x, "recipient key mismatch");
    assert(derived.y == owner_y, "recipient key mismatch");

    assert(note_out.value as Field == val, "claim value mismatch");
    assert(note_out.asset_id == asset_id, "claim asset mismatch");
    assert(note_out.parents == 0, "claim output parents must be zero");

    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);
    let minted = mint::mint_self_note(note_out, eph, compliance_pk);

    (minted.leaf, minted.eph_pub.x, minted.ciphertext)
}

fn note_out() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 100,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        psi: 0x2b15d2a7e6a394714f0489affd8fcb29292b35d148d26453116782a6672edd12,
        parents: 0,
    }
}

global CX: Field = FIXTURE_COMPLIANCE_X;
global CY: Field = FIXTURE_COMPLIANCE_Y;

// KAT: byte-identical to the TS/Solidity golden vector (recipient_sk 0x3039, memo of 6 fields, eph 31).
#[test]
fn test_public_claim_kat() {
    let (leaf, epk_x, ct) = main(
        0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93,
        CX,
        CY,
        0,
        100,
        0x1234567890123456789012345678901234567890,
        0,
        0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54e,
        0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8f,
        0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4,
        0x3039,
        note_out(),
        31,
    );
    assert(leaf == 0x09a98ec0c22cfd2a253e128d36453471a20e6de6b049bc9e342c4dcfa5716fe2);
    assert(epk_x == 0x1390b1c9d9a82d2159b46c2bb964b4b2f33fce1689896c95545db5582db57f2e);
    assert(ct[0] == 0x25b192408132608596a8fcb2580b40eef0ae69bac2ddd618919bfead13c9fc22);
    assert(ct[6] == 0x1271e8440d429e8b2e2bfbe6f6cdae0c76b0238dac17d93e83c663b7d893761f);
}

#[test(should_fail_with = "recipient key mismatch")]
fn audit_reject_wrong_recipient_key() {
    let _ = main(
        0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93,
        CX,
        CY,
        0,
        100,
        0x1234567890123456789012345678901234567890,
        0,
        0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54e,
        0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8f,
        0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4,
        0x303a,
        note_out(),
        31,
    );
}

#[test(should_fail_with = "claim value mismatch")]
fn audit_reject_claim_value_inflation() {
    let mut inflated = note_out();
    inflated.value = 200;
    let _ = main(
        0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93,
        CX,
        CY,
        0,
        100,
        0x1234567890123456789012345678901234567890,
        0,
        0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54e,
        0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8f,
        0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4,
        0x3039,
        inflated,
        31,
    );
}

#[test(should_fail_with = "claim output parents must be zero")]
fn audit_reject_nonzero_parents() {
    let mut note = note_out();
    note.parents = 0x1;
    let _ = main(
        0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93,
        CX,
        CY,
        0,
        100,
        0x1234567890123456789012345678901234567890,
        0,
        0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54e,
        0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8f,
        0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4,
        0x3039,
        note,
        31,
    );
}

#[test(should_fail_with = "memo id mismatch")]
fn audit_reject_memo_id_mismatch() {
    let _ = main(
        0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f94,
        CX,
        CY,
        0,
        100,
        0x1234567890123456789012345678901234567890,
        0,
        0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54e,
        0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8f,
        0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4,
        0x3039,
        note_out(),
        31,
    );
}
