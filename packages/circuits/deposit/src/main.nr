use ::ecdh::Point;
use ::shared::mint;
use ::shared::note_v2::Note;

// Deposit is a pure self-mint: value and asset are public (the contract moves the ERC20 in the clear), the
// leaf commits the plaintext note, and eph_pub.x is the self discovery tag.
fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    note: Note,
    eph: Field,
) -> pub (Field, Field, Field, Field, Field, [Field; 7]) {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let minted = mint::mint_self_note(note, eph, compliance_pk);

    (
        minted.leaf, minted.eph_pub.x, minted.eph_pub.y, note.value as Field, note.asset_id,
        minted.ciphertext,
    )
}

fn fixture_note() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 100,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        psi: 0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731,
        parents: 0,
    }
}

// KAT: byte-identical to the TS/Solidity golden vector (sandbox gen_v2_fixtures, eph=5).
#[test]
fn test_deposit_kat() {
    let (leaf, epk_x, epk_y, value, asset, ct) = main(
        0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
        0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
        fixture_note(),
        5,
    );
    assert(leaf == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
    assert(epk_x == 0x1961ff2315812fd2f3e459a258f5ded2dde68cd35c79c8b9fb443e1860e1fbe4);
    assert(epk_y == 0x217d990737cc33efe8db5485973124fdd98c866783f0d81ffccfffe7102a9c6a);
    assert(value == 100);
    assert(asset == 0x1234567890123456789012345678901234567890);
    assert(ct[0] == 0x13e12fd48ec5eefe22cea1ccf4f29e16f8883011140afbe24dfe35a049b34f1d);
    assert(ct[6] == 0x0f0c848a687a5d761bda9b0043218db11eddbbdab55c4bec7d5dae04c89182cb);
}

#[test(should_fail_with = "note owner must be non-zero")]
fn audit_reject_zero_owner() {
    let mut note = fixture_note();
    note.owner = 0;
    let _ = main(
        0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
        0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
        note,
        5,
    );
}

#[test(should_fail_with = "psi not bound to CEK")]
fn audit_reject_unbound_psi() {
    let mut note = fixture_note();
    note.psi = note.psi + 1;
    let _ = main(
        0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
        0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
        note,
        5,
    );
}
