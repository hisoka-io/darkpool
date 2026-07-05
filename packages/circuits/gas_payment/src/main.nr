use ::ecdh::Point;
use ::shared::{conservation, mint, TREE_DEPTH, verify_spend};
use ::shared::note_v2::Note;

// Spend one note, pay `payment_value` of `payment_asset_id` to a relayer, mint the self change note. The
// relayer address and execution hash are public for the contract to bind but are not circuit-constrained.
fn main(
    current_timestamp: pub Field,
    payment_value: pub u128,
    payment_asset_id: pub Field,
    _relayer_address: pub Field,
    _execution_hash: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    old_note: Note,
    spend_scalar: Field,
    old_note_index: Field,
    old_note_path: [Field; TREE_DEPTH],
    change_note: Note,
    change_eph: Field,
) -> pub (Field, Field, Field, Field, Field, [Field; 7]) {
    let _ = current_timestamp;
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    mint::assert_valid_compliance_pk(compliance_pk);

    let (nullifier, computed_root) =
        verify_spend(old_note, spend_scalar, old_note_index, old_note_path);

    assert(old_note.asset_id == payment_asset_id, "old asset mismatch");
    assert(change_note.asset_id == payment_asset_id, "change asset mismatch");
    conservation::assert_conserved([old_note.value], [change_note.value], payment_value);

    let change = mint::mint_self_note(change_note, change_eph, compliance_pk);

    (nullifier, computed_root, change.leaf, change.eph_pub.x, change.eph_pub.y, change.ciphertext)
}

fn spent_note() -> Note {
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

fn change_note() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 90,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        psi: 0x2e0981a81b0e7a3152010b46fae7fe70b8ebf69b75d248a765d8fa482a34011b,
        parents: 0,
    }
}

global ASSET: Field = 0x1234567890123456789012345678901234567890;
global CX: Field = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
global CY: Field = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

// KAT: byte-identical to the TS/Solidity golden vector (payment 10, change eph 29).
#[test]
fn test_gas_payment_kat() {
    let (nf, root, leaf, epk_x, epk_y, ct) = main(
        0,
        10,
        ASSET,
        0x1111,
        0xabcdef,
        CX,
        CY,
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        change_note(),
        29,
    );
    assert(nf == 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e);
    assert(root == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
    assert(leaf == 0x082093685c087c81fc0deba24eae846875771cb24476937895c908cc50b703fc);
    assert(epk_x == 0x2290daef092cdb12c7c1d72dd140aa1025d8e8c07373278b43229b7cc0ca11a3);
    assert(epk_y == 0x19177cace783d18d1f03782c343e2223071c4f1752de2d160c4c79740bdbae20);
    assert(ct[0] == 0x2d485e329f43f0af2154f21aaa42f6a62119396dc67698bf3377aa6419b1ca54);
}

#[test(should_fail_with = "value not conserved")]
fn audit_reject_value_inflation() {
    let mut inflated = change_note();
    inflated.value = 100;
    let _ = main(
        0,
        10,
        ASSET,
        0x1111,
        0xabcdef,
        CX,
        CY,
        spent_note(),
        789,
        0,
        [0; TREE_DEPTH],
        inflated,
        29,
    );
}
