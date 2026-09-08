//! swap_intent (taker): spends A_in, mints own change + received self-notes; inner proof consumed by swap_settle's recursion.

use ::ecdh::Point;
use ::kage_lib::{build_intent, INTENT_PI_LEN, pack_intent};
use ::shared::note::Note;
use ::shared::TREE_DEPTH;

// No `pub` params: the 28-wide return is the whole PI vector; a `pub` param would break swap_settle's fixed-width verify.
fn main(
    chain_id: Field,
    darkpool_address: Field,
    compliance_pubkey_x: Field,
    compliance_pubkey_y: Field,
    note_in: Note,
    spend_scalar: Field,
    index_in: Field,
    path_in: [Field; TREE_DEPTH],
    change_note: Note,
    change_eph: Field,
    received_note: Note,
    received_eph: Field,
    to_asset: Field,
    from_amount: u128,
    expiry: Field,
) -> pub [Field; INTENT_PI_LEN] {
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    let pi = build_intent(
        chain_id,
        darkpool_address,
        compliance_pk,
        note_in,
        spend_scalar,
        index_in,
        path_in,
        change_note,
        change_eph,
        received_note,
        received_eph,
        to_asset,
        from_amount,
        expiry,
    );
    pack_intent(pi)
}

mod kat {
    use super::main;
    use ::ecdh::{bjj::BJJ, ECDHTrait, Point};
    use ::poseidon::poseidon2::Poseidon2;
    use ::shared::note::Note;
    use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y, fixture_note};
    use ::shared::TREE_DEPTH;

    global PSI_DOMAIN: Field = 0x138d495e7a5c1b3f504318dd6cfcf0a7cf7bb6d69cf9eadb049cc35d6831ef5b;
    global TO_ASSET: Field = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd;
    global SELF_OWNER: Field = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    global CHAIN_ID: Field = 31337;
    global DARKPOOL: Field = 0x3aa5ebb10dc797cac828524e59a333d0a371443c;

    fn psi_of(eph: Field, c: Point) -> Field {
        Poseidon2::hash([BJJ::new(eph).derive_shared_key(c), PSI_DOMAIN], 2)
    }

    fn self_note(asset: Field, value: u128, eph: Field, c: Point) -> Note {
        Note {
            note_version: 1,
            asset_id: asset,
            note_type: 0,
            conditions_hash: 0,
            value,
            owner: SELF_OWNER,
            psi: psi_of(eph, c),
            parents: 0,
        }
    }

    #[test]
    fn swap_intent_accepts() {
        let c = Point { x: FIXTURE_COMPLIANCE_X, y: FIXTURE_COMPLIANCE_Y };
        let change = self_note(fixture_note().asset_id, 40, 9, c);
        let received = self_note(TO_ASSET, 50, 15, c);
        let out = main(
            CHAIN_ID,
            DARKPOOL,
            c.x,
            c.y,
            fixture_note(),
            789,
            0,
            [0; TREE_DEPTH],
            change,
            9,
            received,
            15,
            TO_ASSET,
            60,
            2000000000,
        );
        assert(out[0] == 0x218015d81e0358e2a28413bf26e312ca3535f4a771d81637c331d30847afa078);
        assert(out[1] == 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e);
        assert(out[2] == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
        assert(out[3] == FIXTURE_COMPLIANCE_X);
        assert(out[4] == FIXTURE_COMPLIANCE_Y);
        assert(out[5] == fixture_note().asset_id);
        assert(out[6] == TO_ASSET);
        assert(out[7] == 60);
        assert(out[8] == 50);
        assert(out[9] == 2000000000);
    }

    #[test]
    fn deployment_domain_changes_with_chain_and_darkpool() {
        let c = Point { x: FIXTURE_COMPLIANCE_X, y: FIXTURE_COMPLIANCE_Y };
        let change = self_note(fixture_note().asset_id, 40, 9, c);
        let received = self_note(TO_ASSET, 50, 15, c);
        let expected = main(
            CHAIN_ID,
            DARKPOOL,
            c.x,
            c.y,
            fixture_note(),
            789,
            0,
            [0; TREE_DEPTH],
            change,
            9,
            received,
            15,
            TO_ASSET,
            60,
            2000000000,
        )[0];
        let other_chain = main(
            1,
            DARKPOOL,
            c.x,
            c.y,
            fixture_note(),
            789,
            0,
            [0; TREE_DEPTH],
            change,
            9,
            received,
            15,
            TO_ASSET,
            60,
            2000000000,
        )[0];
        let other_darkpool = main(
            CHAIN_ID,
            DARKPOOL + 1,
            c.x,
            c.y,
            fixture_note(),
            789,
            0,
            [0; TREE_DEPTH],
            change,
            9,
            received,
            15,
            TO_ASSET,
            60,
            2000000000,
        )[0];
        assert(expected != other_chain);
        assert(expected != other_darkpool);
    }
}
