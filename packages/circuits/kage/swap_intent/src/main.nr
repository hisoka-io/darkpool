//! Kage swap_intent (the taker / taker). Spends A_in (fromAsset) and mints her OWN two self-notes: the fromAsset change
//! and the toAsset she wants to receive. Because the taker mints her received note herself, the maker cannot redirect or
//! shortchange it. Fully client-provable (no recursion); the maker's swap_settle verifies THIS proof inside itself.
//! The 27 public inputs are consumed by the maker's circuit as witness and never surface on-chain. Logic + the full
//! negative battery live in `kage_lib`.

use ::ecdh::Point;
use ::kage_lib::{build_intent, INTENT_PI_LEN, pack_intent};
use ::shared::note::Note;
use ::shared::TREE_DEPTH;

// swap_intent is an INNER proof (never submitted on-chain), so it has NO `pub` params: its ONLY public inputs are the
// 27-wide return, which swap_settle consumes as intent_public_inputs. compliance rides in the pack (indices
// 2,3). Making compliance a `pub` param here would inflate the real public-input vector and duplicate compliance,
// so a real swap_intent proof would fail swap_settle's 27-wide verify.
fn main(
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

    // Spends the shared fixture note (fromAsset 100, key 789, index 0) -> ties to the split/transfer golden
    // nullifier + root, so a parity drift on the shared spend path fails here too. Pins the 27-wide scalar prefix
    // layout (indices 0..8) so a public-input reorder breaks the recursion ABI here.
    #[test]
    fn swap_intent_accepts() {
        let c = Point { x: FIXTURE_COMPLIANCE_X, y: FIXTURE_COMPLIANCE_Y };
        let change = self_note(fixture_note().asset_id, 40, 9, c);
        let received = self_note(TO_ASSET, 50, 15, c);
        let out = main(
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
        assert(out[0] == 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e); // taker_nullifier
        assert(out[1] == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551); // root
        assert(out[2] == FIXTURE_COMPLIANCE_X); // compliance_x
        assert(out[3] == FIXTURE_COMPLIANCE_Y); // compliance_y
        assert(out[4] == fixture_note().asset_id); // from_asset
        assert(out[5] == TO_ASSET); // to_asset
        assert(out[6] == 60); // from_amount
        assert(out[7] == 50); // expected_return (== received.value)
        assert(out[8] == 2000000000); // expiry
    }
}
