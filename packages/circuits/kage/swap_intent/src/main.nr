//! swap_intent (taker): spends A_in, mints own change + received self-notes; inner proof consumed by swap_settle's recursion.

use ::ecdh::Point;
use ::kage_lib::{build_intent, INTENT_PI_LEN, pack_intent};
use ::shared::note::Note;
use ::shared::TREE_DEPTH;

// No `pub` params: the 27-wide return is the whole PI vector; a `pub` param would break swap_settle's fixed-width verify.
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
        // out[0..8] = nullifier, root, C.x, C.y, from_asset, to_asset, from_amount, expected_return(==received.value), expiry
        assert(out[0] == 0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755e);
        assert(out[1] == 0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551);
        assert(out[2] == FIXTURE_COMPLIANCE_X);
        assert(out[3] == FIXTURE_COMPLIANCE_Y);
        assert(out[4] == fixture_note().asset_id);
        assert(out[5] == TO_ASSET);
        assert(out[6] == 60);
        assert(out[7] == 50);
        assert(out[8] == 2000000000);
        // out[9..26] = change (leaf, eph.x, ct[7]) then received (leaf, eph.x, ct[7]), recomputed with the
        // TypeScript SDK.
        let notes: [Field; 18] = [
            0x0f63d89a3b50db7c2ea72541bedf70e594c0bfdbcf274f91421375246bb2c68f,
            0x0a677185fd6cd905b6a544b1006f4b3ea4a0dd596d47cabdab76a305859d928f,
            0x2a64ecd1a565510001a4be3b38c6c62610915f6941a0f2e33f2ab960e327f28c,
            0x2487da39c75d3102e92179b6e18a91a558bb503c9eb784b3d80a10bb24631f01,
            0x2d104abee506979217f3c4499106ed8f2144676bfbcd87ee5cb8dcb9a4568f1b,
            0x208beb9124bdd6633db485f1a8fec05fe5a51dac055a19b30b3db487412c876d,
            0x26e8efa7c73ddd8647956a8d55c31890c2fa65c2e9268f3ceaa1cf7489805dc6,
            0x0679b3ef37fd71c7040a1d4fc5d55d701b9f629cc63ff1e7ade3192780d2d2ee,
            0x186a5c31e828e71e5f90dd57189b8c718fc107fecda0a132f22e705a6896c8d6,
            0x2be4f44ddb77acb745c9df0c0b8f7cad34fcbbc69e18379beba4fe7450f73292,
            0x0d2c8ddcfdd735e9fdd0d51538022ba533cfa83b81d2acec70b17f505c17f048,
            0x068ce47d657722bad36cdc4a62ea2eda509a4d750d3aed5a6217f6bac4126413,
            0x20d005ef9d502a7c74d019cdbc296762f9e869c99dedd68790d1b4512f364eed,
            0x2c95d08b6f16d6013ce1bab83111e497e933c08bb1cbe85f7e6cbc8c28f4ada3,
            0x0e9454ccf13ae61faf1d29834fcdd952fcd84a1922d932ecc8c1fe671f19c157,
            0x1283d25e8fb77781bbffc4e9e66a68d1ed0ae3baadc24b5527b830a0800a59b7,
            0x2334f5ea84be17fe4c0b551281985862af6d372b19f9d6da098d40c184d30099,
            0x1adf0a5630fed360a4526ca7027b61171ea5afee21d64e9345340c07213b99ac,
        ];
        for i in 0..18 {
            assert(out[9 + i] == notes[i], f"intent public input {i} drifted");
        }
    }
}
