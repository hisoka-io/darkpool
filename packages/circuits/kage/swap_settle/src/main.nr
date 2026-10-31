//! swap_settle (maker): verifies the taker's swap_intent inside, spends B_in, mints the maker's two self-notes.

use ::ecdh::Point;
use ::kage_lib::{
    INTENT_PI_LEN, INTENT_PROOF_LEN, INTENT_VK_HASH, INTENT_VK_LEN, PROOF_TYPE, settle_swap,
    unpack_intent,
};
use ::shared::note::Note;
use ::shared::TREE_DEPTH;

fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    current_timestamp: pub Field,
    verification_key: [Field; INTENT_VK_LEN],
    intent_proof: [Field; INTENT_PROOF_LEN],
    intent_public_inputs: [Field; INTENT_PI_LEN],
    maker_note_in: Note,
    maker_spend_scalar: Field,
    maker_index: Field,
    maker_path: [Field; TREE_DEPTH],
    maker_received: Note,
    maker_received_eph: Field,
    maker_change: Note,
    maker_change_eph: Field,
) -> pub (Field, Field, Field, // taker_nullifier, maker_nullifier, root
Field, Field, [Field; 7], // taker_change (relayed): leaf, eph.x, ct
Field, Field, [Field; 7], // taker_received (relayed): leaf, eph.x, ct
Field, Field, [Field; 7], // maker_received: leaf, eph.x, ct
Field, Field, [Field; 7] // maker_change: leaf, eph.x, ct
) {
    // verification_key is an untrusted solver witness; pinned only by INTENT_VK_HASH.
    std::verify_proof_with_type(
        verification_key,
        intent_proof,
        intent_public_inputs,
        INTENT_VK_HASH,
        PROOF_TYPE,
    );

    let intent = unpack_intent(intent_public_inputs);
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };

    let o = settle_swap(
        intent,
        compliance_pk,
        current_timestamp,
        maker_note_in,
        maker_spend_scalar,
        maker_index,
        maker_path,
        maker_received,
        maker_received_eph,
        maker_change,
        maker_change_eph,
    );

    (
        o.taker_nullifier, o.maker_nullifier, o.root, o.taker_change.leaf, o.taker_change.eph_pub_x,
        o.taker_change.ciphertext, o.taker_received.leaf, o.taker_received.eph_pub_x,
        o.taker_received.ciphertext, o.maker_received.leaf, o.maker_received.eph_pub.x,
        o.maker_received.ciphertext, o.maker_change.leaf, o.maker_change.eph_pub.x,
        o.maker_change.ciphertext,
    )
}

// Words 3..41 recomputed independently with the TypeScript SDK (leaf, eph.x and DEM ciphertext per output, both
// nullifiers, and the level-hashed LeanIMT root over the two input leaves).
mod kat {
    use super::main;
    use ::shared::note::Note;
    use ::shared::test_fixtures::{FIXTURE_COMPLIANCE_X, FIXTURE_COMPLIANCE_Y};
    use ::shared::TREE_DEPTH;

    global FROM_ASSET: Field = 0x1234567890123456789012345678901234567890;
    global TO_ASSET: Field = 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd;
    global SELF_OWNER: Field = 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785;
    // The taker's note A_in at index 0; the maker's B_in sits at index 1 beside it.
    global LEAF_A: Field = 0x28be7bbf15a290be8537d34ec7427b0350bdee1db99d28bc0ec8b4149a4f16b1;

    fn note(asset: Field, value: u128, psi: Field, parents: Field) -> Note {
        Note {
            note_version: 1,
            asset_id: asset,
            note_type: 0,
            conditions_hash: 0,
            value,
            owner: SELF_OWNER,
            psi,
            parents,
        }
    }

    // The 27 words swap_intent returns for the taker side of this swap (A_in 100 -> release 60, keep 40, ask 50).
    fn intent_words() -> [Field; 27] {
        [
            0x2ba8eece4e2b02cefcda23e2751f892aa061f4fdc846efe2a8458e7ba7d4a13f,
            0x17e25d7b151726cdbc7bf3bd0bff3d3d2bdf8caf4443c9afbf215e190ba01fe1,
            0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
            0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
            0x1234567890123456789012345678901234567890,
            0xabcdefabcdefabcdefabcdefabcdefabcdefabcd,
            60,
            50,
            2000000000,
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
        ]
    }

    // nargo's executor does not check the inner proof, so zero VK and proof words run the outer logic only; the
    // recursion itself is gated by the native prover test.
    #[test]
    fn swap_settle_pins_all_42_words() {
        let mut maker_path = [0; TREE_DEPTH];
        maker_path[0] = LEAF_A;
        let (taker_nf, maker_nf, root, tc_leaf, tc_eph, tc_ct, tr_leaf, tr_eph, tr_ct, mr_leaf, mr_eph, mr_ct, mc_leaf, mc_eph, mc_ct) = main(
            FIXTURE_COMPLIANCE_X,
            FIXTURE_COMPLIANCE_Y,
            1000000000,
            [0; super::INTENT_VK_LEN],
            [0; super::INTENT_PROOF_LEN],
            intent_words(),
            note(
                TO_ASSET,
                100,
                0x06ea3916a960222276ecf7338844b98b7bfbece9bfa82afe4f47a34909eaa8b4,
                0,
            ),
            789,
            1,
            maker_path,
            note(
                FROM_ASSET,
                60,
                0x1fc1420fa8dd294ee9feaa5067000d40945bdc796e47ce5dfbfa4cbb4210ef8d,
                1,
            ),
            20,
            note(
                TO_ASSET,
                50,
                0x09fb1bde9d635c97fa5a0884a8a38d961cec75db95e76629aabec8b63baec84a,
                1,
            ),
            28,
        );
        let mut got = [0; 42];
        got[0] = FIXTURE_COMPLIANCE_X;
        got[1] = FIXTURE_COMPLIANCE_Y;
        got[2] = 1000000000;
        got[3] = taker_nf;
        got[4] = maker_nf;
        got[5] = root;
        let leaves = [tc_leaf, tr_leaf, mr_leaf, mc_leaf];
        let ephs = [tc_eph, tr_eph, mr_eph, mc_eph];
        let cts = [tc_ct, tr_ct, mr_ct, mc_ct];
        for n in 0..4 {
            got[6 + 9 * n] = leaves[n];
            got[7 + 9 * n] = ephs[n];
            for j in 0..7 {
                got[8 + 9 * n + j] = cts[n][j];
            }
        }
        let want: [Field; 42] = [
            0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
            0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
            0x000000000000000000000000000000000000000000000000000000003b9aca00,
            0x2ba8eece4e2b02cefcda23e2751f892aa061f4fdc846efe2a8458e7ba7d4a13f,
            0x06ecd791557229bb84ae6be69e9110d682e7f9374755ee5d7e6208288393fbff,
            0x17e25d7b151726cdbc7bf3bd0bff3d3d2bdf8caf4443c9afbf215e190ba01fe1,
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
            0x0637adb6c7f8ff915793efab398ff370229416e2303b29ccfeda059a73755b11,
            0x28f4a492bbfdf5eed5ad1b304b95fb96040be5e4281bd288b1955f61bfac0afa,
            0x2d2e6e16f7530bf082e178ea30d33ae5b0de9b6844010318f1f2041e8fc42ac8,
            0x1c1c5dacc8f1a6877a1bbf38ab5d6413277cdb8b009456a590b1022f29681674,
            0x2fedf20c6caa1ee939777affb961048a6ad41bd640c6ce1eea77aefa880c0106,
            0x06802ef8982354a446a864d3ebbc58ff6e3a389cf18d50c28bf1af343cc1c3e0,
            0x082861e1e5bb16646d27a2786fe7f58b24ca12f9e941e522e15338826f4562b6,
            0x02a95b52a0cb8f50b47652049866a6dfe02170197b3494c1d179fc39a55db41a,
            0x2169b27f06c7e58cd045788ab94ad891299566c4274efb8da2eccdc9985a02c3,
            0x27291766aca84722142b2ac24052e388572cb7d725aff5421bfbdddefd73ce15,
            0x239a26d12954771a03d624b21a260f447412b746b66eede628a2f0af3be0a212,
            0x059d4801f52074b83e793e4c9461d1686c52340eb324ae906ee4392535da6a57,
            0x265edf876fe327b801e7769c4584f29cab5c2f24b87efaccbbef37c642011b0f,
            0x1e12ba17172adba0a00e55f6686bf495ad29ec3bb842c12332da1ce8f1011772,
            0x0a1bfa7aa29ccdcac433b768052655129d066e830ac185d271d6de5d518eb449,
            0x0d66f9b695d265d1669464d72e9ce6ba14c5a21174fee86c64c8be1ed8e02dce,
            0x158d6041a862e483266b584e2c9cc63bb784d91f06c5df75c3873499539ebdc4,
            0x06336786f549d87a592609356877a66f440ed09e1eb7ebdfc555ea98592607df,
        ];
        for i in 0..42 {
            assert(got[i] == want[i], f"settle public input {i} drifted");
        }
    }
}
