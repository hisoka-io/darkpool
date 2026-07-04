use ::ecdh::Point;
use ::shared::{
    encrypt_note_for_compliance, lean_imt_inclusion_proof, Note, TREE_DEPTH, verify_spend,
};

fn main(
    merkle_root: pub Field,
    current_timestamp: pub Field,
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    note_in: Note,
    secret_in: Field,
    index_in: Field,
    path_in: [Field; TREE_DEPTH],
    preimage_in: Field,
    note_out_1: Note,
    sk_out_1: Field,
    note_out_2: Note,
    sk_out_2: Field,
    nk: Field,
) -> pub (Field, Field, Field, [Field; 7], Field, Field, [Field; 7], Field) {
    let (nullifier_in, commitment_in) = verify_spend(
        note_in,
        secret_in,
        nk,
        index_in,
        current_timestamp,
        preimage_in,
    );
    let root = lean_imt_inclusion_proof(commitment_in, index_in, path_in);
    assert(root == merkle_root);

    assert(note_in.value == note_out_1.value + note_out_2.value);
    assert(note_in.asset_id == note_out_1.asset_id);
    assert(note_in.asset_id == note_out_2.asset_id);

    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };
    let enc_1 = encrypt_note_for_compliance(note_out_1, sk_out_1, compliance_pk);
    let enc_2 = encrypt_note_for_compliance(note_out_2, sk_out_2, compliance_pk);

    (
        nullifier_in, enc_1.epk_x, enc_1.epk_y, enc_1.ciphertext, enc_2.epk_x, enc_2.epk_y,
        enc_2.ciphertext, note_in.asset_id,
    )
}

#[test]
fn test_split_smoke() {
    let merkle_root = 0x0a179299a5482960d4fba7025036e10187d940abb23f3935c5b510cf59619cf7;
    let current_timestamp = 0;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let nk = 0x00000000000000000000000000000000000000000000000000000000000001c8;

    let note_in = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003f4,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let secret_in = 0x28ac5b086973c5b4c5086623df5f60d9ffb2fa26155fdcdd44b9c85049ef8fec;
    let index_in = 2;
    let path_in = [
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0aba59c2a9ccbfef3b36e42af175c1a80ce75561fab3fb085c242d6f8b66e199,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000000,
    ];
    let preimage_in = 0;

    let note_out_1 = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out_1 = 0x00bb23254618a83067b02e833f90a901a7f5a0559324929722051d58a7b61443;

    let note_out_2 = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out_2 = 0x037cd9321c280f024e594f89c9b775d6ebc8727202b6a2fc8792beda802c335e;

    let exp_nf = 0x23028e5ff1cddfa5e79c04e25f69683a6a32def08d8399656d9ccc52dbfdaa05;
    let exp_ct1 = [
        0x00ecb7c2028e2af7ac179e48c2c6d4322f8f856a512e8c793699fae9c705003b,
        0x001d0864e4d2935c0fdedbc12fd4dc3d779f0667030e2b2682882a050ce2f4c6,
        0x00c5af508bcd167711a28dc43eb5ada8a6ce5bef8405defdede59fc2bd3b2e09,
        0x00725bb0201ac292956164d6094affaf21a5a28ed61280bbb6ee49335ed6aaed,
        0x006969e61df329b19d4c0063c48eef1941cd3e6ad74ada6bc7213d034cd7a5cd,
        0x002f951243f5ed0b54b8c6bace5e33dde03435c893abc040bd05565bad6377a1,
        0x00000000000000000000bcdb0aa3149cb3e2a2a7bc4f45f312f87f9f196fed2a,
    ];
    let exp_ct2 = [
        0x004aca314c38e8fb5125272643ca1019b3ff34500cb490428e15eb0814e8e531,
        0x00fec54f12f40834e50e14177457702ccfad1e903298dc2bc646a062242e4a29,
        0x00a9b7ba86323861e7b54a68ba537760a4c97db0c88f021ce7a6297a310fc0f7,
        0x00ba0975592b18c535ceab6eaf3463b4a7a4986671a6aa9f05b73ebae8795e1c,
        0x00ba0fac45e28f93e00973c3bcc49ce4cbe0e59ba0de215f6e3dd8f96efbbbb5,
        0x0036b1553633207e46cc89b9e47c3be60187c1523c5ba529629c1dd5a4537a93,
        0x000000000000000000008468040e8d503f30da270548980ee2bb3955e03a55ba,
    ];

    let (nf, _, _, ct1, _, _, ct2, _) = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        note_in,
        secret_in,
        index_in,
        path_in,
        preimage_in,
        note_out_1,
        sk_out_1,
        note_out_2,
        sk_out_2,
        nk,
    );

    assert(nf == exp_nf);
    assert(ct1 == exp_ct1);
    assert(ct2 == exp_ct2);
}

// A leaf index with a set bit at an empty (zero-sibling) level is non-canonical: the inclusion proof
// rejects it, so one note has exactly one spendable index (no high-bit index malleability).
#[test(should_fail_with = "non-canonical leaf index")]
fn audit_reject_noncanonical_index() {
    let merkle_root = 0x0a179299a5482960d4fba7025036e10187d940abb23f3935c5b510cf59619cf7;
    let current_timestamp = 0;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let nk = 0x00000000000000000000000000000000000000000000000000000000000001c8;

    let note_in = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003f4,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let secret_in = 0x28ac5b086973c5b4c5086623df5f60d9ffb2fa26155fdcdd44b9c85049ef8fec;
    // bit 0 is set, but level 0 is empty (sibling zero) -> non-canonical.
    let index_in = 3;
    let mut path_in = [0; 32];
    path_in[1] = 0x0aba59c2a9ccbfef3b36e42af175c1a80ce75561fab3fb085c242d6f8b66e199;
    let preimage_in = 0;

    let note_out_1 = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 40,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out_1 = 0x00bb23254618a83067b02e833f90a901a7f5a0559324929722051d58a7b61443;

    let note_out_2 = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 60,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out_2 = 0x037cd9321c280f024e594f89c9b775d6ebc8727202b6a2fc8792beda802c335e;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        note_in,
        secret_in,
        index_in,
        path_in,
        preimage_in,
        note_out_1,
        sk_out_1,
        note_out_2,
        sk_out_2,
        nk,
    );
}

// Outputs summing to more than the input (no wrap) violates conservation directly: the equality assert
// rejects minting value across a split.
#[test(should_fail)]
fn audit_reject_value_inflation() {
    let merkle_root = 0x0a179299a5482960d4fba7025036e10187d940abb23f3935c5b510cf59619cf7;
    let current_timestamp = 0;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let nk = 0x00000000000000000000000000000000000000000000000000000000000001c8;

    let note_in = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003f4,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let secret_in = 0x28ac5b086973c5b4c5086623df5f60d9ffb2fa26155fdcdd44b9c85049ef8fec;
    let index_in = 2;
    let mut path_in = [0; 32];
    path_in[1] = 0x0aba59c2a9ccbfef3b36e42af175c1a80ce75561fab3fb085c242d6f8b66e199;
    let preimage_in = 0;

    let note_out_1 = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out_1 = 0x00bb23254618a83067b02e833f90a901a7f5a0559324929722051d58a7b61443;

    let note_out_2 = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out_2 = 0x037cd9321c280f024e594f89c9b775d6ebc8727202b6a2fc8792beda802c335e;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        note_in,
        secret_in,
        index_in,
        path_in,
        preimage_in,
        note_out_1,
        sk_out_1,
        note_out_2,
        sk_out_2,
        nk,
    );
}

// Two outputs whose u128 sum wraps past 2^128 to equal the input trigger the add overflow check, not a
// silent modular wrap: value cannot be minted by splitting into overflowing outputs.
#[test(should_fail)]
fn audit_reject_conservation_overflow() {
    let merkle_root = 0x0a179299a5482960d4fba7025036e10187d940abb23f3935c5b510cf59619cf7;
    let current_timestamp = 0;
    let compliance_pubkey_x = 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
    let compliance_pubkey_y = 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

    let nk = 0x00000000000000000000000000000000000000000000000000000000000001c8;

    let note_in = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 100,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003f4,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let secret_in = 0x28ac5b086973c5b4c5086623df5f60d9ffb2fa26155fdcdd44b9c85049ef8fec;
    let index_in = 2;
    let mut path_in = [0; 32];
    path_in[1] = 0x0aba59c2a9ccbfef3b36e42af175c1a80ce75561fab3fb085c242d6f8b66e199;
    let preimage_in = 0;

    let note_out_1 = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 0x80000000000000000000000000000000,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out_1 = 0x00bb23254618a83067b02e833f90a901a7f5a0559324929722051d58a7b61443;

    let note_out_2 = Note {
        asset_id: 0x0000000000000000000000001234567890123456789012345678901234567890,
        value: 0x80000000000000000000000000000064,
        secret: 0x00000000000000000000000000000000000000000000000000000000000003e7,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        timelock: 0,
        hashlock: 0,
    };
    let sk_out_2 = 0x037cd9321c280f024e594f89c9b775d6ebc8727202b6a2fc8792beda802c335e;

    let _ = main(
        merkle_root,
        current_timestamp,
        compliance_pubkey_x,
        compliance_pubkey_y,
        note_in,
        secret_in,
        index_in,
        path_in,
        preimage_in,
        note_out_1,
        sk_out_1,
        note_out_2,
        sk_out_2,
        nk,
    );
}
