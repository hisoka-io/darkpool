//! Kage recursive_swap (Bob / maker / solver). Verifies Alice's pre_swap proof INSIDE the circuit, then spends
//! B_in and mints his OWN two self-notes (fromAsset received + toAsset change), enforcing both conservations
//! (kage_lib::kage_settle). One proof to the on-chain `kageSwap` entrypoint: 2 nullifiers + 4 leaves + events, NO
//! terms/assets/amounts. Alice's two notes are relayed unchanged (she minted them), so Bob cannot touch them.
//!
//! Every settlement constraint is in kage_lib and is exercised by `nargo test`. The one part not unit-testable in
//! nargo is the recursion call below -- it needs a real Alice proof + VK from bb.js, so it is validated in the
//! native-bb e2e (the prover Kage path), not here.

use ::ecdh::Point;
use ::kage_lib::{
    ALICE_PI_LEN, kage_settle, PRE_SWAP_PROOF_LEN, PRE_SWAP_VK_HASH, PRE_SWAP_VK_LEN, PROOF_TYPE,
    unpack_alice_pi,
};
use ::shared::note::Note;
use ::shared::TREE_DEPTH;

fn main(
    compliance_pubkey_x: pub Field,
    compliance_pubkey_y: pub Field,
    current_timestamp: pub Field,
    verification_key: [Field; PRE_SWAP_VK_LEN],
    alice_proof: [Field; PRE_SWAP_PROOF_LEN],
    alice_public_inputs: [Field; ALICE_PI_LEN],
    note_b_in: Note,
    spend_scalar_b: Field,
    index_b: Field,
    path_b: [Field; TREE_DEPTH],
    bob_received: Note,
    eph_breceived: Field,
    bob_change: Note,
    eph_bchange: Field,
) -> pub (Field, Field, Field, // nullifier_a, nullifier_b, root
Field, Field, [Field; 7], // alice_change (relayed): leaf, eph.x, ct
Field, Field, [Field; 7], // alice_received (relayed): leaf, eph.x, ct
Field, Field, [Field; 7], // bob_received: leaf, eph.x, ct
Field, Field, [Field; 7] // bob_change: leaf, eph.x, ct
) {
    // `verification_key` is an UNTRUSTED solver witness pinned ONLY by the hardcoded PRE_SWAP_VK_HASH constant (see
    // kage_lib). A random VK plus a malicious-circuit proof is rejected because it will not hash to that constant.
    std::verify_proof_with_type(
        verification_key,
        alice_proof,
        alice_public_inputs,
        PRE_SWAP_VK_HASH,
        PROOF_TYPE,
    );

    let alice_pi = unpack_alice_pi(alice_public_inputs);
    let compliance_pk = Point { x: compliance_pubkey_x, y: compliance_pubkey_y };

    let o = kage_settle(
        alice_pi,
        compliance_pk,
        current_timestamp,
        note_b_in,
        spend_scalar_b,
        index_b,
        path_b,
        bob_received,
        eph_breceived,
        bob_change,
        eph_bchange,
    );

    (
        o.nullifier_a, o.nullifier_b, o.root, o.alice_change.leaf, o.alice_change.eph_pub_x,
        o.alice_change.ciphertext, o.alice_received.leaf, o.alice_received.eph_pub_x,
        o.alice_received.ciphertext, o.bob_received.leaf, o.bob_received.eph_pub.x,
        o.bob_received.ciphertext, o.bob_change.leaf, o.bob_change.eph_pub.x,
        o.bob_change.ciphertext,
    )
}
