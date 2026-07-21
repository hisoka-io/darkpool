//! swap_settle (maker): verifies the taker's swap_intent inside, spends B_in, mints maker's two self-notes; on-chain
//! output = 2 nullifiers + 4 leaves + events (no terms). Constraints in kage_lib (nargo-tested); recursion call is
//! e2e-only.

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
    // verification_key is an untrusted solver witness; pinned only by INTENT_VK_HASH (see kage_lib).
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
