// leaf_index range-binding regression harness (TEST-ONLY; not a production circuit).
//
// WHAT IT PROVES. `assert_parents_bound` (circuits/shared/src/common/note.nr:77-83) narrows the spend indexes
// with `indexes[i] as u32`. That cast TRUNCATES silently: `3 as u32 == (2^32 + 3) as u32`
// (`the_parents_cast_aliases` pins it). So `assert_parents_bound` contributes NOTHING to bounding the index.
//
// The same `leaf_index` witness also reaches `nullifier(psi, leaf_index)`
// (circuits/shared/src/spend.nr:18) as a RAW Field. If the index were unbounded, `k` and `2^32 + k` would
// drive the identical Merkle path -- the path only ever consumes 32 bits -- while producing two DIFFERENT
// nullifiers for one committed leaf. That is a double-spend of every note in the pool, repeatable.
//
// The sole guard is `leaf_index.to_le_bits::<32>()` inside `lean_imt_inclusion_proof`
// (circuits/shared/src/lib.nr:33). This harness pins that it holds, that it is load-bearing, and what breaks
// without it.
//
// WHY THIS HARNESS IS SHAPED DIFFERENTLY FROM frost-forgery / psi-cek-forgery. Those mirror a Noir-SOURCE
// binding and ablate it textually. Here the binding is COMPILER-EMITTED, not source-level: Noir's
// `Field::to_le_bits` only checks modulus canonicality in stdlib source; the recomposition that ties the bit
// hint to the value is emitted during ACIR generation. The binding's existence is established here by opcode
// accounting rather than by quoting a compiler dump: `nargo info` on a circuit whose only work is
// `x.to_le_bits::<N>()` reports 2N+2 ACIR opcodes for every N (18/34/66/130 at N=8/16/32/64) against a
// constant 17-opcode Brillig hint. The hint is O(1) while the constrained cost is linear in N, which is the
// signature of a per-bit range constraint plus a recomposition assert. The behavioural consequence is pinned
// directly by `real_to_le_bits_rejects_oversized` below, which drives the REAL stdlib call.
//
// and the opcode count is exactly 2N+2 for every N (8->18, 16->34, 32->66, 64->130) while the Brillig hint
// stays at 17 opcodes regardless of N -- the signature of one booleanity plus one recomposition term per bit.
// So the hint IS bound, and it cannot be ablated from Noir source. `check_binding_absent` therefore MODELS
// the compiler-emitted binding's absence by taking the bit decomposition as a parameter. That is a weaker
// construction than a textual mirror and is labelled as such; the mirrored HASHING body is still guarded
// against drift by `check-byte-identity.sh`.
//
// Read the three load-bearing tests together:
//   - the real inclusion proof rejects an out-of-range index -> real_inclusion_proof_rejects_out_of_range_index
//   - nothing else objects to one                            -> the_parents_cast_aliases
//   - and without it, one leaf yields two nullifiers         -> unbound_index_yields_two_nullifiers_for_one_leaf

use poseidon::poseidon2::Poseidon2;
use shared::{lean_imt_inclusion_proof, TREE_DEPTH};
use shared::note::{assert_parents_bound, Note, pack_parents, Parent};

// note_nullifier.nr:10-12 -- private to `shared`, reproduced here (pinned by nullifier_mirror_matches_the_kat).
fn nullifier(note_psi: Field, leaf_index: Field) -> Field {
    Poseidon2::hash([note_psi, leaf_index], 2)
}

// ---- the inclusion-proof body with the index decomposition supplied by the caller (the injection point) ----
//
// Everything below `path_bits` is copied from `lean_imt_inclusion_proof` (circuits/shared/src/lib.nr:34-47);
// `check-byte-identity.sh` fails on any drift. The ONLY deviation is that `path_bits` arrives as a parameter
// instead of `leaf_index.to_le_bits()`, which is exactly the binding being modelled away.
fn check_binding_absent<let MAX_DEPTH: u32>(
    leaf: Field,
    path_bits: [bool; MAX_DEPTH],
    siblings: [Field; MAX_DEPTH],
) -> Field {
    let mut current = leaf;

    for i in 0..MAX_DEPTH {
        let sibling = siblings[i];
        if sibling != 0 {
            let path_bit = path_bits[i] as Field;
            let left = current + path_bit * (sibling - current);
            let right = sibling + path_bit * (current - sibling);
            current = Poseidon2::hash([left, right], 2);
        } else {
            assert(!path_bits[i], "non-canonical leaf index: right child at empty level");
        }
    }
    current
}

// ---- fixtures: a depth-32 LeanIMT membership at index 1 ----

global LEAF: Field = 4;
global HONEST_INDEX: Field = 1;
// Same low 32 bits as HONEST_INDEX, so it drives the identical path but a different nullifier.
global FORGED_INDEX: Field = 4294967297; // 2^32 + 1
global PSI: Field = 0x0441d9b1006cd55062a6458b5dd1db14869f1a5c8fbc66f73032208c2b109956;

fn siblings() -> [Field; TREE_DEPTH] {
    let mut s: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    s[0] = 3;
    s
}

// Bits of HONEST_INDEX: the decomposition an attacker presents while the raw witness stays FORGED_INDEX.
fn honest_path_bits() -> [bool; TREE_DEPTH] {
    let mut b: [bool; TREE_DEPTH] = [false; TREE_DEPTH];
    b[0] = true;
    b
}

// The decomposition an attacker DERIVES from an out-of-range index: the low 32 bits, which is precisely the
// truncation `assert_parents_bound` already performs. Nothing here is chosen by hand.
fn truncated_path_bits(index: Field) -> [bool; TREE_DEPTH] {
    let low: u32 = index as u32;
    (low as Field).to_le_bits()
}

// ================= PARITY =================

// The reproduced nullifier matches the committed production KAT (note_nullifier.nr:16-21), so this harness
// attacks the protocol's nullifier and not its own arithmetic.
#[test]
fn nullifier_mirror_matches_the_kat() {
    assert(nullifier(PSI, 3) == 0x0ced8160f191dfff5c3432bc36f182188226143b294192021ea754f282075897);
}

// The modelled body reproduces the REAL inclusion proof on an honest witness, so the ablation below differs
// from production in exactly one thing: the index binding.
#[test]
fn modelled_body_matches_the_real_inclusion_proof() {
    let real = lean_imt_inclusion_proof(LEAF, HONEST_INDEX, siblings());
    let modelled = check_binding_absent(LEAF, honest_path_bits(), siblings());
    assert(real == modelled, "the modelled body must agree with production on an honest witness");
}

// ================= REJECT (production) =================

// THE production guard, exercised against the REAL circuit function -- not a mirror. An index carrying any bit
// above 2^32 cannot be decomposed into the 32 path bits, so the spend is rejected before a nullifier exists.
#[test(should_fail)]
fn real_inclusion_proof_rejects_out_of_range_index() {
    let _ = lean_imt_inclusion_proof(LEAF, FORGED_INDEX, siblings());
}

// ================= DIFFERENTIAL: nothing else objects =================

// `assert_parents_bound` is the other consumer of the index, and it is BLIND to the forgery: the `as u32`
// narrowing truncates, so an output note whose parents were packed from the honest index is accepted while
// the spend witness carries the out-of-range one. This is what makes the range check the SOLE guard.
#[test]
fn the_parents_cast_aliases() {
    let packed_from_honest = pack_parents([
        Parent { leaf_index: HONEST_INDEX as u32 },
        Parent { leaf_index: 0 },
    ]);
    let note = Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 100,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        psi: PSI,
        parents: packed_from_honest,
    };

    // The forged index is accepted by the parents binding: it narrows to the same u32.
    assert_parents_bound(note, [FORGED_INDEX, 0]);
    assert(HONEST_INDEX as u32 == FORGED_INDEX as u32, "the narrowing cast must alias");
}

// THE load-bearing differential. With the index binding modelled away, the forged decomposition drives the
// SAME Merkle root -- so membership, the parents binding and every other guard accept -- while the raw
// `leaf_index` witness feeding the nullifier is different. One committed leaf, two valid nullifiers: the note
// is spent twice. This is a drain, and the 2N+2 recomposition constraint is what prevents it.
#[test]
fn unbound_index_yields_two_nullifiers_for_one_leaf() {
    // The path bits are derived FROM the out-of-range witness, not hand-picked.
    let forged_root = check_binding_absent(LEAF, truncated_path_bits(FORGED_INDEX), siblings());
    let honest_root = lean_imt_inclusion_proof(LEAF, HONEST_INDEX, siblings());
    assert(forged_root == honest_root, "the forged index must drive the honest membership proof");

    let nf_honest = nullifier(PSI, HONEST_INDEX);
    let nf_forged = nullifier(PSI, FORGED_INDEX);
    assert(nf_honest != nf_forged, "one leaf must not yield two spendable nullifiers");
}

// ================= NOT VACUOUS =================

// The modelled body is not "accept everything": a wrong sibling still changes the root, so membership is
// genuinely enforced and the accept above is not free.
#[test]
fn modelled_body_still_rejects_a_wrong_sibling() {
    let mut bad = siblings();
    bad[0] = 0x0abc;
    let good_root = check_binding_absent(LEAF, honest_path_bits(), siblings());
    let bad_root = check_binding_absent(LEAF, honest_path_bits(), bad);
    assert(good_root != bad_root, "membership must still be enforced without the index binding");
}

// The modelled body still enforces LeanIMT canonicality: a right-child bit at an empty level is rejected
// whether or not the index is bound.
#[test(should_fail_with = "non-canonical leaf index: right child at empty level")]
fn modelled_body_still_rejects_a_right_child_at_an_empty_level() {
    let mut bits = honest_path_bits();
    bits[5] = true;
    let _ = check_binding_absent(LEAF, bits, siblings());
}

// ================= bb proving target =================

// The double-spend under the modelled-away binding as a provable circuit: `nargo execute` + `bb prove` +
// `bb verify` must produce a VERIFYING proof whose two public nullifiers differ while the root matches the
// honest membership proof. The production path is proven by rejection at execute time instead
// (`real_inclusion_proof_rejects_out_of_range_index`).
fn main(leaf: Field, honest_index: pub Field, forged_index: Field) -> pub (Field, Field, Field) {
    let root = check_binding_absent(leaf, truncated_path_bits(forged_index), siblings());
    assert(root == lean_imt_inclusion_proof(leaf, honest_index, siblings()));

    let nf_honest = nullifier(PSI, honest_index);
    let nf_forged = nullifier(PSI, forged_index);
    assert(nf_honest != nf_forged, "the forgery must produce a second nullifier");
    (root, nf_honest, nf_forged)
}
