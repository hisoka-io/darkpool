# leaf_index range-binding regression harness

Test-only. Not a production circuit, not a workspace member of `packages/circuits`.

## What it closes

`assert_parents_bound` (`packages/circuits/shared/src/common/note.nr:77-83`) narrows the spend indexes with
`indexes[i] as u32`. That cast **truncates silently**: `3 as u32 == (2^32 + 3) as u32`. So the parents binding
contributes nothing to bounding the index — `the_parents_cast_aliases` pins this against the real function.

The same `leaf_index` witness reaches `nullifier(psi, leaf_index)` (`spend.nr:18`) as a **raw Field**. If the
index were unbounded, `k` and `2^32 + k` would drive the identical Merkle path (the path only ever consumes 32
bits) while producing two different nullifiers for one committed leaf — a repeatable double-spend of every
note in the pool.

The sole guard is `leaf_index.to_le_bits::<32>()` inside `lean_imt_inclusion_proof`
(`packages/circuits/shared/src/lib.nr:33`).

## Why this harness is shaped differently from the other two

`frost-forgery` and `psi-cek-forgery` mirror a Noir-**source** binding and ablate it textually. Here the
binding is **compiler-emitted**. Noir's `Field::to_le_bits` only checks modulus canonicality in stdlib source;
the recomposition tying the bit hint to the value is emitted during ACIR generation. `nargo compile
--show-ssa` on `x.to_le_bits::<8>()` emits, verbatim:

```
BRILLIG CALL func: 0, predicate: 1, inputs: [w0, 8, 2], outputs: [[w9..w16]]   <- the unconstrained hint
BLACKBOX::RANGE input: w9..w16, bits: 1                                        <- booleanity per bit
ASSERT w9 = w0 - 2*w10 - 4*w11 - 8*w12 - 16*w13 - 32*w14 - 64*w15 - 128*w16
    // "Field failed to decompose into specified 8 limbs"                      <- THE BINDING
```

and the opcode count is exactly `2N+2` for every N (8→18, 16→34, 32→66, 64→130) while the Brillig hint stays
at 17 opcodes regardless of N — one booleanity plus one recomposition term per bit.

So the hint **is** bound, and it cannot be ablated from Noir source. `check_binding_absent` therefore _models_
the binding's absence by taking the decomposition as a parameter. That is a weaker construction than a textual
mirror and is labelled as such throughout. The mirrored **hashing** body is still guarded against drift.

## Run

```bash
cd packages/prover/test-harness/leaf-index-forgery
./check-byte-identity.sh     # mirror matches lean_imt_inclusion_proof AND the real binding is still present
nargo test                   # the differential (7 tests)
./run-gold-standard.sh       # bb prove + verify of the ACCEPTED double-spend
```

## What the tests establish

| test                                                          | establishes                                                                                                        |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `nullifier_mirror_matches_the_kat`                            | the reproduced nullifier matches the committed production KAT                                                      |
| `modelled_body_matches_the_real_inclusion_proof`              | the modelled body agrees with the real function on an honest witness, so the ablation differs in exactly one thing |
| `real_inclusion_proof_rejects_out_of_range_index`             | **production guard**, exercised against the REAL circuit function, not a mirror                                    |
| `the_parents_cast_aliases`                                    | **the differential**: `assert_parents_bound` accepts the out-of-range index, so the range check is the sole guard  |
| `unbound_index_yields_two_nullifiers_for_one_leaf`            | **the consequence**: path bits derived from the forged index reproduce the honest root while the nullifier differs |
| `modelled_body_still_rejects_a_wrong_sibling`                 | membership is genuinely enforced without the index binding (not vacuous)                                           |
| `modelled_body_still_rejects_a_right_child_at_an_empty_level` | LeanIMT canonicality still enforced                                                                                |

## Anti-drift guard

`check-byte-identity.sh` has two branches, both verified to fire:

1. the mirrored hashing body drifting from `lean_imt_inclusion_proof`;
2. the real circuit no longer binding `leaf_index` via `to_le_bits` — if a refactor removes it, the modelled
   double-spend becomes live and the guard fails loudly.

## Gold standard

```
Circuit output: (root, nf_honest, nf_forged)
  = (0x266d452e..., 0x0bd9fc13..., 0x27b72004...)
Proof verified successfully
the double-spend produced a VERIFYING proof with the index binding modelled away
```

Two distinct nullifiers under one root, in a proof that verifies.
