# FROST forged-scalar regression harness

Test-only. Not a production circuit, not a workspace member of `packages/circuits` (deliberately outside it,
so it does not enter `nargo test` there or the circuit-guard call-site baselines).

## What it closes

`verify_frost_spend` (`packages/circuits/shared/src/multisig/frost.nr:29`) decodes the Schnorr challenge with
`ScalarField<63>::from(e)`. The wNAF slices come from an **unconstrained** hint, so a prover picks them
freely. The width-63 binding `assert(acc - skew == x)` is the only thing forcing them to encode the true `e`.

Without that binding, a forger who knows no secret picks any `z` and any `e_forge`, sets
`R = z*Base8 - e_forge*gpk`, and `z*Base8 == R + e_forge*gpk` holds by construction: a valid-looking FROST
signature on any message, i.e. a drain of any multisig account.

`nargo test` in `packages/circuits` cannot reach this. It builds witnesses honestly, so the slices always
encode `e` and the binding is never attacked. This harness attacks it at the layer where a real attacker
lives: witness generation.

## Run

```bash
cd packages/prover/test-harness/frost-forgery
./check-byte-identity.sh     # the mirror still matches the vendored library
nargo test                   # the differential (7 tests)
./run-gold-standard.sh       # bb prove + verify of the ACCEPTED forgery
```

## What the tests establish

| test                                                   | establishes                                                                                                                                                                                   |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `control_honest_kat_accepts_under_binding_63`          | the rig accepts a genuine 3-of-5 FROST signature (not vacuous)                                                                                                                                |
| `control_forged_r_fails_under_the_honest_scalar`       | the forged `R` is a REAL forgery: under the honest scalar it fails `FROST signature invalid`, so the forger holds no signature. Without this the accept-path would be circular                |
| `forgery_rejected_by_binding_63`                       | **production guard**: the forged decomposition is rejected                                                                                                                                    |
| `forgery_rejected_by_binding_64`                       | the vendored width-64 path also rejects it (its `assert(hi*2^128+lo==x)` binds mod p)                                                                                                         |
| `forged_witness_passes_every_guard_except_the_binding` | **the differential**: the forged witness passes the ENTIRE relation when the binding is absent (subgroup, on-curve, identity, scalar range, 4-bit range and the group equation all still run) |
| `ablated_binding_body_raises_no_objection_63`          | the mirrored body minus the binding introduces no new rejection. NOT the differential: with the pub(crate) split this call is causally inert on the accept side                               |
| `ablated_rig_still_accepts_the_honest_kat`             | the ablated rig is not "accept everything"                                                                                                                                                    |
| `ablated_rig_still_rejects_a_mutated_z`                | the group equation is still enforced in the ablated rig                                                                                                                                       |

The rejection is at the binding assert specifically, not incidental. Re-running the reject case without
`should_fail` prints:

```
error: Failed constraint
   ┌─ src/main.nr:94:9
94 │         assert(acc - skew as Field == x);
   = Call stack:
     2: check_binding at src/main.nr:94:9
```

Gold standard for the accept path (bb 5.0.0, UltraHonk):

```
nargo execute -> Circuit witness successfully solved
bb write_vk / prove / verify -> "Proof verified successfully"  (exit 0)
```

Public inputs of that proof are the group key and the message. What this establishes, precisely: the forged
witness is satisfiable and provable end to end on the real proving stack, not merely accepted by the test
interpreter. It does NOT by itself carry the differential -- `main` derives `R` internally, so its group
equation holds by construction. The differential lives in the tests above; this run rules out "the ACVM was
lenient".

## Anti-drift

`check_binding` mirrors the constrained region of `From<Field> for ScalarField<N>::from`
(`packages/circuits/vendor/noir-edwards/src/scalar_field.nr:87-142`). A mirror that silently desyncs from the
real `from` proves nothing, so `check-byte-identity.sh` re-derives the vendored region and fails on drift. It
caught a real error during development (an `hi.assert_max_bit_size::<128>()` line that exists on the
noir-edwards fork branch but is **not** in the vendored code). It also pins that `check_binding_ablated`
differs from `check_binding` by exactly the two binding asserts, so the "only the binding was removed" premise
cannot rot (verified load-bearing: weakening a range check inside the twin is caught). The prior `edw-sf64`
harness had no such guard; this is the improvement over it.

## Honest caveats

- **The pub(crate) split.** `ScalarField`'s fields are `pub(crate)` to edwards, so an external crate cannot
  hand forged slices to edwards' `mul`. Production's single `from(e)`-with-a-malicious-hint is therefore split
  into (a) the byte-identical binding constraints run against `e` over the forged decomposition, and (b) `mul`
  consuming a scalar built by an honest `from(e_forge)`. Same scalar reaches `mul`, same constraints decide
  accept/reject. The extra honest binding in (b) is satisfied in every variant and does not affect the
  differential. A consequence, stated plainly: on the ACCEPT side the ablated-body call is causally inert --
  deleting it would not change the outcome. That is why the differential is
  `forged_witness_passes_every_guard_except_the_binding` (binding absent, every other guard live) rather than
  the ablated-body test. Closing the split fully would need a test hook inside the vendored crate, out of bounds.
- **The ablation is the differential, not `<64>`.** The task framing assumed width-64 is the "no binding"
  path. That was true of upstream noir-edwards v0.2.5, but the vendored copy carries PR#53's
  `assert(hi*2^128+lo==x)`, so `<64>` now rejects the forgery too. The true no-binding comparison is the
  ablated body, which is what the differential uses.
- The accept path is proven for the ablated body. The production body is proven by rejection at execute time
  (the ACVM enforces constraints during solving), so there is no proof to generate for it.
- The two REJECT tests use bare `should_fail`. The mirrored assert carries no message (the vendored one does
  not either, and adding one would break the byte-identity guard), so the cause is pinned by
  `forged_witness_passes_every_guard_except_the_binding` -- if a future edit moved the rejection to some other
  constraint, that test would start failing.
