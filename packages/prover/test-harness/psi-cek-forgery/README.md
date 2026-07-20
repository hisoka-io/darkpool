# psi/CEK forged-scalar regression harness

Test-only. Not a production circuit, not a workspace member of `packages/circuits` (deliberately outside it,
so it does not enter `nargo test` there or the circuit-guard call-site baselines).

## What it closes

Every mint binds the note's `psi` to the compliance ECDH secret:

- `assert(note.psi == psi(cek))` — `packages/circuits/shared/src/mint.nr:54`
- `cek = (eph * C).x` — `packages/circuits/shared/src/common/kem.nr:6-9`

That scalar mul decodes `eph` with `ScalarField<63>::from`, whose wNAF slices come from an **unconstrained**
hint. The width-63 binding `assert(acc - skew == x)` is the only thing forcing them to encode `eph`.

The published `eph_pub = eph * Base8` comes from a **second, independent** `ScalarField::from(eph)` call
(`mint.nr:56`). So a prover who forges only the hint inside `derive_cek` mints a note whose `psi` is keyed to
`eph_forge` while the on-chain `eph_pub` still commits to `eph`. Compliance holds `c` with `C = c*Base8` and
recovers the content key as `(c * eph_pub).x = (eph * C).x` — the honest cek. It derives a psi that is not the
note's psi, so the note is **permanently untraceable while staying fully spendable by its owner**.

`nargo test` in `packages/circuits` cannot reach this. It builds witnesses honestly, so the slices always
encode `eph` and the binding is never attacked.

## Scope: this is not a drain

`psi` is one of the 8 plaintext fields of the leaf commitment (`note.nr:42,56`) and `verify_spend` reads
`note.psi` back out of the committed note rather than re-deriving it (`spend.nr:18`). The Merkle inclusion
proof therefore pins psi for the life of the note, so one leaf can never yield two nullifiers. The forgery
defeats **compliance tracing**, not value. `psi_is_merkle_bound_not_rederived` pins that structural fact, so a
refactor that starts re-deriving psi on the spend path fails here.

## Run

```bash
cd packages/prover/test-harness/psi-cek-forgery
./check-byte-identity.sh     # the mirror still matches the vendored library
nargo test                   # the differential (11 tests)
./run-gold-standard.sh       # bb prove + verify of the ACCEPTED forgery
```

## What the tests establish

| test                                                   | establishes                                                                                                                                                                                   |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mirror_reproduces_production_kem_and_psi_kats`        | the mirrored crypto path is production-identical (reproduces the committed KEM/psi/nullifier KATs), so the rig is attacking the protocol and not its own arithmetic                           |
| `control_honest_mint_accepts_and_compliance_traces_it` | the rig accepts an honest mint and compliance recovers exactly the committed psi (not vacuous)                                                                                                |
| `compliance_cannot_rederive_the_forged_psi`            | the forged note is a REAL attack: compliance, acting correctly on the published `eph_pub`, lands on a different psi. Without this the accept path would carry no harm                         |
| `the_forged_note_remains_spendable_by_its_owner`       | untraceable AND spendable, which is what makes the binding worth having                                                                                                                       |
| `forgery_rejected_by_binding_63`                       | **production guard**: the forged decomposition is rejected                                                                                                                                    |
| `forgery_rejected_by_binding_64`                       | the vendored width-64 path also rejects it                                                                                                                                                    |
| `forged_witness_passes_every_guard_except_the_binding` | **the differential**: the forged witness passes the ENTIRE mint psi relation when the binding is absent (subgroup, on-curve, 4-bit range and the `psi not bound to CEK` assert all still run) |
| `ablated_binding_body_raises_no_objection_63`          | the mirrored body minus the binding introduces no new rejection. NOT the differential: with the `pub(crate)` split this call is causally inert on the accept side                             |
| `ablated_rig_still_accepts_an_honest_mint`             | the ablated rig is not "accept everything"                                                                                                                                                    |
| `ablated_rig_still_rejects_a_mutated_psi`              | the `psi not bound to CEK` assert is still enforced in the ablated rig                                                                                                                        |
| `psi_is_merkle_bound_not_rederived`                    | the structural reason this stops at traceability and is not a double-spend                                                                                                                    |

## Gold standard

`run-gold-standard.sh` proves the ablated forgery with native `bb` 5.0.0 and verifies it:

```
Proof verified successfully
the forged psi/CEK mint produced a VERIFYING proof under the ablated binding
```

The complement holds too: swapping `check_binding_ablated` for `check_binding` in `main` makes
`nargo execute` fail with `error: Failed constraint`. Accepted under ablation, rejected in production.

Note that the compiler independently flags the ablated hint during execution:
`This Brillig call's inputs and its return values haven't been sufficiently constrained.`
