# Kage intent forger

Test-only. Not a production circuit, not a workspace member of `packages/circuits`.

## What it closes

`swap_settle` takes the taker's intent proof and its verification key as solver-supplied witnesses and checks
them with `std::verify_proof_with_type(..., INTENT_VK_HASH, PROOF_TYPE)`. The only thing that ties that key to
`swap_intent` is the compile-time `INTENT_VK_HASH` in `kage_lib`, which barretenberg compares with the hash of
the supplied key.

A tampered key, proof or public input also breaks the inner proof against its own key, so a gate built only
from those cases stays green even if the hash comparison disappeared. This crate is the case that needs the
pin: a different, valid circuit with the same public shape (`[Field; INTENT_PI_LEN]` out, nothing else
public), whose honest `noir-recursive` proof and key have `swap_intent`'s widths. Its proof can carry any
intent vector, for example one where the maker pays 1 unit instead of the 50 the relayed note commits to.

## How it runs

`packages/prover/src/__tests__/kageRecursion.native.test.ts` (the Kage native gate, `pnpm test:native`)
compiles this crate with `nargo compile --target-dir <tmp>`, proves it with bb.js `noir-recursive`, and
asserts:

- the forged key, proof and public-input widths equal `INTENT_VK_LEN`, `INTENT_PROOF_LEN`, `INTENT_PI_LEN`, and
  its key hash differs from `INTENT_VK_HASH`;
- `swap_settle` proved natively with the forged intent fails verification, and bb's prove log reports
  `Recursive Ultra Verifier: VK Hash Mismatch`;
- `proveSwapSettle` refuses the forged intent with `IntentVkMismatchError` before any native prove.

Compiling `swap_settle` with `INTENT_VK_HASH` set to this crate's key hash makes the forged settle verify, and
the gate goes red.

```bash
cd packages/prover/test-harness/kage-intent-forger
nargo fmt --check
nargo compile
```
