# noir-edwards

Optimized Noir implementation of Twisted Edwards curves, including Baby Jubjub.

This archive is a self-contained Noir library crate. It has no local, git, JavaScript, or Rust dependencies.

## Pinned toolchain

- Nargo/Noir: `1.0.0-beta.22`
- `noirc` commit: `c57152f91260ecdb9faad4efc20abb14b6d2ece7`
- Native Barretenberg (`bb`): `5.0.0`

Use these exact versions. Different compiler or backend versions can produce a different constraint system or
behave differently around unconstrained witness generation.

```bash
noirup -v 1.0.0-beta.22
bbup -v 5.0.0
```

Confirm the environment:

```bash
nargo --version
bb --version
```

## Build and test

Run from the archive root:

```bash
nargo compile
nargo test
```

The supplied suite contains 16 tests.

`bb` is not needed for the library's existing unit tests. It is pinned so an auditor can construct a binary
harness, generate a proof from an adversarial witness, and verify that proof with the matching backend.

## Source layout

- `src/lib.nr`: constrained curve operations, scalar multiplication, MSM, and unconstrained addition hint.
- `src/scalar_field.nr`: signed radix-16/wNAF witness generation and its binding constraints.
- `src/bjj.nr`: Baby Jubjub parameters and generator.
- `src/test.nr`: existing correctness and adversarial tests.

## Review instructions

Perform an independent, in-depth security review of the entire library. Establish the intended mathematical and constraint-system invariants from the implementation, rather than assuming that the existing tests or comments describe the complete attack surface. Prioritize the core logic and the safety of every public API.

Treat Noir-specific behavior as first-class review scope. Examine trait definitions and implementations,
generic and compile-time parameters, operator overloading, conversions, type and field semantics, standard
library calls, unconstrained execution, and the constraints emitted by the pinned compiler. Investigate defects
that arise only through interaction with the Noir standard library, compiler, ACIR generation, or Barretenberg
backend; these dependency and toolchain issues are in scope when they affect this library's security.

Do not limit the review to known or documented bug classes. Validate findings using executable tests or proof
harnesses with the exact pinned toolchain whenever possible.
