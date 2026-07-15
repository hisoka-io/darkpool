# Vendored Noir crypto libraries

The exact source of `poseidon`, `ecdh`, and `noir-edwards`, pinned in-tree. nargo 1.0.0-beta.22 has no
`Nargo.lock` and no `rev=`/commit field for git dependencies, so a `tag=` pin is a mutable pointer: an upstream
force-move on a cold CI cache would silently swap a circuit + its verifier VK. Vendoring moves the
pin out of git-ref space and into our own version control. Commits + provenance: `PROVENANCE.md`. Every circuit
crate depends on these via relative `path=`; no git dependency remains under `packages/circuits/`.

## Two intentional, UNREACHABLE upstream gaps (CI-guarded here; fixed upstream)

1. **noir-edwards `msm()` lacks the on-curve gate `mul()` has.** UNREACHABLE: there are zero `msm(` call sites
   in our circuits (`scripts/circuit-guards.sh` guard 2 fails the build on any `msm(` call; msm has no `self`
   receiver, so it is invoked as `Type::msm(`, never `.msm(`). Fixed upstream: noir-lang/noir-edwards PR #54
   (hisoka fork tag `v0.2.5-hisoka.2`).
2. **noir-edwards `ScalarField<64>` N==64 binding is incomplete** (accepts the negative representative V = x - p).
   UNREACHABLE: every live `ScalarField` on a money path is `<63>` (`scripts/circuit-guards.sh` guards 1 + 9 fail
   the build on a live `<64>`, whether written directly or reached via an aliased/generic-propagated `ScalarField`).
   Fix in flight upstream (completion of PR #53).

Both are latent library soundness gaps, not live drains. Do NOT edit vendored source here; upstream fixes are
re-vendored as a reviewed diff (that reviewability is the point of vendoring).
