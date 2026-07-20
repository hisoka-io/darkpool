# Vendored Noir crypto libraries

The exact source of `poseidon`, `ecdh`, and `noir-edwards`, pinned in-tree. nargo 1.0.0-beta.22 has no
`Nargo.lock` and no `rev=`/commit field for git dependencies, so a `tag=` pin is a mutable pointer: an upstream
force-move on a cold CI cache would silently swap a circuit and its verifier VK. Vendoring moves the pin out of
git-ref space and into our own version control. Commits and provenance: `PROVENANCE.md`. Every circuit crate
depends on these via relative `path=`; no git dependency remains under `packages/circuits/`.

Do not edit vendored `.nr` source here. Upstream fixes are re-vendored as a reviewed diff, and that
reviewability is the point of vendoring.

## Two intentional, UNREACHABLE upstream gaps (CI-guarded here; fixed upstream)

1. **noir-edwards `msm()` lacks the on-curve gate `mul()` has.** UNREACHABLE: there are zero `msm(` call sites
   in our circuits. `scripts/circuit-guards.sh` guard 2 fails the build on any `msm(` call, and msm has no
   `self` receiver, so it is invoked as `Type::msm(`, never `.msm(`. Fixed upstream: noir-lang/noir-edwards
   PR #54 (hisoka fork tag `v0.2.5-hisoka.2`).
2. **noir-edwards `ScalarField<64>` N==64 binding is incomplete** (it accepts the negative representative
   V = x - p). UNREACHABLE: every live `ScalarField` on a money path is `<63>`. `scripts/circuit-guards.sh`
   guards 1 and 9 fail the build on a live `<64>`, whether written directly or reached via an aliased or
   generic-propagated `ScalarField`. Fix in flight upstream (completion of PR #53).

Both are latent library soundness gaps, not live drains.

## Provenance summary

| Library      | Commit Hash                                | Tag                    | Source Repository                                  |
| ------------ | ------------------------------------------ | ---------------------- | -------------------------------------------------- |
| noir-edwards | `e1702ab1c5888f5858310ce9c8cd25a032584de4` | `v0.2.5-hisoka.1`      | github.com/hisoka-io/noir-edwards                  |
| ecdh         | `5a72069393b6be1488511689b97c616d17954846` | `ecdh-v0.0.2-hisoka.1` | github.com/hisoka-io/zk-kit.noir (`packages/ecdh`) |
| poseidon     | `0880c371e88e583d39515fd3f877538657ac41eb` | `v0.3.0`               | github.com/noir-lang/poseidon                      |

`ecdh/Nargo.toml` was repointed to the sibling `../noir-edwards`. No vendored `.nr` files were modified. The
byte-identity verification recipe and the load-bearing VK gate are in `PROVENANCE.md`.
