# vendor/ provenance

Exact source of the three money-path Noir crypto libraries, vendored in-tree to remove a supply-chain risk.
nargo 1.0.0-beta.22 has no `Nargo.lock` and no `rev=`/commit field for git dependencies, so a `tag=` pin is a
mutable pointer: a force-moved upstream tag on a cold CI cache would silently swap a constraint-stripped circuit
into a regenerated, green VK. Vendoring moves the pin out of git-ref space into this repo's own history; any
future change is a reviewable diff, never a fetch-time swap. Every circuit crate depends on these via relative
`path=`; no git dependency remains under `packages/circuits/`.

Do not edit vendored `.nr` source. Upstream fixes are re-vendored as a reviewed diff, which is the point.

| lib          | vendored commit                            | upstream tag           | source                                             |
| ------------ | ------------------------------------------ | ---------------------- | -------------------------------------------------- |
| noir-edwards | `e1702ab1c5888f5858310ce9c8cd25a032584de4` | `v0.2.5-hisoka.1`      | github.com/hisoka-io/noir-edwards                  |
| ecdh         | `5a72069393b6be1488511689b97c616d17954846` | `ecdh-v0.0.2-hisoka.1` | github.com/hisoka-io/zk-kit.noir (`packages/ecdh`) |
| poseidon     | `0880c371e88e583d39515fd3f877538657ac41eb` | `v0.3.0`               | github.com/noir-lang/poseidon                      |

The vendored `ecdh/Nargo.toml` edwards dependency was repointed from the mutable git tag to the sibling vendored
edwards (`edwards = { path = "../noir-edwards" }`). That is the only edit inside a vendored file, and it closes
the transitive ecdh to edwards edge. No vendored `.nr` source is modified.

## noir-edwards soundness notes

**`msm()` lacks the on-curve gate `mul()` has** (an unreachable gap, guarded here). `mul` calls
`assert_is_on_curve`; `msm` does not. UNREACHABLE: there are zero `msm(` call sites in our circuits.
`scripts/circuit-guards.sh` guard 2 fails the build on any `msm(` call, and msm has no `self` receiver, so it is
invoked as `Type::msm(`, never `.msm(`. Fixed upstream in PR #54 (fork tag `v0.2.5-hisoka.2`), not in this
vendored snapshot; the build guard is the mitigation.

**`ScalarField<64>` N==64 wNAF underconstraint (noir-edwards #49) is FIXED in this vendored snapshot.** The N==64
branch binds the slices via `assert(hi * 2^128 + lo == x)` plus lo/hi range bounds (`scalar_field.nr`), so a
prover cannot supply a forged decomposition. Our money paths use only `<63>` regardless, and
`scripts/circuit-guards.sh` guards 1 and 9 fail the build on a live `<64>`. The `frost-forgery` harness executably
proves both `<63>` and `<64>` reject a forged FROST challenge.

## Verification (byte-identity)

`diff -r vendor/<lib>/src <fresh-clone-of-the-commit>/src` is empty for all three. VK byte-identity against the
pre-vendor manifest is the load-bearing gate (`vk-hashes.golden.json`).
