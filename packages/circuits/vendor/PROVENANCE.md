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
| noir-edwards | `2f429f5416cc8c4e5d055fb90cd4b97d05973fb3` | `v0.2.5-hisoka.2`      | github.com/hisoka-io/noir-edwards                  |
| ecdh         | `5a72069393b6be1488511689b97c616d17954846` | `ecdh-v0.0.2-hisoka.1` | github.com/hisoka-io/zk-kit.noir (`packages/ecdh`) |
| poseidon     | `0880c371e88e583d39515fd3f877538657ac41eb` | `v0.3.0`               | github.com/noir-lang/poseidon                      |

The vendored `ecdh/Nargo.toml` edwards dependency was repointed from the mutable git tag to the sibling vendored
edwards (`edwards = { path = "../noir-edwards" }`). That is the only edit inside a vendored file, and it closes
the transitive ecdh to edwards edge. No vendored `.nr` source is modified.

## noir-edwards soundness notes

**`msm()` gates every input point on-curve at entry**, mirroring `mul` (`lib.nr`, the `assert_is_on_curve`
loop before the point tables; upstream PR #54, test `msm_rejects_offcurve`). There are still zero `msm(` call
sites in our circuits, so no program instantiates it; `scripts/circuit-guards.sh` guard 2 keeps it that way, so
any future use of `msm` is a deliberate, reviewed change.

**`ScalarField<64>` (noir-edwards #49): the N==64 wNAF slices are BOUND, with a narrow non-canonical residual
that is unreachable here.** The N==64 branch binds the slices to the input via `assert(hi * 2^128 + lo == x)`
plus the lo/hi range bounds (`scalar_field.nr:138`, `:106-132`), closing the #49 free-witness underconstraint:
a forged decomposition encoding a different challenge is rejected. The `frost-forgery` harness proves exactly
this at both widths (`forgery_rejected_by_binding_63` and `forgery_rejected_by_binding_64`, both `should_fail`).
RESIDUAL (incomplete-#49): the branch asserts the field equality but never `hi >= 0`, so a non-canonical
`V = x - p` (negative, `== x mod p`) still satisfies every assert, and a native-bb proof of that witness
verifies; `mul` would then multiply by `(x - p) mod l != x`. This is UNREACHABLE: no shipped circuit
instantiates `<64>`; every live `ScalarField` is `<63>` (`shared/src/multisig/frost.nr:28`,
`vendor/ecdh/src/bjj.nr:47,57`), and `scripts/circuit-guards.sh` fails the build on any live `<64>` (the
`scalarfield64` guard) and pins the whole `ScalarField` surface at 2 sites (the `scalarfield-sites` guard). The
`hi >= 0` completion is upstream noir-edwards PR #53 (consolidating and superseding the earlier narrow PR #50);
it is not part of tag `v0.2.5-hisoka.2`, so the guards above remain the mitigation. Issue #51 is a separate
`dbl_internal` bug, unrelated to this slice binding.

The stale upstream `// TODO` at `scalar_field.nr:95` predates the `:138` binding that landed below it; it is
superseded by that assert and is intentionally NOT removed, because every vendored `*.nr` is byte-frozen by the
vendor-hash guard (`VENDOR-HASHES.sha256`). It is recorded here so a future reader neither edits the vendored
file to drop it nor mistakes it for an in-house hard-rule TODO.

## Verification (byte-identity)

`diff -r vendor/<lib>/src <fresh-clone-of-the-commit>/src` is empty for all three. VK byte-identity against the
pre-vendor manifest is the load-bearing gate (`vk-hashes.golden.json`).
