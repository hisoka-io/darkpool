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
| noir-edwards | `85543d9443050fdd730848b94f86367e4b5513b9` | `v0.2.5-hisoka.3`      | github.com/hisoka-io/noir-edwards                  |
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

**`ScalarField<64>` (noir-edwards #49): the N==64 wNAF slices are BOUND and canonical.** The N==64 branch binds
the slices to the input via `assert(hi * 2^128 + lo == x)` plus the lo/hi range bounds (`scalar_field.nr:141`,
`:106-135`), closing the #49 free-witness underconstraint: a forged decomposition encoding a different challenge
is rejected. The `frost-forgery` harness proves exactly this at both widths (`forgery_rejected_by_binding_63` and
`forgery_rejected_by_binding_64`, both `should_fail`). The non-canonical residual (a negative `hi` encoding
`V = x - p`, equal to `x` mod p, which the field equality alone accepts) is closed in `v0.2.5-hisoka.3` by
`hi.assert_max_bit_size::<128>()` (`scalar_field.nr:135`, upstream PR #53, consolidating and superseding the
earlier narrow PR #50). The upstream test `n64_rejects_negative_representative` feeds the slices of `7 - p` to
`n64_canonical_checks`, a replica of the N==64 body inside the library's test module, not to `from` itself: it
pins the rule, and deleting the bound at `:135` leaves the library suite green. The production line is held by
two other checks. The vendor-hash guard (guard 6 in `scripts/circuit-guards.sh`) freezes `scalar_field.nr`
against `VENDOR-HASHES.sha256`, and the `frost-forgery` and `psi-cek-forgery` harness mirrors carry the same
bound, with each `check-byte-identity.sh` failing if the mirrored constrained region of `from` drifts from the
vendored one. Issue #51 is a separate `dbl_internal` bug, unrelated to this slice binding.

Every live `ScalarField` is still `<63>` (`shared/src/multisig/frost.nr:28`, `vendor/ecdh/src/bjj.nr:47,57`), so
no shipped program instantiates the N==64 branch and the `.3` bound leaves every program's ACIR and VK unchanged.
The `scalarfield64` guard (fails the build on any live `<64>`) and the `scalarfield-sites` guard (pins the
`ScalarField` surface at 2 sites) stay in `scripts/circuit-guards.sh`: the N==64 path is not needed by any circuit
(every scalar we decode fits `<63>`; the FROST challenge is truncated to 248 bits for it), it is the newest code in
the library, and a width change alters every affected VK, so moving to `<64>` must remain a deliberate, reviewed
change.

The stale upstream `// TODO` at `scalar_field.nr:95` (validate that the N==64 sum is below the modulus) predates
the bounds below it; `:106-135` and the `:141` binding now implement it. It is intentionally NOT removed, because
every vendored `*.nr` is byte-frozen by the vendor-hash guard (`VENDOR-HASHES.sha256`). It is recorded here so a
future reader neither edits the vendored file to drop it nor mistakes it for an in-house hard-rule TODO.

## Verification (byte-identity)

`diff -r vendor/<lib>/src <fresh-clone-of-the-commit>/src` is empty for all three. VK byte-identity against the
pre-vendor manifest is the load-bearing gate (`vk-hashes.golden.json`).
