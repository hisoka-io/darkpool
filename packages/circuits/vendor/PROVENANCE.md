# vendor/ provenance

Exact source of the three money-path Noir crypto libraries, vendored in-tree to remove a supply-chain risk.
Money-path deps were pinned by MUTABLE git tag with no lockfile on nargo beta.22, so a force-moved upstream tag
would silently swap a constraint-stripped circuit into a regenerated-and-green VK. These are the exact vendored
bytes; any future change is a reviewable diff in this repo's history, never a fetch-time swap.

| lib          | vendored commit                            | upstream tag           | source                                             |
| ------------ | ------------------------------------------ | ---------------------- | -------------------------------------------------- |
| noir-edwards | `e1702ab1c5888f5858310ce9c8cd25a032584de4` | `v0.2.5-hisoka.1`      | github.com/hisoka-io/noir-edwards                  |
| ecdh         | `5a72069393b6be1488511689b97c616d17954846` | `ecdh-v0.0.2-hisoka.1` | github.com/hisoka-io/zk-kit.noir (`packages/ecdh`) |
| poseidon     | `0880c371e88e583d39515fd3f877538657ac41eb` | `v0.3.0`               | github.com/noir-lang/poseidon                      |

The vendored `ecdh/Nargo.toml` edwards dependency was repointed from the mutable git tag to the sibling vendored
edwards (`edwards = { path = "../noir-edwards" }`). That is the only edit inside a vendored file, and it closes
the transitive ecdh to edwards edge. No vendored `.nr` SOURCE is modified.

## Verification (byte-identity)

`diff -r vendor/<lib>/src <fresh-clone-of-the-commit>/src` is empty for all three. VK byte-identity against the
pre-vendor manifest is the load-bearing gate (`vk-hashes.golden.json`).
