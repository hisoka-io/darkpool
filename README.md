# Hisoka Darkpool Protocol

Private transactions on EVM. Compliant by default.

Tokens are locked into shielded UTXO notes and spent with zero-knowledge proofs. The contract never learns
who owns what: ownership is proven in-circuit, so the on-chain surface only verifies proofs, tracks
nullifiers, and appends to a Merkle tree. Transactions can be relayed through a
[mixnet](https://github.com/hisoka-io/nox), swaps settle inside the pool without revealing either side, and
compliance runs through a threshold-decryption key held by a committee quorum.

## How it works

A note is a commitment to eight plaintext fields, hashed with Poseidon2 into a depth-32 append-only Merkle
tree. Spending proves, in-circuit, knowledge of the BabyJubJub scalar behind the note's owner field, and
publishes one nullifier per note so it cannot be spent twice. Note contents are encrypted to the recipient
with an ECDH-derived key and a Poseidon2 stream, with no AES anywhere in the pipeline. The same ECDH key is
wrapped to a rotatable threshold compliance key, so a quorum of committee members can decrypt what a
recipient can, and no single member can.

Group-owned accounts spend with an in-circuit FROST threshold Schnorr signature over BabyJubJub, so a
t-of-n group produces one signature and the circuit verifies it like any other spend.

## Packages

| Package                                 | What it does                                                                                                       |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| [circuits](packages/circuits)           | 13 Noir crates: 6 standard (deposit, withdraw, transfer, split, join, public claim), 4 FROST-multisig, 3 Kage swap |
| [wallets](packages/wallets)             | Note format, key derivation, scanning, FROST signing. Poseidon2, BabyJubJub, Poseidon2 stream cipher               |
| [prover](packages/prover)               | UltraHonk proving via bb.js, plus native bb for the Kage recursive proof                                           |
| [adaptors](packages/adaptors)           | DeFi intent encoding (Uniswap V3)                                                                                  |
| [evm-contracts](packages/evm-contracts) | DarkPool (UUPS), ComplianceRegistry, BundleExecutor, MerkleTreeLib, Nox contracts, 11 generated verifiers          |

## Quick start

- Node 20
- pnpm 10
- [Nargo 1.0.0-beta.22](https://noir-lang.org)
- [Foundry](https://getfoundry.sh)

```bash
just setup    # install deps, check toolchain
just build    # compile circuits + contracts + ts
just test     # run everything
```

Circuit changes require regenerating the verifiers, since each verifier pins its circuit's verification-key
hash and the contract rejects a proof from a circuit it was not generated for.

## Security

Circuit soundness is the security boundary: `DarkPool.sol` has no `msg.sender` ownership checks, so every
constraint is load-bearing. The suite reflects that. Each circuit ships a mutation harness that mutates a
valid witness and asserts the constraint system rejects it. The frozen seams (verification-key manifest,
public-input layout, tree depth) are pinned by tests that fail on drift. The crypto libraries are vendored
in-tree at audited commits, so a moved upstream tag cannot silently change a circuit.

This code has not had an external audit. Do not use it with real funds.

## Related repos

- [nox](https://github.com/hisoka-io/nox) · mixnet
- [nox-sdk](https://github.com/hisoka-io/nox-sdk) · client SDK
- [docs](https://docs.hisoka.io) · protocol documentation

## License

[Apache 2.0](LICENSE)
