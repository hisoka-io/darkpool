# Hisoka Darkpool Protocol

Private transactions on EVM. Compliant by default.

Hisoka privatizes all on-chain interactions, metadata, and transactions. Tokens are locked into shielded UTXO notes and spent using zero-knowledge proofs. Transactions are relayed through a [mixnet](https://github.com/hisoka-io/nox), private DeFi is executed by a solver network baked into the pool, and compliance is built into the protocol via threshold compliance and selective disclosure.

## Packages

| Package                                 | What it does                                                                           |
| --------------------------------------- | -------------------------------------------------------------------------------------- |
| [circuits](packages/circuits)           | Noir ZK circuits · deposit, withdraw, transfer, split, join, public claim, gas payment |
| [wallets](packages/wallets)             | Crypto primitives · Poseidon2, BabyJubJub, AES-128-CBC, key derivation                 |
| [prover](packages/prover)               | UltraHonk proof generation via bb.js                                                   |
| [adaptors](packages/adaptors)           | DeFi intent encoding (Uniswap V3)                                                      |
| [evm-contracts](packages/evm-contracts) | Solidity · DarkPool, NoxRegistry, NoxRewardPool, RelayerMulticall, verifiers           |

## Quick start

- Node 18+
- pnpm 10
- [Nargo 1.0.0-beta.19](https://noir-lang.org)
- [Foundry](https://getfoundry.sh)

```bash
just setup    # install deps, check toolchain
just build    # compile circuits + contracts + ts
just test     # run everything
```

## Related repos

- [nox](https://github.com/hisoka-io/nox) · mixnet
- [nox-sdk](https://github.com/hisoka-io/nox-sdk) · client SDK
- [docs](https://docs.hisoka.io) · protocol documentation

## License

[Apache 2.0](LICENSE)
