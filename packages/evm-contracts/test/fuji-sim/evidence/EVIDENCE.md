# Howl on Avalanche Fuji: simulation evidence

A test deployment with simulated user agents on the Howl pre-freeze test build on Avalanche Fuji (testnet).
Pool [`0x44B3d56c0B8260044153378dab383251fe2e1713`](https://testnet.snowtrace.io/address/0x44B3d56c0B8260044153378dab383251fe2e1713). Run window 2026-11-11T14:58:58.158Z to 2026-11-12T21:49:00.456Z (UTC).

## Totals

| Measure                                       | Value                                        |
| --------------------------------------------- | -------------------------------------------- |
| Transactions on chain                         | 251 (203 graded actions, 48 token approvals) |
| Cheats attempted and refused on chain         | 6 of 6, each with the expected error         |
| Mismatches against the independent chain scan | 0                                            |
| Spends built on Merkle paths served by Raven  | 105, every root known to the pool            |
| Raven node readiness (`/howl/v1/ready`)       | 170 of 171 checks answered 200               |
| Gas spent by the agents                       | 0.000000028915 AVAX                          |

## Waves

| Wave                                  | Graded | Refused cheats | Mismatches | Leaves at end | Raven paths | Minutes |
| ------------------------------------- | ------ | -------------- | ---------- | ------------- | ----------- | ------- |
| 1 (stopped part-way: wave-1-attempt1) | 0      | 0              | 0          | 1             | 0           | 5       |
| 1                                     | 54     | 1              | 0          | 66            | 32          | 40      |
| 2                                     | 40     | 2              | 0          | 118           | 33          | 41      |
| 3                                     | 34     | 3              | 0          | 159           | 21          | 41      |
| 4                                     | 30     | 0              | 0          | 194           | 19          | 40      |
| 5 (stopped part-way: wave-5-attempt1) | 37     | 0              | 0          | 242           | 29          | -       |
| 5                                     | 2      | 0              | 0          | 245           | 0           | 24      |

## Transactions per persona and action

| Persona | approve | deposit | transfer | publicClaim | swap | join | split | withdraw | publicTransfer | cheat | hop |
| ------- | ------- | ------- | -------- | ----------- | ---- | ---- | ----- | -------- | -------------- | ----- | --- |
| alice   | 10      | 10      | 0        | 8           | 6    | 13   | 2     | 5        | 0              | 0     | 0   |
| bob     | 5       | 5       | 11       | 3           | 0    | 0    | 4     | 2        | 0              | 6     | 0   |
| charlie | 11      | 5       | 12       | 2           | 0    | 0    | 4     | 0        | 6              | 0     | 0   |
| david   | 7       | 3       | 12       | 1           | 0    | 0    | 0     | 5        | 4              | 0     | 0   |
| ellie   | 9       | 9       | 2        | 21          | 20   | 3    | 1     | 0        | 0              | 0     | 0   |
| frank   | 5       | 5       | 0        | 0           | 0    | 0    | 1     | 0        | 0              | 0     | 0   |
| grace   | 1       | 1       | 0        | 1           | 0    | 2    | 3     | 0        | 0              | 0     | 5   |

## Cheats

| Attempt                                  | Expected              | Refused with          | Transaction                                                                                                           |
| ---------------------------------------- | --------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------- |
| replay withdraw                          | NullifierAlreadySpent | NullifierAlreadySpent | [0x089f27bf7d...](https://testnet.snowtrace.io/tx/0x089f27bf7d0d47ed431b8fbc1f8a99bd5514055d517c4ad34c2422db96ce1a0a) |
| double spend                             | NullifierAlreadySpent | NullifierAlreadySpent | [0xea75459de5...](https://testnet.snowtrace.io/tx/0xea75459de53735b703aed0162bf937bc3fcd90949ed0a2ae4444525398fe3df5) |
| phantom note withdraw                    | InvalidRoot           | InvalidRoot           | [0x51cbcaa0f0...](https://testnet.snowtrace.io/tx/0x51cbcaa0f004d7efdb6b9c0c1af348e8a47824ddb8a2351c0810053082a15b97) |
| withdraw with inflated value             | ProofRejected         | SumcheckFailed        | [0x5746e9bcff...](https://testnet.snowtrace.io/tx/0x5746e9bcff696f83bb5f040d449b6088ab3bf6d74e63db21561a23e3f93c5336) |
| withdraw redirected to another recipient | ProofRejected         | SumcheckFailed        | [0x1e18aabd60...](https://testnet.snowtrace.io/tx/0x1e18aabd60cc9ab43f6b2a20faaeab07d845cdd2f34f359422e0576ec5139a4b) |
| replay another wallet's claim            | MemoSpent             | MemoSpent             | [0xcd55f897df...](https://testnet.snowtrace.io/tx/0xcd55f897dff75c667f9fb85375a94607b5e8d2c9f754c6bc22399b844a645c31) |

## Gas against the pool's leaf count

Mean gas per action, by the number of leaves in the pool when it was graded (n in brackets). Leaves inserted is the step's measured leaf delta.

| Action         | Leaves inserted | 1-64 leaves   | 65-128 leaves  | 129-192 leaves | 193-256 leaves | Change, first band to last |
| -------------- | --------------- | ------------- | -------------- | -------------- | -------------- | -------------------------- |
| split          | 2               | 1,094,208 (3) | 1,159,073 (2)  | 1,183,792 (6)  | 1,218,604 (4)  | +124,396                   |
| transfer       | 2               | 1,144,662 (7) | 1,181,541 (13) | 1,178,159 (9)  | 1,211,021 (8)  | +66,359                    |
| hop            | 2               | 1,171,536 (2) | 1,206,774 (2)  | -              | 1,183,763 (1)  | +12,227                    |
| deposit        | 1               | 984,503 (17)  | 1,026,585 (8)  | 1,036,824 (10) | 1,035,609 (3)  | +51,106                    |
| join           | 1               | 1,058,583 (4) | 1,070,405 (5)  | 1,083,513 (4)  | 1,086,361 (5)  | +27,778                    |
| swap           | 1               | 1,413,931 (9) | 1,431,321 (6)  | 1,421,647 (6)  | 1,455,090 (5)  | +41,159                    |
| withdraw       | 1               | 1,044,181 (2) | 1,061,034 (2)  | 1,082,414 (6)  | 1,104,463 (2)  | +60,282                    |
| publicClaim    | 1               | 1,007,809 (6) | 1,026,780 (10) | 1,022,515 (7)  | 1,042,085 (12) | +34,276                    |
| publicTransfer | 0               | 131,723 (2)   | 131,726 (4)    | 131,711 (2)    | 131,699 (2)    | -24                        |

`publicTransfer` writes a public memo and no tree leaf, and its cost holds within 30 gas at every pool size. Every action that inserts a leaf costs more as the pool grows, by about 12k to 124k gas from the first band to the last. That fits the tree insert hashing more levels as the tree deepens (a 64-leaf tree is 6 levels deep, a 256-leaf tree 8); the proof and its verifier are independent of the pool's size. Proof bytes also vary per proof, which spreads each band. The repo's per-entrypoint ceilings (deposit 1,002,000, transfer 1,104,000, split 1,102,000, join 1,046,000, withdraw 1,044,000, publicClaim 990,000) are measured on a 3-leaf tree, which is why live gas on a 245-leaf pool sits above them.

## Gas per action (measured on Fuji)

| Action         | n   | Mean      | Range                  |
| -------------- | --- | --------- | ---------------------- |
| approve        | 48  | 46,349    | 46,319 to 46,355       |
| deposit        | 38  | 1,011,166 | 961,731 to 1,095,204   |
| transfer       | 37  | 1,180,115 | 1,108,067 to 1,261,299 |
| publicClaim    | 36  | 1,028,480 | 983,903 to 1,083,887   |
| swap           | 26  | 1,427,639 | 1,386,539 to 1,469,471 |
| join           | 18  | 1,075,123 | 1,042,572 to 1,115,130 |
| split          | 15  | 1,171,862 | 1,081,775 to 1,238,045 |
| withdraw       | 12  | 1,076,153 | 1,034,193 to 1,113,466 |
| publicTransfer | 10  | 131,717   | 131,681 to 131,729     |
| hop            | 5   | 1,188,076 | 1,149,427 to 1,217,153 |

## Kage and multisig smoke on Fuji

Two further flows beyond the persona waves, on the same deployed pool, with a Raven node following Fuji.

**Kage (private in-pool swap).** A solver registered in the pool's KageRegistry with the minimum stake of 1 mWETH ([registration](https://testnet.snowtrace.io/tx/0xb4cb2fcaff4b75a808a7d88c68bd923b8d0de45e7d5bc43188046c8c582ae5dd)). The taker proved its swap intent on a Raven Merkle path at a leaf count it chose; the solver kept its own tree from the pool's logs, resolved the intent's root to a count, and settled through KageSettlement with an EIP-712 approval from its registered signer.

| Intent root | Resolved count | Settlement                                                                                                            | Gas       |
| ----------- | -------------- | --------------------------------------------------------------------------------------------------------------------- | --------- |
| older       | 281            | [0x2659e9401c...](https://testnet.snowtrace.io/tx/0x2659e9401cb7b4d713363612efc8ecfab6ab6057bb2c8a8c750326e8f5b1bea2) | 1,717,142 |
| current     | 288            | [0xcc58870c3b...](https://testnet.snowtrace.io/tx/0xcc58870c3bc7601eddce5480037a4761d3233f51a7312eed3904d1ca8be86106) | 1,577,088 |

Each order with a wrong leaf-count hint was refused before any proving (2 of 2), and every grade of the taker matched Raven against the chain scan.

**FROST 2-of-3 multisig.** All three members found the group's notes through Raven, self mints and transfers to the group's receiving addresses, including notes past the first scan window that only the window growth reaches. A signer handed a session at another known root refused before committing. The group then withdrew ([0xad087d19ae...](https://testnet.snowtrace.io/tx/0xad087d19ae84e6e031595dfb32656873f65dd7360059296500e25f3eb273419d), 1,064,945 gas), split, joined and transferred, each through a signing session every signer checked against its own scan and its own Raven path.

Records: the `smoke` section of `evidence.json` (Kage from its third attempt, multisig from its first; the two earlier Kage attempts each led to a harness fix: the chain scan refreshes its logs before every grade, and the solver draws a fresh seed per run so a persistent chain sees each maker note once).

## Setup

- Howl: hisoka-io/darkpool, branch `test/fuji-howl`; deployed contracts from commit `a64f05b`, simulation harness `7ae4395` + `68255e8`, Kage and multisig smoke `119dcb6` (`packages/evm-contracts/test/fuji-sim/`).
- Raven Howl node built from hisoka-io/raven `5a8d9cf`; wallets use `@hisoka-io/raven-howl-client@0.1.0-alpha.1` with `@hisoka-io/howl-client-wasm@0.1.0-alpha.1`. Every note a wallet holds and every Merkle path it spends with comes through the node; the grade is an independent scan of the pool's own logs.
- Endpoint: the publicnode Fuji endpoint, through separate local relays for the node and for the harness.
- Seven agents: alice (greedy), bob (cheater, 6 attempts for the whole run), charlie (donor), david (philanthropist), ellie (trader, swaps through a fixed 1:1 test router behind Howl's UniswapAdaptor), frank (whale), grace (privacy: small amounts, hops through her own fresh addresses).
- Five waves of about 40 minutes. Wave 5 ran across two sittings, resumed the next day after the host machine slept; its first check after the resume graded every wallet against the full chain state, and its final step claimed every open memo, so the pool closed with balances equal to the agents' unspent notes and every memo claimed.
- The one readiness answer of 503 is the first check after that resume, taken as the node finished a day of catch-up; every later check answered 200.
- Gas on a tree of up to 245 leaves sits above the single-entrypoint ceilings the repo pins on a 3-leaf tree, because each insert hashes more levels.

Every transaction with its Snowtrace link is in `evidence.json`.
