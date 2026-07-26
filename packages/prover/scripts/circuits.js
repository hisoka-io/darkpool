// Keep in step with circuits/Nargo.toml members and the CIRCUIT_* ids in DarkPool.sol.
export const CIRCUITS = [
  { name: "deposit", verifier: "DepositVerifier.sol" },
  { name: "withdraw", verifier: "WithdrawVerifier.sol" },
  { name: "transfer", verifier: "TransferVerifier.sol" },
  { name: "join", verifier: "JoinVerifier.sol" },
  { name: "split", verifier: "SplitVerifier.sol" },
  { name: "public_claim", verifier: "PublicClaimVerifier.sol" },
  { name: "withdraw_multisig", verifier: "WithdrawMultisigVerifier.sol" },
  { name: "transfer_multisig", verifier: "TransferMultisigVerifier.sol" },
  { name: "split_multisig", verifier: "SplitMultisigVerifier.sol" },
  { name: "join_multisig", verifier: "JoinMultisigVerifier.sol" },
];

// swap_intent is inner-only; swap_settle's verifier needs native bb (bb.js WASM excludes recursion).
export const KAGE_CIRCUITS = [
  { name: "swap_intent", verifier: null },
  { name: "swap_settle", verifier: "KageVerifier.sol" },
];
