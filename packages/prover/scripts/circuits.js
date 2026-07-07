// Single source of truth for the circuit roster (crate name -> generated verifier), consumed by
// compile_circuit.js and generate_verifier.js so the two lists cannot drift. Keep in step with
// circuits/Nargo.toml workspace members and the CIRCUIT_* ids in DarkPool.sol.
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
