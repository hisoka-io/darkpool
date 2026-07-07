// Single source of truth for the circuit roster: crate name -> generated Solidity verifier file. Consumed by
// compile_circuit.js and generate_verifier.js so a circuit can never be compiled without its verifier
// generated (or vice versa) via drifting hand-maintained lists. Keep in step with the circuits/Nargo.toml
// workspace members and the contract's circuit-id constants (CIRCUIT_* in DarkPool.sol).
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
