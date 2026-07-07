// FROST threshold-Schnorr signing toolkit (`@hisoka/wallets/frost`): a ciphersuite-generic 2-round protocol
// (frost.ts) instantiated over BabyJubJub+Poseidon2 (production, bjjCiphersuite), plus the multisig-account
// note VIEW layer (owner = Poseidon2(gpk), shared viewing key v, member-partitioned self ephemerals). The
// protocol LOGIC is certified against the RFC 9591 KAT via a ristretto255 ciphersuite that is TEST-ONLY and
// never re-exported here (so it stays out of every shipped bundle). The simulated account ceremony (DKG /
// view-key) is TEST/DEV-only (unsafe-sim) and is deliberately NOT exported.

export * from "./ciphersuite.js";
export * from "./frost.js";
export * from "./message.js";
export * from "./multisigNote.js";
export * from "./multisigScan.js";
export { bjjCiphersuite, encodeMessage } from "./ciphersuites/bjj.js";
