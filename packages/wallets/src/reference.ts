// Reference wallet infrastructure: local scan-based discovery, in-memory key/UTXO repositories, and the
// ephemeral counter. NOT production -- Raven serves single-shot discovery and PSS serves encrypted state; this is
// the reference implementation (and cross-package test surface) the production wallet replaces. A separate entry
// point so it never bloats the base `@hisoka/wallets` crypto import.
export * from "./repositories.js";
export * from "./utxo/Utxo.js";
export * from "./state/types.js";
export * from "./state/KeyRepository.js";
export * from "./state/EphemeralCounterStore.js";
export * from "./state/UtxoRepository.js";
export * from "./sync/types.js";
export * from "./sync/ScanEngine.js";
export * from "./sync/NoteProcessor.js";
