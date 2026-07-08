export * from "./interfaces.js";
export * from "./repositories.js";
export * from "./crypto/fields.js";
export * from "./keys/DarkAccount.js";
export * from "./utxo/Utxo.js";
export * from "./crypto/index.js";
export * from "./merkle/LeanIMT.js";
export * from "./address.js";
export * from "./state/types.js";
export * from "./state/KeyRepository.js";
export * from "./state/EphemeralCounterStore.js";
export * from "./state/UtxoRepository.js";

export * from "./note/note.js";
export * from "./note/nullifier.js";
export * from "./note/keys.js";

export * from "./sync/types.js";
export * from "./sync/ScanEngine.js";
export * from "./sync/NoteProcessor.js";

// The FROST-multisig signer + threshold-compliance/committee tooling ship as SEPARATE entry points
// (`@hisoka/wallets/frost`, `@hisoka/wallets/threshold`) so a base UTXO-wallet consumer never downloads the
// ~1.4k LOC of BN254/FROST/committee-deanonymization surface. They are intentionally NOT re-exported here.
