/**
 * Transaction assembly. Opt-in on `@hisoka/wallets/tx`, deliberately off the main barrel: the barrel is the
 * crypto core every consumer needs (addresses, notes, decode), while assembly is what only a SPENDING wallet
 * needs. A read-only consumer, a scanner or a Raven client should not pay for it.
 *
 * Proving is not here and never will be: the witness carries the spend scalar, so a remote prover is a total
 * custody break. `ProverPort` exists so each environment supplies its own LOCAL backend.
 */
export * from "./plan.js";
export * from "./ports.js";
export * from "./assemble.js";
export * from "./witnessSources.js";
