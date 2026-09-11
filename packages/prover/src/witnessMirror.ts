/**
 * Compile-time guard on the wallets/prover witness mirror. TYPE-ONLY: emits no runtime code.
 *
 * `@hisoka/wallets` cannot import `@hisoka/prover` (that is the cycle), so the assemblers mirror the prover's
 * witness types structurally instead. The golden vectors in `tx-vectors.json` catch a VALUE drift, but a
 * purely additive field, or one whose type widened, produces identical vectors and diverges silently.
 *
 * This lives in the prover because only the prover can see both sides, and in `src/` rather than a test so
 * the ordinary build checks it. `Mutual` is bidirectional on purpose: a one-way `extends` accepts an extra
 * field on the wider side, which is exactly the drift a vector cannot show.
 */
import type { ProverNoteInput, PublicClaimWitness } from "@hisoka/wallets";
import type {
  AssembledTransferWitness,
  DepositWitness,
  JoinWitness,
  SplitWitness,
  TransferWitness,
  WithdrawWitness,
} from "@hisoka/wallets/tx";
import type { StandardNoirInputByCircuit } from "@hisoka/howl-protocol/proving";
import type { InputMap } from "@noir-lang/noir_js";
import type {
  DepositInputs,
  JoinInputs,
  NoteInput,
  PublicClaimInputs,
  SplitInputs,
  TransferInputs,
  WithdrawInputs,
} from "./types.js";

type Mutual<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
type Assert<T extends true> = T;

/** Fails the build if the wallets mirror and the prover witness drift in EITHER direction. */
export type NoteInputMirrorIsExact = Assert<Mutual<ProverNoteInput, NoteInput>>;
export type DepositInputMirrorIsExact = Assert<
  Mutual<DepositWitness, DepositInputs>
>;
export type WithdrawInputMirrorIsExact = Assert<
  Mutual<WithdrawWitness, WithdrawInputs>
>;
export type TransferInputMirrorIsExact = Assert<
  Mutual<TransferWitness, TransferInputs>
>;
export type AssembledTransferFitsProver = Assert<
  AssembledTransferWitness extends TransferInputs ? true : false
>;
export type SplitInputMirrorIsExact = Assert<Mutual<SplitWitness, SplitInputs>>;
export type JoinInputMirrorIsExact = Assert<Mutual<JoinWitness, JoinInputs>>;
export type PublicClaimInputMirrorIsExact = Assert<
  Mutual<PublicClaimWitness, PublicClaimInputs>
>;
export type StandardNoirInputsFitNoirJs = Assert<
  StandardNoirInputByCircuit[keyof StandardNoirInputByCircuit] extends InputMap
    ? true
    : false
>;
