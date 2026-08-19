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
import type { ProverNoteInput } from "@hisoka/wallets";
import type { NoteInput } from "./types.js";

type Mutual<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;
type Assert<T extends true> = T;

/** Fails the build if the wallets mirror and the prover witness drift in EITHER direction. */
export type NoteInputMirrorIsExact = Assert<Mutual<ProverNoteInput, NoteInput>>;
