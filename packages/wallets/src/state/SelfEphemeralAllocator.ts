import { Fr } from "@aztec/foundation/fields";
import { DarkAccount } from "../keys/DarkAccount.js";
import { publicKey, pubkeyOwner } from "../note/keys.js";
import { selfEphemeralFault } from "../note/mint.js";
import type {
  SelfMintAllocator,
  SelfMintCandidate,
} from "../discovery/preflight.js";
import { markDerivedSelfMintCandidate } from "../types/ephemeral.js";
import type {
  EphemeralCounterStore,
  EphemeralReservation,
} from "./EphemeralCounterStore.js";

/** Durable counter scope of the standard self family; `reconcileCounterWithChain` must ratchet this scope. */
export const SELF_EPHEMERAL_SCOPE = "self";

/** Bounds the odd-y skip loop; each index is even-y with probability about 1/2. */
const MAX_SELF_EPHEMERAL_RESERVATIONS = 256;

export class SelfEphemeralAllocatorError extends Error {
  constructor(
    readonly reason:
      | "INVALID_ACCOUNT"
      | "COUNTER_UNAVAILABLE"
      | "COUNTER_INVALID"
      | "NO_CANONICAL_EPHEMERAL",
    message: string,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "SelfEphemeralAllocatorError";
  }
}

/**
 * Reserves one durable index per attempt and derives that index's self ephemeral. An index whose ephemeral
 * the circuit would reject (odd y, or a zero scalar) stays reserved and is skipped, so the pure derivation
 * can never revisit it; the returned index is committed before it is returned.
 */
export async function reserveSelfEphemeral(
  account: DarkAccount,
  counters: EphemeralCounterStore,
): Promise<SelfMintCandidate> {
  const ownerCommitment = await pubkeyOwner(await account.getSelfSpendPub());
  for (let attempt = 0; attempt < MAX_SELF_EPHEMERAL_RESERVATIONS; attempt++) {
    let reservation: EphemeralReservation;
    try {
      reservation = await counters.reserve(SELF_EPHEMERAL_SCOPE, 1);
    } catch (cause) {
      throw new SelfEphemeralAllocatorError(
        "COUNTER_UNAVAILABLE",
        `self ephemeral reservation failed after ${attempt} attempts: ${cause instanceof Error ? cause.message : String(cause)}`,
        cause,
      );
    }
    const index = reservation.base;
    if (!Number.isSafeInteger(index) || index < 0 || reservation.span !== 1) {
      throw new SelfEphemeralAllocatorError(
        "COUNTER_INVALID",
        `counter store returned base ${index} span ${reservation.span} for a one-index self reservation`,
      );
    }
    const eph = await account.getSelfEphemeral(BigInt(index));
    if (selfEphemeralFault(eph) !== null) continue;
    await reservation.commit(index);
    const ephPub = publicKey(eph);
    return markDerivedSelfMintCandidate(
      { eph, ephPub, tag: new Fr(ephPub[0]), index },
      ownerCommitment,
    );
  }
  throw new SelfEphemeralAllocatorError(
    "NO_CANONICAL_EPHEMERAL",
    `no even-y self ephemeral within ${MAX_SELF_EPHEMERAL_RESERVATIONS} reservations`,
  );
}

/**
 * The production `SelfMintAllocator` for a standard wallet: every candidate is derived from the account's
 * view key at a freshly reserved index of `counters`, which must be the durable counter every device of
 * this wallet shares. A reused index reuses the CEK, so this is the only safe source of self ephemerals.
 */
export class SelfEphemeralAllocator implements SelfMintAllocator<SelfMintCandidate> {
  readonly #account: DarkAccount;
  readonly #counters: EphemeralCounterStore;

  constructor(account: DarkAccount, counters: EphemeralCounterStore) {
    if (!(account instanceof DarkAccount)) {
      throw new SelfEphemeralAllocatorError(
        "INVALID_ACCOUNT",
        "self ephemeral allocator needs a DarkAccount; its derivation is what makes a self note findable",
      );
    }
    this.#account = account;
    this.#counters = counters;
  }

  next(): Promise<SelfMintCandidate> {
    return reserveSelfEphemeral(this.#account, this.#counters);
  }
}
