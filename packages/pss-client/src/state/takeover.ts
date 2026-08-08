import { CryptoBackend } from "../crypto/backend.js";
import { COLLECTIONS, Collection } from "../wire/collection.js";
import { toHex } from "../wire/codec.js";
import { INSTALL_ID_BYTES, PLATFORM_MAX_CHARS } from "../wire/constants.js";
import {
  INSTALL_ID_SHAPE,
  ParsedStatePayload,
  PssStatePayload,
} from "../wire/payload.js";
import { PssStateError } from "./errors.js";
import { VersionFloor } from "./floor.js";

export type WriteMode = "writer" | "readonly";

declare const stampedTag: unique symbol;

// `stamp` is the only enforcement point for read-only demotion, and it was opt-in: `mergeStatePayloads`
// and `serializeStatePayload` are both public and take no guard, so a caller could merge and upload a
// payload still carrying the other device's installId. Branding the output means a write path typed to
// take a StampedPayload cannot be reached without passing through the check.
export type StampedPayload = ParsedStatePayload & {
  readonly [stampedTag]: true;
};

export interface InstallIdentity {
  readonly installId: string;
  readonly platform: string;
}

export interface TakeoverDecision {
  readonly mode: WriteMode;
  readonly heldBy: InstallIdentity | null;
}

export function newInstallId(backend: CryptoBackend): string {
  return toHex(backend.randomBytes(INSTALL_ID_BYTES));
}

// One writer per account, by takeover rather than by lock. Two devices allocating ephemeral indices
// independently collide, and a collision is a key handover rather than a lost update, so it has to be
// prevented at mint time. A blob compare-and-swap cannot do that, because the collision happens before
// either device writes.
export class InstallGuard {
  readonly #identity: InstallIdentity;
  readonly #floor: VersionFloor;
  // The holder the user confirmed against, not a bare flag. A grant that outlived the holder it was
  // given for would make every later takeover automatic, which is the two-writer state this class
  // exists to keep unreachable.
  #confirmedAgainst: string | null = null;

  constructor(identity: InstallIdentity, floor: VersionFloor) {
    if (!INSTALL_ID_SHAPE.test(identity.installId)) {
      throw new PssStateError(
        `installId must be ${INSTALL_ID_BYTES} bytes of 0x-prefixed lowercase hex`,
      );
    }
    if (identity.platform.length > PLATFORM_MAX_CHARS) {
      throw new PssStateError(
        `platform must be at most ${PLATFORM_MAX_CHARS} characters`,
      );
    }
    this.#identity = identity;
    this.#floor = floor;
  }

  get identity(): InstallIdentity {
    return this.#identity;
  }

  evaluate(remote: PssStatePayload | null): TakeoverDecision {
    if (remote === null) return { mode: "writer", heldBy: null };
    if (remote.installId === this.#identity.installId) {
      // Our own id is in the blob, so the handover completed and the grant has served its purpose.
      // Holding it open would let the device we took over from take the account back without a prompt.
      this.#confirmedAgainst = null;
      return { mode: "writer", heldBy: null };
    }
    if (remote.installId === this.#confirmedAgainst) {
      return { mode: "writer", heldBy: null };
    }
    this.#confirmedAgainst = null;
    return {
      mode: "readonly",
      heldBy: { installId: remote.installId, platform: remote.platform },
    };
  }

  /**
   * Takeover is never automatic: this runs only behind an explicit user confirmation, and the grant it
   * records is good for `remote`'s holder alone. The chain floor bootstrap happens BEFORE this install
   * becomes the writer, so anything the previous device minted and did not sync is still respected.
   */
  async confirmTakeover(
    remote: PssStatePayload,
    chainFloors: Readonly<Record<Collection, number>>,
  ): Promise<void> {
    for (const collection of COLLECTIONS) {
      await this.#floor.bootstrap(collection, chainFloors[collection]);
    }
    this.#confirmedAgainst = remote.installId;
  }

  stamp(
    payload: ParsedStatePayload,
    remote: PssStatePayload | null,
    updatedAt: number,
  ): StampedPayload {
    const decision = this.evaluate(remote);
    if (decision.mode !== "writer") {
      throw new PssStateError(
        `this install is read-only: the account is active on ` +
          `${decision.heldBy?.platform ?? "another device"} and takeover was not confirmed`,
      );
    }
    return {
      known: {
        ...payload.known,
        installId: this.#identity.installId,
        platform: this.#identity.platform,
        updatedAt,
      },
      extra: payload.extra,
    } as StampedPayload;
  }
}
