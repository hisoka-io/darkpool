import { Fr } from "@aztec/foundation/fields";
import { Point } from "../tss/bjj.js";
import { toFr } from "../crypto/fields.js";
import { demDecrypt } from "../crypto/dem.js";
import { deriveCek } from "../crypto/kem.js";
import { computeNullifier, computePsi } from "../note/nullifier.js";
import { leaf as computeLeaf, Note } from "../note/note.js";
import { isEvenY, recoverEvenY } from "../note/keys.js";
import { ComplianceKeyRing } from "../note/complianceKeys.js";
import type { UnprocessedEvent } from "../sync/types.js";
import {
  MultisigAddress,
  NOTE_TYPE_MULTISIG,
  deriveSelfEph,
  memberReadIncoming,
  multisigAddress,
  multisigIncomingKeyAt,
} from "./multisigNote.js";

// asset ids are ERC20 addresses; >= 2^160 cannot be a real asset (mirrors NoteProcessor).
const ASSET_MODULUS = 1n << 160n;

const DEFAULT_SELF_WINDOW = 100;

// The window is the index distance a recovery scan crosses past the last MATCHED index, so it has to
// cover everything a mint can skip: one index burned by a crash between reserve and commit, plus the
// odd-y indices the even-y roll abandons, plus the note itself. The odd-y run is geometric at about one
// half per index, so a floor of 1 fails roughly half the time with no crash at all; a first-ever deposit
// landing at j=3 is undiscoverable at a window of 1. Sixteen leaves the failure probability negligible
// while costing sixteen derivations.
const MIN_LOOKAHEAD_WINDOW = 16;

function assertWindow(window: number, label: string): number {
  if (!Number.isInteger(window) || window < MIN_LOOKAHEAD_WINDOW) {
    throw new Error(
      `multisig ${label} lookahead must be an integer of at least ${MIN_LOOKAHEAD_WINDOW}, got ${window}`,
    );
  }
  return window;
}

const MAX_SELF_ROLL = 1_000;

// A gap limit over ISSUED receiving addresses, mirroring the standard path: a group that rotates per payer
// must still find notes sent to an address it issued but has not yet seen used.
const DEFAULT_INCOMING_WINDOW = 20;

export interface MultisigNoteView {
  note: Note;
  commitment: Fr;
  leafIndex: number;
  nullifier: Fr;
  isIncoming: boolean;
  memberId?: bigint;
  derivationJ?: bigint;
}

export interface MultisigScanConfig {
  v: Fr;
  gpk: Point;
  /** A bare key is the single-version case; pass a ring once the pool has rotated (see ComplianceKeyRing). */
  compliancePk: Point | ComplianceKeyRing;
  memberIds: bigint[];
  selfWindow?: number;
  incomingWindow?: number;
}

interface SelfSource {
  memberId: bigint;
  j: bigint;
  eph: Fr;
}

interface IncomingSource {
  index: bigint;
  viewKey: Fr;
}

export class MultisigScanner {
  readonly #v: Fr;
  readonly #complianceKeys: ComplianceKeyRing;
  #unopenable = 0;
  readonly #expectedOwner: Fr;
  readonly #incomingTags: Map<string, IncomingSource>;
  readonly #selfTags: Map<string, SelfSource>;
  readonly #memberIds: readonly bigint[];
  // Per member: the highest j already registered, and the highest j a real note matched at. The gap
  // between them is the remaining lookahead.
  readonly #selfScanJ = new Map<bigint, bigint>();
  readonly #highestMatchedSelf = new Map<bigint, bigint>();
  #incomingScanIndex: bigint;
  #highestMatchedIncoming = -1n;

  private constructor(
    v: Fr,
    compliancePk: Point | ComplianceKeyRing,
    expectedOwner: Fr,
    incomingTags: Map<string, IncomingSource>,
    selfTags: Map<string, SelfSource>,
    memberIds: readonly bigint[],
    selfScanJ: Map<bigint, bigint>,
    incomingScanIndex: bigint,
  ) {
    this.#v = v;
    this.#complianceKeys = ComplianceKeyRing.coerce(compliancePk);
    this.#expectedOwner = expectedOwner;
    this.#incomingTags = incomingTags;
    this.#selfTags = selfTags;
    this.#memberIds = memberIds;
    this.#selfScanJ = selfScanJ;
    this.#incomingScanIndex = incomingScanIndex;
  }

  /**
   * Grows the self-tag map so every member is registered at least `window` indices past its highest
   * matched one. Without this the map is built once and never extended, so a note minted beyond the
   * initial window is invisible even though its index is perfectly derivable.
   */
  async ensureSelfLookahead(window: number): Promise<boolean> {
    assertWindow(window, "self");
    let advanced = false;
    for (const memberId of this.#memberIds) {
      const matched = this.#highestMatchedSelf.get(memberId) ?? -1n;
      const target = matched + 1n + BigInt(window);
      let next = this.#selfScanJ.get(memberId) ?? 0n;
      while (next < target) {
        const { eph, ephPub } = await deriveSelfEph(this.#v, memberId, next);
        if (isEvenY(ephPub)) {
          const key = tagKey(ephPub[0]);
          if (!this.#selfTags.has(key)) advanced = true;
          this.#selfTags.set(key, { memberId, j: next, eph });
        }
        next++;
      }
      this.#selfScanJ.set(memberId, next);
    }
    return advanced;
  }

  /** The same gap limit over ISSUED receiving addresses. */
  async ensureIncomingLookahead(window: number): Promise<boolean> {
    assertWindow(window, "incoming");
    const target = this.#highestMatchedIncoming + 1n + BigInt(window);
    let advanced = false;
    while (this.#incomingScanIndex < target) {
      const { index, viewKey, viewPub } = await multisigIncomingKeyAt(
        this.#v,
        this.#incomingScanIndex,
      );
      const key = tagKey(viewPub[0]);
      if (!this.#incomingTags.has(key)) advanced = true;
      this.#incomingTags.set(key, { index, viewKey });
      this.#incomingScanIndex = index + 1n;
    }
    return advanced;
  }

  static async create(cfg: MultisigScanConfig): Promise<MultisigScanner> {
    const address: MultisigAddress = await multisigAddress(cfg.gpk, cfg.v);
    const window = assertWindow(cfg.selfWindow ?? DEFAULT_SELF_WINDOW, "self");
    const selfTags = new Map<string, SelfSource>();
    const selfScanJ = new Map<bigint, bigint>();
    for (const memberId of cfg.memberIds) {
      // Counted in RAW indices, the same unit `ensureSelfLookahead` uses. Counting even-y hits instead
      // would make the same knob mean twice the index span here and half the gap there.
      const limit = BigInt(Math.min(window, MAX_SELF_ROLL));
      for (let j = 0n; j < limit; j++) {
        const { eph, ephPub } = await deriveSelfEph(cfg.v, memberId, j);
        if (!isEvenY(ephPub)) continue;
        selfTags.set(tagKey(ephPub[0]), { memberId, j, eph });
      }
      selfScanJ.set(memberId, limit);
    }

    // Each rotated address wraps its content key to a DIFFERENT point, so the scanner must carry the
    // per-address secret, not just the tag: matching the tag is not enough to open the note.
    const incomingTags = new Map<string, IncomingSource>();
    const incomingWindow = assertWindow(
      cfg.incomingWindow ?? DEFAULT_INCOMING_WINDOW,
      "incoming",
    );
    // Counted in RAW indices, the same unit `ensureIncomingLookahead` targets. Counting even-y hits
    // instead made the same knob mean a different span in each place, which is what made a lookahead
    // test flaky rather than deterministic.
    const incomingLimit = BigInt(Math.min(incomingWindow, MAX_SELF_ROLL));
    let next = 0n;
    while (next < incomingLimit) {
      const { index, viewKey, viewPub } = await multisigIncomingKeyAt(
        cfg.v,
        next,
      );
      if (index >= incomingLimit) break;
      incomingTags.set(tagKey(viewPub[0]), { index, viewKey });
      next = index + 1n;
    }
    next = incomingLimit;

    return new MultisigScanner(
      cfg.v,
      cfg.compliancePk,
      address.ownerCommitment,
      incomingTags,
      selfTags,
      [...cfg.memberIds],
      selfScanJ,
      next,
    );
  }

  /** A malformed event is SKIPPED (null), not thrown; a skip logs only a trace id, never key/cek/plaintext. */
  async readNote(event: UnprocessedEvent): Promise<MultisigNoteView | null> {
    try {
      if (event.type === "NEW_MEMO") return await this.#readIncoming(event);
      if (event.type === "NEW_NOTE") return await this.#readSelf(event);
      return null;
    } catch (err) {
      this.#warnSkip(event, err);
      return null;
    }
  }

  #warnSkip(event: UnprocessedEvent, err: unknown): void {
    const why = err instanceof Error ? err.message : "unknown error";
    console.warn(
      `[MultisigScanner] skipped malformed event (block=${event.blockNumber}, leaf=${event.args.leafIndex}): ${why}`,
    );
  }

  async #readIncoming(
    event: UnprocessedEvent,
  ): Promise<MultisigNoteView | null> {
    const { tag, cekWrap, ephemeralX } = event.args;
    if (tag === undefined || cekWrap === undefined) return null;
    const source = this.#incomingTags.get(tagKey(tag));
    if (!source) return null;
    if (source.index > this.#highestMatchedIncoming) {
      this.#highestMatchedIncoming = source.index;
    }
    const ephPub: Point = recoverEvenY(ephemeralX);
    const cek = await memberReadIncoming(
      new Fr(cekWrap),
      source.viewKey,
      ephPub,
    );
    return this.#recover(event, cek, true, undefined, source.index);
  }

  /**
   * Notes whose tag matched this group but which no compliance key version could open. Non-zero means
   * the ring is missing a version and the reported balance is LOWER than the true one.
   */
  get unopenableNoteCount(): number {
    return this.#unopenable;
  }

  async #readSelf(event: UnprocessedEvent): Promise<MultisigNoteView | null> {
    const source = this.#selfTags.get(tagKey(event.args.ephemeralX));
    // A miss is the common case: every note in the pool belonging to someone else misses this map, so a
    // per-miss log would be noise and a privacy-adjacent event trail.
    if (!source) return null;
    if (source.j > (this.#highestMatchedSelf.get(source.memberId) ?? -1n)) {
      this.#highestMatchedSelf.set(source.memberId, source.j);
    }
    // The tag is this group's own derived ephemeral, so the note IS ours; only the compliance key that
    // minted it is unknown, and rotation leaves older notes bound to older versions.
    const tried: number[] = [];
    for (const epoch of this.#complianceKeys.candidatesFor(event.blockNumber)) {
      const cek = deriveCek(source.eph, epoch.pk);
      tried.push(epoch.version);
      // A wrong key decrypts to a random field element, so the leaf rebuild THROWS on the u128 range
      // check more often than it returns a clean mismatch. Both mean wrong key, try the next.
      try {
        const view = await this.#recover(
          event,
          cek,
          false,
          source.memberId,
          source.j,
        );
        if (view) return view;
      } catch {
        continue;
      }
    }
    this.#unopenable += 1;
    console.error(
      `[MultisigScanner] self-tagged note at leaf ${event.args.leafIndex} (block ${event.blockNumber}) ` +
        `could not be opened by any known compliance key (tried versions ${tried.join(", ")}). ` +
        `Balance is UNDER-reported. Rebuild the ring from the pool's ComplianceKeyRotated log.`,
    );
    return null;
  }

  async #recover(
    event: UnprocessedEvent,
    cek: Fr,
    isIncoming: boolean,
    memberId: bigint | undefined,
    derivationJ: bigint | undefined,
  ): Promise<MultisigNoteView | null> {
    const ciphertext = event.args.packedCiphertext.map((h) => toFr(h));
    const plaintext = await demDecrypt(cek, ciphertext);
    const psi = await computePsi(cek);
    const note: Note = {
      noteVersion: plaintext[0],
      assetId: plaintext[1],
      noteType: plaintext[2],
      conditionsHash: plaintext[3],
      value: plaintext[4].toBigInt(),
      owner: plaintext[5],
      psi,
      parents: plaintext[6],
    };

    const commitment = toFr(event.args.commitment);
    const rebuilt = await computeLeaf(note);
    if (!rebuilt.equals(commitment)) return null;

    if (note.noteType.toBigInt() !== NOTE_TYPE_MULTISIG) return null;
    if (!note.owner.equals(this.#expectedOwner)) return null;
    if (note.assetId.toBigInt() >= ASSET_MODULUS) return null;

    const leafIndex = Number(event.args.leafIndex);
    const nullifier = await computeNullifier(psi, new Fr(BigInt(leafIndex)));
    return {
      note,
      commitment,
      leafIndex,
      nullifier,
      isIncoming,
      memberId,
      derivationJ,
    };
  }
}

export function selfNoteEvent(args: {
  leafIndex: bigint;
  note: Note;
  commitment: Fr;
  ephPub: Point;
  packedCiphertext: Fr[];
}): UnprocessedEvent {
  return {
    type: "NEW_NOTE",
    blockNumber: 0,
    txHash: "",
    args: {
      leafIndex: args.leafIndex,
      commitment: args.commitment.toString(),
      ephemeralX: args.ephPub[0],
      packedCiphertext: args.packedCiphertext.map((f) => f.toString()),
    },
  };
}

/**
 * Refuses a self-family note the group's own scanner cannot open, before it is broadcast.
 *
 * This is the mint-time detector for the whole undiscoverable-note class: a note whose tag the scanner
 * does not register is invisible and unspendable from the seed alone, with no error anywhere and only a
 * quietly smaller balance to show for it. Checking at mint costs one local scan and catches every
 * honest-mistake case, which is why the scanner itself stays silent on a tag miss.
 */
export async function assertSelfNoteDiscoverable(
  scanner: MultisigScanner,
  args: {
    leafIndex: bigint;
    note: Note;
    commitment: Fr;
    ephPub: Point;
    packedCiphertext: Fr[];
  },
): Promise<MultisigNoteView> {
  const view = await scanner.readNote(selfNoteEvent(args));
  if (view === null) {
    throw new Error(
      "multisig self note is not discoverable by the group's own scanner: refusing to broadcast, " +
        "because its tag is the ephemeral's own public x and a tag the scanner does not register " +
        "makes the note permanently invisible and unspendable from the seed",
    );
  }
  return view;
}

export function incomingNoteEvent(args: {
  leafIndex: bigint;
  commitment: Fr;
  ephPub: Point;
  tag: Fr;
  cekWrap: Fr;
  packedCiphertext: Fr[];
}): UnprocessedEvent {
  return {
    type: "NEW_MEMO",
    blockNumber: 0,
    txHash: "",
    args: {
      leafIndex: args.leafIndex,
      commitment: args.commitment.toString(),
      ephemeralX: args.ephPub[0],
      packedCiphertext: args.packedCiphertext.map((f) => f.toString()),
      tag: args.tag.toBigInt(),
      cekWrap: args.cekWrap.toBigInt(),
    },
  };
}

function tagKey(x: bigint): string {
  return new Fr(x).toString();
}
