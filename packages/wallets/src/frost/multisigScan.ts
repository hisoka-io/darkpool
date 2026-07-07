// Focused note_type=MULTISIG reader. Given an account VIEW ({ v, gpk, C, member ids }) it precomputes the
// discovery tags -- the STATIC incoming V.x plus each member's partitioned self/change eph_pub.x window -- and
// turns a NewNote/NewPrivateMemo event into a MultisigNoteView (decrypt, rebuild the leaf, verify, derive the
// nullifier). This is the multisig analog of NoteProcessor.recover; it is deliberately SELF-CONTAINED because
// a MULTISIG note has no single spend scalar (spend is a FROST quorum), so it does not fit the WalletNote
// record. Integrating it into the shared ScanEngine/KeyRepository is a follow-up (see the module doc below).

import { Fr } from "@aztec/foundation/fields";
import { Point } from "../tss/bjj.js";
import { toFr } from "../crypto/fields.js";
import { demDecrypt } from "../crypto/dem.js";
import { deriveCek } from "../crypto/kem.js";
import { computeNullifier, computePsi } from "../note/nullifier.js";
import { leaf as computeLeaf, Note } from "../note/note.js";
import { isEvenY } from "../note/keys.js";
import type { UnprocessedEvent } from "../sync/types.js";
import {
  MultisigAddress,
  NOTE_TYPE_MULTISIG,
  deriveSelfEph,
  memberReadIncoming,
  multisigAddress,
} from "./multisigNote.js";

// asset ids are ERC20 addresses; anything at or above 2^160 cannot be a real asset (mirrors NoteProcessor).
const ASSET_MODULUS = 1n << 160n;

// Per-member even-y self-tag lookahead. Bounds the precompute at n*window tags (single-shot Raven).
const DEFAULT_SELF_WINDOW = 100;

// Guards the even-y roll from spinning unboundedly while collecting the window.
const MAX_SELF_ROLL = 1_000;

/** A recovered MULTISIG note. It carries the coordinating member for a self/change output (internal
 *  accountability); an incoming note has none. Spending needs the t-of-n FROST quorum, not a scalar. */
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
  /** Shared viewing scalar (secret; never log). */
  v: Fr;
  /** Group spend key (public). */
  gpk: Point;
  /** Compliance point C (public). */
  compliancePk: Point;
  /** The account member identifiers, for the partitioned self-tag precompute. */
  memberIds: bigint[];
  /** Per-member even-y self-tag lookahead (default 100). */
  selfWindow?: number;
}

interface SelfSource {
  memberId: bigint;
  j: bigint;
  eph: Fr;
}

/** Reader for one multisig account's notes. Build via `create` (the tag precompute is async). */
export class MultisigScanner {
  readonly #v: Fr;
  readonly #compliancePk: Point;
  readonly #expectedOwner: Fr;
  readonly #incomingTag: string;
  readonly #selfTags: Map<string, SelfSource>;

  private constructor(
    v: Fr,
    compliancePk: Point,
    expectedOwner: Fr,
    incomingTag: string,
    selfTags: Map<string, SelfSource>,
  ) {
    this.#v = v;
    this.#compliancePk = compliancePk;
    this.#expectedOwner = expectedOwner;
    this.#incomingTag = incomingTag;
    this.#selfTags = selfTags;
  }

  static async create(cfg: MultisigScanConfig): Promise<MultisigScanner> {
    const address: MultisigAddress = await multisigAddress(cfg.gpk, cfg.v);
    const window = cfg.selfWindow ?? DEFAULT_SELF_WINDOW;
    const selfTags = new Map<string, SelfSource>();
    for (const memberId of cfg.memberIds) {
      let found = 0;
      for (let j = 0n; found < window && j < BigInt(MAX_SELF_ROLL); j++) {
        const { eph, ephPub } = await deriveSelfEph(cfg.v, memberId, j);
        if (!isEvenY(ephPub)) continue;
        selfTags.set(tagKey(ephPub[0]), { memberId, j, eph });
        found++;
      }
    }
    return new MultisigScanner(
      cfg.v,
      cfg.compliancePk,
      address.ownerCommitment,
      tagKey(address.viewPub[0]),
      selfTags,
    );
  }

  /** Decrypt + verify one event into a MULTISIG note, or null if it is not this account's. A malformed event
   *  (attacker-crafted eph_pub / ciphertext) is SKIPPED (returns null) rather than throwing, so one poisoned
   *  on-chain event cannot halt a whole scan -- mirrors the base ScanEngine/NoteProcessor per-event isolation.
   *  Only a trace id (block + leaf index) is logged on a skip; never a key, cek, or plaintext. */
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
    const { tag, cekWrap, ephemeralX, ephemeralY } = event.args;
    if (tag === undefined || cekWrap === undefined) return null;
    if (tagKey(tag) !== this.#incomingTag) return null;
    const ephPub: Point = [ephemeralX, ephemeralY];
    const cek = await memberReadIncoming(new Fr(cekWrap), this.#v, ephPub);
    return this.#recover(event, cek, true, undefined, undefined);
  }

  async #readSelf(event: UnprocessedEvent): Promise<MultisigNoteView | null> {
    const source = this.#selfTags.get(tagKey(event.args.ephemeralX));
    if (!source) return null;
    const cek = deriveCek(source.eph, this.#compliancePk);
    return this.#recover(event, cek, false, source.memberId, source.j);
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

    // A MULTISIG note owned by THIS account: type pinned to MULTISIG and owner pinned to Poseidon2(gpk), so a
    // tag collision or a foreign note never enters the account's set.
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

/** Sender-side event payloads a caller emits on-chain, so a test (or an integration) can round-trip a built
 *  note through `readNote` without a live contract. */
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
      ephemeralY: args.ephPub[1],
      packedCiphertext: args.packedCiphertext.map((f) => f.toString()),
    },
  };
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
      ephemeralY: args.ephPub[1],
      packedCiphertext: args.packedCiphertext.map((f) => f.toString()),
      tag: args.tag.toBigInt(),
      cekWrap: args.cekWrap.toBigInt(),
    },
  };
}

function tagKey(x: bigint): string {
  return new Fr(x).toString();
}
