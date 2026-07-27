import { Fr } from "@aztec/foundation/fields";
import { Point } from "../tss/bjj.js";
import { toFr } from "../crypto/fields.js";
import { demDecrypt } from "../crypto/dem.js";
import { deriveCek } from "../crypto/kem.js";
import { computeNullifier, computePsi } from "../note/nullifier.js";
import { leaf as computeLeaf, Note } from "../note/note.js";
import { isEvenY, recoverEvenY } from "../note/keys.js";
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
  compliancePk: Point;
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
  readonly #compliancePk: Point;
  readonly #expectedOwner: Fr;
  readonly #incomingTags: Map<string, IncomingSource>;
  readonly #selfTags: Map<string, SelfSource>;

  private constructor(
    v: Fr,
    compliancePk: Point,
    expectedOwner: Fr,
    incomingTags: Map<string, IncomingSource>,
    selfTags: Map<string, SelfSource>,
  ) {
    this.#v = v;
    this.#compliancePk = compliancePk;
    this.#expectedOwner = expectedOwner;
    this.#incomingTags = incomingTags;
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

    // Each rotated address wraps its content key to a DIFFERENT point, so the scanner must carry the
    // per-address secret, not just the tag: matching the tag is not enough to open the note.
    const incomingTags = new Map<string, IncomingSource>();
    const incomingWindow = cfg.incomingWindow ?? DEFAULT_INCOMING_WINDOW;
    let next = 0n;
    for (let found = 0; found < incomingWindow; found++) {
      const { index, viewKey, viewPub } = await multisigIncomingKeyAt(
        cfg.v,
        next,
      );
      incomingTags.set(tagKey(viewPub[0]), { index, viewKey });
      next = index + 1n;
    }

    return new MultisigScanner(
      cfg.v,
      cfg.compliancePk,
      address.ownerCommitment,
      incomingTags,
      selfTags,
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
    const ephPub: Point = recoverEvenY(ephemeralX);
    const cek = await memberReadIncoming(
      new Fr(cekWrap),
      source.viewKey,
      ephPub,
    );
    return this.#recover(event, cek, true, undefined, source.index);
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
