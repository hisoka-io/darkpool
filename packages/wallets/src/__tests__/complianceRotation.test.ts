/**
 * Compliance-key rotation must not delete balance.
 *
 * A note binds its content key to the compliance key current AT MINT TIME, and `rotateComplianceKey`
 * replaces that key without touching any existing note. A scanner holding only the latest key derives the
 * wrong cek for every older note, the leaf check fails, and `process` used to return null with no log: a
 * seed-only reinstall then reported a smaller balance than the wallet actually owned.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { NoteProcessor } from "../sync/NoteProcessor";
import { UnprocessedEvent } from "../sync/types";
import { ComplianceKeyRing, ComplianceKeyError } from "../note/complianceKeys";
import { mintSelfNote, mintIncomingNote } from "../note/mint";
import { demEncrypt } from "../crypto/dem";
import { toFr } from "../crypto/fields";
import { publicKey, isEvenY } from "../note/keys";
import type { DerivedEph } from "../types/ephemeral";
import {
  IKeyRepository,
  IncomingAddress,
  KeyRepoState,
  SelfEphemeral,
} from "../repositories";
import {
  MultisigScanner,
  canonicalMultisigSelfTag,
  multisigAddress,
  selfNoteEvent,
  NOTE_TYPE_MULTISIG,
} from "../frost/index.js";
import {
  scalarBaseMul,
  randScalar,
  type Point as BjjPoint,
} from "../tss/bjj.js";
import { deriveCek } from "../crypto/kem";
import { computePsi } from "../note/nullifier";
import { leaf as computeLeaf, type Note } from "../note/note";

const KEY_V0: Point<bigint> = mulPointEscalar(Base8, 111111n);
const KEY_V1: Point<bigint> = mulPointEscalar(Base8, 222222n);
const KEY_V2: Point<bigint> = mulPointEscalar(Base8, 333333n);
const SELF_SPEND = new Fr(789n);
const IN_KEY = new Fr(31n);
const ASSET = toFr(0x1234567890123456789012345678901234567890n);
const eph = (n: bigint): DerivedEph => new Fr(n) as DerivedEph;

/** A memo event carries only eph_pub.x, so the scanner recovers the EVEN-y point; roll until it is one. */
function evenYEph(seed: bigint): Fr {
  let s = seed;
  while (!isEvenY(publicKey(new Fr(s)))) s += 1n;
  return new Fr(s);
}

class Repo implements IKeyRepository {
  readonly selfScanIndex = 0;
  readonly incomingScanIndex = 0;
  constructor(
    private readonly selfTags: Map<string, { eph: Fr; index: number }>,
    private readonly incomingTags: Map<string, { inKey: Fr; index: number }>,
  ) {}
  matchSelfTag(tag: bigint | string) {
    return this.selfTags.get(new Fr(BigInt(tag)).toString()) ?? null;
  }
  matchIncomingTag(tag: bigint | string) {
    return this.incomingTags.get(new Fr(BigInt(tag)).toString()) ?? null;
  }
  async getSelfSpendScalar(): Promise<Fr> {
    return SELF_SPEND;
  }
  async getSelfSpendPub(): Promise<Point<bigint>> {
    return publicKey(SELF_SPEND);
  }
  recordIncomingMatch(): void {}
  async ensureSelfLookahead(): Promise<boolean> {
    return false;
  }
  async ensureIncomingLookahead(): Promise<boolean> {
    return false;
  }
  nextSelfEphemeral(): Promise<SelfEphemeral> {
    return Promise.reject(new Error("fixture does not mint"));
  }
  nextIncomingAddress(): Promise<IncomingAddress> {
    return Promise.reject(new Error("fixture does not issue"));
  }
  getState(): KeyRepoState {
    throw new Error("fixture is not durable");
  }
  async restore(): Promise<void> {}
}

/** Mint a self note under `key` and render the chain event a scanner would see. */
async function selfNoteAt(
  key: Point<bigint>,
  index: bigint,
  value: bigint,
  blockNumber: number,
): Promise<{ event: UnprocessedEvent; repo: Repo }> {
  const minted = await mintSelfNote(eph(index), value, SELF_SPEND, ASSET, key);
  const ct = await demEncrypt(minted.cek, [
    minted.note.noteVersion,
    minted.note.assetId,
    minted.note.noteType,
    minted.note.conditionsHash,
    minted.note.value,
    minted.note.owner,
    minted.note.parents,
  ]);
  const repo = new Repo(
    new Map([[minted.tag.toString(), { eph: minted.eph, index: 0 }]]),
    new Map(),
  );
  return {
    repo,
    event: {
      type: "NEW_NOTE",
      blockNumber,
      txHash: "0x00",
      args: {
        leafIndex: index,
        commitment: minted.commitment.toString(),
        ephemeralX: minted.ephPub[0],
        packedCiphertext: ct.map((f) => f.toString()),
      },
    },
  };
}

afterEach(() => vi.restoreAllMocks());

describe("compliance-key rotation", () => {
  // The defect, stated as money: this exact assertion fails without the key ring.
  it("recovers a note minted BEFORE a rotation", async () => {
    const { event, repo } = await selfNoteAt(KEY_V0, 4n, 250n, 100);
    const ring = ComplianceKeyRing.from([
      { version: 1, pk: KEY_V0, fromBlock: 0 },
      { version: 2, pk: KEY_V1, fromBlock: 500 },
    ]);

    const note = await new NoteProcessor(repo, ring).process(event);
    expect(note).not.toBeNull();
    expect(note!.note.value).toBe(250n);
  });

  // The control. Without it the test above could pass for reasons unrelated to the ring.
  it("a scanner holding ONLY the post-rotation key loses that note, and says so", async () => {
    const { event, repo } = await selfNoteAt(KEY_V0, 4n, 250n, 100);
    const err = vi.spyOn(console, "error").mockImplementation(() => {});

    const processor = new NoteProcessor(repo, KEY_V1);
    expect(await processor.process(event)).toBeNull();

    // The whole point of the fix: the loss is no longer silent.
    expect(processor.unopenableNoteCount).toBe(1);
    expect(err).toHaveBeenCalledTimes(1);
    expect(String(err.mock.calls[0]![0])).toMatch(/UNDER-reported/);
  });

  it("recovers notes from EVERY version across two rotations", async () => {
    const ring = ComplianceKeyRing.from([
      { version: 1, pk: KEY_V0, fromBlock: 0 },
      { version: 2, pk: KEY_V1, fromBlock: 500 },
      { version: 3, pk: KEY_V2, fromBlock: 900 },
    ]);
    for (const [i, [key, block]] of (
      [
        [KEY_V0, 100],
        [KEY_V1, 600],
        [KEY_V2, 950],
      ] as const
    ).entries()) {
      const { event, repo } = await selfNoteAt(key, BigInt(i + 1), 10n, block);
      const note = await new NoteProcessor(repo, ring).process(event);
      expect(note, `version ${i} note`).not.toBeNull();
      expect(note!.note.value).toBe(10n);
    }
  });

  // A wallet that knows the ORDER of rotations but not the blocks must still recover everything.
  it("works with no block information at all", async () => {
    const { event, repo } = await selfNoteAt(KEY_V0, 7n, 42n, 100);
    const ring = ComplianceKeyRing.from([
      { version: 1, pk: KEY_V0 },
      { version: 2, pk: KEY_V1 },
    ]);
    expect(await new NoteProcessor(repo, ring).process(event)).not.toBeNull();
  });

  it("a bare key still works, so existing single-version callers are unaffected", async () => {
    const { event, repo } = await selfNoteAt(KEY_V0, 3n, 99n, 10);
    const note = await new NoteProcessor(repo, KEY_V0).process(event);
    expect(note!.note.value).toBe(99n);
  });

  // Proves the memo path was correctly left alone rather than overlooked.
  it("an incoming memo is rotation-independent: its cek travels in cekWrap", async () => {
    const inPub = publicKey(IN_KEY);
    const minted = await mintIncomingNote(
      evenYEph(55n),
      77n,
      inPub,
      IN_KEY,
      ASSET,
      KEY_V0,
    );
    const ct = await demEncrypt(minted.cek, [
      minted.note.noteVersion,
      minted.note.assetId,
      minted.note.noteType,
      minted.note.conditionsHash,
      minted.note.value,
      minted.note.owner,
      minted.note.parents,
    ]);
    const repo = new Repo(
      new Map(),
      new Map([[minted.tag.toString(), { inKey: IN_KEY, index: 0 }]]),
    );
    // Scanner carries ONLY the post-rotation key and still recovers it.
    const note = await new NoteProcessor(repo, KEY_V2).process({
      type: "NEW_MEMO",
      blockNumber: 900,
      txHash: "0x00",
      args: {
        leafIndex: 9n,
        commitment: minted.commitment.toString(),
        ephemeralX: minted.ephPub[0],
        packedCiphertext: ct.map((f) => f.toString()),
        tag: minted.tag.toBigInt(),
        cekWrap: minted.cekWrap!.toBigInt(),
      },
    });
    expect(note).not.toBeNull();
    expect(note!.note.value).toBe(77n);
  });
});

describe("ComplianceKeyRing", () => {
  it("builds from the pool's rotation log", () => {
    const ring = ComplianceKeyRing.fromRotations(
      KEY_V0,
      [
        {
          oldVersion: 1,
          newVersion: 2,
          newX: KEY_V1[0],
          newY: KEY_V1[1],
          blockNumber: 500,
        },
        {
          oldVersion: 2,
          newVersion: 3,
          newX: KEY_V2[0],
          newY: KEY_V2[1],
          blockNumber: 900,
        },
      ],
      0,
    );
    expect(ring.epochs.map((e) => e.version)).toEqual([1, 2, 3]);
    expect(ring.currentVersion).toBe(3);
    expect(ring.current).toEqual(KEY_V2);
  });

  it("tries the epoch covering the block FIRST, then the rest", () => {
    const ring = ComplianceKeyRing.fromRotations(KEY_V0, [
      {
        oldVersion: 1,
        newVersion: 2,
        newX: KEY_V1[0],
        newY: KEY_V1[1],
        blockNumber: 500,
      },
      {
        oldVersion: 2,
        newVersion: 3,
        newX: KEY_V2[0],
        newY: KEY_V2[1],
        blockNumber: 900,
      },
    ]);
    expect(ring.candidatesFor(600).map((e) => e.version)).toEqual([2, 3, 1]);
    // Never a subset: an approximate fromBlock must not be able to hide a version.
    expect(ring.candidatesFor(600)).toHaveLength(3);
  });

  it("falls back to newest-first when the block is unknown", () => {
    const ring = ComplianceKeyRing.from([
      { version: 1, pk: KEY_V0 },
      { version: 2, pk: KEY_V1 },
    ]);
    expect(ring.candidatesFor().map((e) => e.version)).toEqual([2, 1]);
  });

  it("fails CLOSED on an empty ring", () => {
    expect(() => ComplianceKeyRing.from([])).toThrow(ComplianceKeyError);
  });

  it("rejects a duplicated version, which means two histories were merged", () => {
    expect(() =>
      ComplianceKeyRing.from([
        { version: 1, pk: KEY_V0 },
        { version: 1, pk: KEY_V1 },
      ]),
    ).toThrow(/appears twice/);
  });
});

/**
 * The multisig scanner carries the same binding and shipped the same blindness, on the published
 * `./frost` subpath. Covered here rather than in `multisig-note.test.ts` so the rotation invariant reads
 * as one property across both scanners.
 */
describe("compliance-key rotation: multisig scanner", () => {
  function evenYViewKey(): Fr {
    for (let i = 0; i < 256; i++) {
      const v = new Fr(randScalar());
      if (isEvenY(scalarBaseMul(v.toBigInt()))) return v;
    }
    throw new Error("no even-y view key sampled");
  }

  async function encryptMultisigNote(cek: Fr, owner: Fr, value: bigint) {
    const psi = await computePsi(cek);
    const note: Note = {
      noteVersion: new Fr(1n),
      assetId: new Fr(0xfeedn),
      noteType: new Fr(NOTE_TYPE_MULTISIG),
      conditionsHash: new Fr(0n),
      value,
      owner,
      psi,
      parents: new Fr(0n),
    };
    return {
      note,
      commitment: await computeLeaf(note),
      ciphertext: await demEncrypt(cek, [
        note.noteVersion,
        note.assetId,
        note.noteType,
        note.conditionsHash,
        new Fr(value),
        note.owner,
        note.parents,
      ]),
    };
  }

  async function groupNoteUnder(key: BjjPoint, v: Fr, gpk: BjjPoint) {
    const { ownerCommitment } = await multisigAddress(gpk, v);
    const tag = await canonicalMultisigSelfTag(v, 2n, 0n);
    const enc = await encryptMultisigNote(
      deriveCek(tag.eph, key),
      ownerCommitment,
      50n,
    );
    return selfNoteEvent({
      leafIndex: 4n,
      note: enc.note,
      commitment: enc.commitment,
      ephPub: tag.ephPub,
      packedCiphertext: enc.ciphertext,
    });
  }

  it("recovers a group note minted BEFORE a rotation", async () => {
    const gpk: BjjPoint = scalarBaseMul(randScalar());
    const v = evenYViewKey();
    const event = await groupNoteUnder(KEY_V0, v, gpk);

    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk: ComplianceKeyRing.from([
        { version: 1, pk: KEY_V0 },
        { version: 2, pk: KEY_V1 },
      ]),
      memberIds: [1n, 2n, 3n],
      selfWindow: 16,
    });

    const view = await scanner.readNote(event);
    expect(view).not.toBeNull();
    expect(view!.note.value).toBe(50n);
    expect(scanner.unopenableNoteCount).toBe(0);
  });

  it("a group scanner holding ONLY the post-rotation key loses that note, and says so", async () => {
    const gpk: BjjPoint = scalarBaseMul(randScalar());
    const v = evenYViewKey();
    const event = await groupNoteUnder(KEY_V0, v, gpk);
    const err = vi.spyOn(console, "error").mockImplementation(() => {});

    const scanner = await MultisigScanner.create({
      v,
      gpk,
      compliancePk: KEY_V1,
      memberIds: [1n, 2n, 3n],
      selfWindow: 16,
    });

    expect(await scanner.readNote(event)).toBeNull();
    expect(scanner.unopenableNoteCount).toBe(1);
    expect(String(err.mock.calls[0]![0])).toMatch(/UNDER-reported/);
  });
});
