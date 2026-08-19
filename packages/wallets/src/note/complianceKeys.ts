import { Point } from "@zk-kit/baby-jubjub";

/**
 * The compliance key history a scanner needs to open its own notes.
 *
 * A note binds its content key to the compliance key that was CURRENT WHEN IT WAS MINTED
 * (`cek = (eph * C).x`), and `rotateComplianceKey` changes that key without touching any existing note.
 * So a wallet holding only the latest key derives the wrong `cek` for every older note, the leaf check
 * fails, and the balance silently shrinks. The chain keeps only the current key in storage; the history
 * lives in the `ComplianceKeyRotated` log, which is public.
 */
export interface ComplianceKeyEpoch {
  /** The on-chain version this key was assigned; 0 is the key set at initialization. */
  readonly version: number;
  readonly pk: Point<bigint>;
  /**
   * Block at which this version became current. Optional because a caller may know the ORDER of
   * rotations without knowing where they landed; ordering alone is enough to stay correct, and a block
   * only makes the first attempt more likely to be the right one.
   */
  readonly fromBlock?: number;
}

/** Shape of one `ComplianceKeyRotated` log, as the scanner needs it. */
export interface ComplianceKeyRotation {
  readonly newVersion: number;
  readonly newX: bigint;
  readonly newY: bigint;
  readonly blockNumber?: number;
}

export class ComplianceKeyError extends Error {
  constructor(
    readonly reason: "EMPTY_RING" | "DUPLICATE_VERSION",
    message: string,
  ) {
    super(message);
    this.name = "ComplianceKeyError";
  }
}

/**
 * An ordered set of compliance key versions, newest last.
 *
 * Scanners try every version rather than guessing one. The cost is one ECDH per extra version on notes
 * that miss, and the alternative is a wallet that under-reports its balance with no error.
 */
export class ComplianceKeyRing {
  private readonly ordered: readonly ComplianceKeyEpoch[];

  private constructor(epochs: readonly ComplianceKeyEpoch[]) {
    if (epochs.length === 0) {
      throw new ComplianceKeyError(
        "EMPTY_RING",
        "a compliance key ring needs at least one key; a scanner with no key can open nothing",
      );
    }
    const seen = new Set<number>();
    for (const e of epochs) {
      if (seen.has(e.version)) {
        throw new ComplianceKeyError(
          "DUPLICATE_VERSION",
          `compliance key version ${e.version} appears twice; versions are unique on chain, so the caller merged two histories`,
        );
      }
      seen.add(e.version);
    }
    this.ordered = [...epochs].sort((a, b) => a.version - b.version);
  }

  /** A wallet that has never seen a rotation. Equivalent to the old single-key behaviour. */
  static of(pk: Point<bigint>, fromBlock?: number): ComplianceKeyRing {
    return new ComplianceKeyRing([
      { version: 0, pk, ...(fromBlock !== undefined ? { fromBlock } : {}) },
    ]);
  }

  static from(epochs: readonly ComplianceKeyEpoch[]): ComplianceKeyRing {
    return new ComplianceKeyRing(epochs);
  }

  /** Build from the genesis key plus the `ComplianceKeyRotated` logs read off the pool. */
  static fromRotations(
    genesis: Point<bigint>,
    rotations: readonly ComplianceKeyRotation[],
    genesisBlock?: number,
  ): ComplianceKeyRing {
    const epochs: ComplianceKeyEpoch[] = [
      {
        version: 0,
        pk: genesis,
        ...(genesisBlock !== undefined ? { fromBlock: genesisBlock } : {}),
      },
    ];
    for (const r of rotations) {
      epochs.push({
        version: r.newVersion,
        pk: [r.newX, r.newY] as Point<bigint>,
        ...(r.blockNumber !== undefined ? { fromBlock: r.blockNumber } : {}),
      });
    }
    return new ComplianceKeyRing(epochs);
  }

  /** Accepts either a bare key (the common single-version case) or a ring, so callers need not branch. */
  static coerce(source: Point<bigint> | ComplianceKeyRing): ComplianceKeyRing {
    return source instanceof ComplianceKeyRing
      ? source
      : ComplianceKeyRing.of(source);
  }

  get epochs(): readonly ComplianceKeyEpoch[] {
    return this.ordered;
  }

  /** The key a NEW note must be minted against; the pool rejects any other. */
  get current(): Point<bigint> {
    return this.ordered[this.ordered.length - 1]!.pk;
  }

  get currentVersion(): number {
    return this.ordered[this.ordered.length - 1]!.version;
  }

  /**
   * Every version, ordered by how likely it is to open a note seen at `blockNumber`: the epoch covering
   * that block first, then the rest newest-first. The full set is always returned, because a caller that
   * learned rotations from a partial log range has approximate blocks, and a missed note is worse than
   * a second ECDH.
   */
  candidatesFor(blockNumber?: number): readonly ComplianceKeyEpoch[] {
    const newestFirst = [...this.ordered].reverse();
    if (blockNumber === undefined) return newestFirst;

    const covering = newestFirst.find(
      (e) => e.fromBlock !== undefined && e.fromBlock <= blockNumber,
    );
    if (covering === undefined) return newestFirst;
    return [covering, ...newestFirst.filter((e) => e !== covering)];
  }
}
