import { Fr } from "@aztec/foundation/fields";
import {
  decodeHowlNoteRecord,
  encodeHowlNoteRecord,
  HOWL_NOTE_CELL_BYTES,
  LEAF_BLOCK_SIZE,
  type DiscoverySource,
  type FirstOccurrence,
  type HowlNoteRecord,
  type OccurrenceRequest,
} from "@hisoka/wallets";

/**
 * A stand-in for Raven that is faithful about SHAPE and honest about CRYPTO.
 *
 * Faithful: the 256-byte cell, `(tag, occurrence)` keying, the occurrence count returned by round 1, a
 * probe returning a plausible row on a MISS, and DB2 as a plain block fetch that is deliberately not
 * private. Those are the properties an integration breaks on.
 *
 * Not faithful: cells are XOR-masked with a per-generation pad instead of encrypted under a PIR scheme, so
 * this provides NO query privacy. Rather than pretend otherwise it counts every query it serves, which is
 * what lets a test assert the property that actually matters: the number of round trips and rows fetched is
 * bounded and does not grow with the size of the pool.
 */

function xorMask(cell: Uint8Array, seed: number): Uint8Array {
  // Deliberately trivial. A real deployment gets its confidentiality from the PIR scheme, not from here.
  const out = new Uint8Array(cell.length);
  for (let i = 0; i < cell.length; i++) {
    out[i] = cell[i] ^ ((seed + i * 31) & 0xff);
  }
  return out;
}

export interface RavenQueryLog {
  /** Round trips, which is the number the two-round-trip design bounds at 2 per sync. */
  roundTrips: number;
  /** Rows requested. Under a real PIR this is the padded batch size. */
  rowsRequested: number;
  /** Rows that carried a real note. A miss still costs a row, which is the point of padding. */
  rowsHit: number;
  /** Blocks fetched from DB2. */
  blocksFetched: number;
}

export class MockRaven implements DiscoverySource {
  readonly #rows = new Map<string, Uint8Array>();
  readonly #counts = new Map<string, number>();
  readonly #leaves: Fr[] = [];
  readonly #generationSeed: number;
  #log: RavenQueryLog = {
    roundTrips: 0,
    rowsRequested: 0,
    rowsHit: 0,
    blocksFetched: 0,
  };

  constructor(generationSeed = 0x5a) {
    this.#generationSeed = generationSeed;
  }

  static key(tag: Fr, occurrence: number): string {
    return `${tag.toString()}:${occurrence}`;
  }

  /** Indexer side. Appends a note under its tag, assigning the next occurrence by insertion order. */
  insert(tag: Fr, record: HowlNoteRecord): number {
    const occurrence = this.#counts.get(tag.toString()) ?? 0;
    this.#rows.set(
      MockRaven.key(tag, occurrence),
      xorMask(encodeHowlNoteRecord(record), this.#generationSeed),
    );
    this.#counts.set(tag.toString(), occurrence + 1);
    return occurrence;
  }

  /** DB2 side. Leaves are appended in tree order, exactly as the chain emits them. */
  appendLeaf(commitment: Fr): void {
    this.#leaves.push(commitment);
  }

  get noteCount(): number {
    return this.#rows.size;
  }

  get queryLog(): Readonly<RavenQueryLog> {
    return { ...this.#log };
  }

  resetQueryLog(): void {
    this.#log = {
      roundTrips: 0,
      rowsRequested: 0,
      rowsHit: 0,
      blocksFetched: 0,
    };
  }

  #read(tag: Fr, occurrence: number): HowlNoteRecord | null {
    const masked = this.#rows.get(MockRaven.key(tag, occurrence));
    if (masked === undefined) return null;
    const cell = xorMask(masked, this.#generationSeed);
    if (cell.length !== HOWL_NOTE_CELL_BYTES) {
      throw new Error(`stored cell is ${cell.length} bytes`);
    }
    return decodeHowlNoteRecord(cell);
  }

  async probeFirst(tags: readonly Fr[]): Promise<readonly FirstOccurrence[]> {
    this.#log.roundTrips += 1;
    this.#log.rowsRequested += tags.length;
    return tags.map((tag) => {
      const record = this.#read(tag, 0);
      if (record !== null) this.#log.rowsHit += 1;
      return {
        tag,
        record,
        occurrenceCount: this.#counts.get(tag.toString()) ?? 0,
      };
    });
  }

  async fetchOccurrences(
    requests: readonly OccurrenceRequest[],
  ): Promise<readonly (HowlNoteRecord | null)[]> {
    // An empty round 2 is not a round trip: nothing is sent when round 1 found no follow-ups.
    if (requests.length > 0) {
      this.#log.roundTrips += 1;
      this.#log.rowsRequested += requests.length;
    }
    return requests.map((r) => {
      const record = this.#read(r.tag, r.occurrence);
      if (record !== null) this.#log.rowsHit += 1;
      return record;
    });
  }

  async fetchLeafBlock(blockIndex: number): Promise<readonly Fr[]> {
    this.#log.blocksFetched += 1;
    const start = blockIndex * LEAF_BLOCK_SIZE;
    return this.#leaves.slice(start, start + LEAF_BLOCK_SIZE);
  }
}
