import { Fr } from "@aztec/foundation/fields";
import {
  commitmentPrefixMatches,
  computePsi,
  MAX_OCCURRENCES_PER_TAG,
  demDecrypt,
  leaf as computeLeaf,
  reconstructCiphertext,
  type DiscoverySource,
  type HowlNoteRecord,
  type OccurrenceRequest,
} from "@hisoka/wallets";

/**
 * The two-round-trip sync a real wallet performs against a discovery service.
 *
 * The shape is the product claim: round 1 probes occurrence 0 for every candidate tag and learns how many
 * notes each tag holds; round 2 fetches the remainder in one padded batch. Total round trips is 2 no matter
 * how deep the history, which is what a trial-decrypt pool cannot do.
 */

export interface TagCandidate {
  readonly tag: Fr;
  /** The CEK for a row under this tag. Self rows derive it; incoming rows unwrap it from the row. */
  readonly cekFor: (record: HowlNoteRecord) => Promise<Fr>;
  /** The owner commitment this wallet would put in the note, recomputed locally and never fetched. */
  readonly ownerCommitment: Fr;
}

export interface DiscoveredNote {
  readonly tag: Fr;
  readonly leafIndex: number;
  readonly plaintext: readonly Fr[];
}

export interface SyncResult {
  readonly notes: readonly DiscoveredNote[];
  /** Rows that came back but failed the local prefix check: probe misses and other people's notes. */
  readonly rejected: number;
  /**
   * Tags whose advertised occurrence count exceeded the cap and were fetched only up to it.
   *
   * Surfaced rather than thrown: throwing lets one hostile count wedge the whole sync, and silently
   * truncating loses notes the wallet owns. The caller is told which tags are incomplete so it can escalate.
   */
  readonly truncatedTags: readonly string[];
}

/**
 * Opens a row, or rejects it.
 *
 * The acceptance rule is the LEAF and it cannot be supplied by the caller, because the obvious weaker check
 * is tautological: `reconstructCiphertext` builds ciphertext word 5 FROM the expected owner, so decrypting
 * it returns that owner for any row under any key. Comparing the recomputed 8-field commitment against the
 * prefix the server sent is the only check that can actually fail, which is why a probe carries a prefix at
 * all.
 */
async function open(
  candidate: TagCandidate,
  record: HowlNoteRecord,
): Promise<DiscoveredNote | null> {
  try {
    const cek = await candidate.cekFor(record);
    const ciphertext = await reconstructCiphertext(
      record,
      cek,
      candidate.ownerCommitment,
    );
    const plaintext = await demDecrypt(cek, ciphertext);
    const psi = await computePsi(cek);
    const recomputed = await computeLeaf({
      noteVersion: plaintext[0],
      assetId: plaintext[1],
      noteType: plaintext[2],
      conditionsHash: plaintext[3],
      value: plaintext[4].toBigInt(),
      owner: plaintext[5],
      psi,
      parents: plaintext[6],
    });
    if (!commitmentPrefixMatches(record, recomputed)) return null;
    return { tag: candidate.tag, leafIndex: record.leafIndex, plaintext };
  } catch {
    // A row we cannot open is a miss, not an error: a cuckoo probe returns a row either way.
    return null;
  }
}

export async function syncViaDiscovery(
  source: DiscoverySource,
  candidates: readonly TagCandidate[],
): Promise<SyncResult> {
  const byTag = new Map(candidates.map((c) => [c.tag.toString(), c]));
  const notes: DiscoveredNote[] = [];
  const truncatedTags: string[] = [];
  let rejected = 0;

  // ROUND 1: occurrence 0 for every candidate, plus the count that makes round 2 exact.
  const first = await source.probeFirst(candidates.map((c) => c.tag));
  const follow: OccurrenceRequest[] = [];

  for (const entry of first) {
    const candidate = byTag.get(entry.tag.toString());
    if (candidate === undefined) continue;
    if (entry.record !== null) {
      const opened = await open(candidate, entry.record);
      if (opened) notes.push(opened);
      else rejected += 1;
    }
    const advertised = entry.occurrenceCount;
    const bounded = Math.min(advertised, MAX_OCCURRENCES_PER_TAG);
    if (advertised > bounded) truncatedTags.push(entry.tag.toString());
    for (let occ = 1; occ < bounded; occ++) {
      follow.push({ tag: entry.tag, occurrence: occ });
    }
  }

  // ROUND 2: every remaining occurrence, independent, one batch. There is never a round 3.
  const rest = await source.fetchOccurrences(follow);
  for (let i = 0; i < rest.length; i++) {
    const record = rest[i];
    if (record === null) continue;
    const candidate = byTag.get(follow[i].tag.toString());
    if (candidate === undefined) continue;
    const opened = await open(candidate, record);
    if (opened) notes.push(opened);
    else rejected += 1;
  }

  return { notes, rejected, truncatedTags };
}

/** Local false-hit rejection. A probe returns a row on a miss, so the prefix is checked before the leaf. */
export function prefixAccepts(record: HowlNoteRecord, commitment: Fr): boolean {
  return commitmentPrefixMatches(record, commitment);
}
