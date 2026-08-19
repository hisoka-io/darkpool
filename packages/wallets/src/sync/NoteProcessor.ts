import { Point } from "@zk-kit/baby-jubjub";
import { Fr } from "@aztec/foundation/fields";
import { WalletNote } from "../state/types.js";
import { IKeyRepository } from "../repositories.js";
import { toFr } from "../crypto/fields.js";
import { demDecrypt } from "../crypto/dem.js";
import { deriveCek, unwrapCek } from "../crypto/kem.js";
import { computeNullifier, computePsi } from "../note/nullifier.js";
import { leaf as computeLeaf, Note } from "../note/note.js";
import { publicKey, pubkeyOwner, recoverEvenY } from "../note/keys.js";
import { NOTE_TYPE_STANDARD } from "../frost/multisigNote.js";
import { ComplianceKeyRing } from "../note/complianceKeys.js";
import { UnprocessedEvent } from "./types.js";

// asset ids are ERC20 addresses; anything at or above 2^160 cannot be a real asset.
const ASSET_MODULUS = 1n << 160n;

/**
 * Why a decrypt attempt ended. `leafMismatch` is the ONLY outcome that another compliance key could
 * change: the leaf commits to the plaintext, so once it matches, the content key was right and a
 * different key cannot rescue a note this path rejects for any other reason.
 */
type RecoverOutcome =
  | { readonly kind: "note"; readonly note: WalletNote }
  | { readonly kind: "leafMismatch" }
  | { readonly kind: "rejected" };

export class NoteProcessor {
  private readonly keys: ComplianceKeyRing;
  #unopenable = 0;

  constructor(
    private readonly keyRepository: IKeyRepository,
    compliancePk: Point<bigint> | ComplianceKeyRing,
  ) {
    this.keys = ComplianceKeyRing.coerce(compliancePk);
  }

  /**
   * Notes whose tag matched this wallet but which no compliance key version could open. Non-zero means
   * the key ring is missing a version, and the reported balance is LOWER than the true one.
   */
  get unopenableNoteCount(): number {
    return this.#unopenable;
  }

  public async process(event: UnprocessedEvent): Promise<WalletNote | null> {
    if (event.type === "NEW_NOTE") {
      return this.processNewNote(event);
    }
    if (event.type === "NEW_MEMO") {
      return this.processMemo(event);
    }
    return null;
  }

  private async processNewNote(
    event: UnprocessedEvent,
  ): Promise<WalletNote | null> {
    try {
      const match = this.keyRepository.matchSelfTag(event.args.ephemeralX);
      if (!match) return null;

      const commitment = toFr(event.args.commitment);
      const leafIndex = Number(event.args.leafIndex);
      const spendScalar = await this.keyRepository.getSelfSpendScalar();

      // The tag came from this wallet's own key schedule, so the note IS ours. Only the compliance key
      // used to mint it is unknown, and it is whichever version was current at that block.
      const tried: number[] = [];
      for (const epoch of this.keys.candidatesFor(event.blockNumber)) {
        const cek = deriveCek(match.eph, epoch.pk);
        tried.push(epoch.version);
        // A wrong key decrypts to a uniformly random field element, so `value` lands outside u128 and
        // `leaf` THROWS far more often than it returns a clean mismatch. Both mean the same thing here:
        // wrong key, try the next one. Letting the throw escape would abandon the remaining versions.
        let outcome: RecoverOutcome;
        try {
          outcome = await this.recover(
            cek,
            event.args.packedCiphertext,
            commitment,
            leafIndex,
            spendScalar,
            false,
            match.index,
          );
        } catch {
          continue;
        }
        if (outcome.kind === "note") return outcome.note;
        if (outcome.kind === "rejected") return null;
      }

      this.reportUnopenable(event, tried);
      return null;
    } catch (err) {
      this.warn("processNewNote", event, err);
      return null;
    }
  }

  private async processMemo(
    event: UnprocessedEvent,
  ): Promise<WalletNote | null> {
    try {
      const { tag, cekWrap, ephemeralX } = event.args;
      if (tag === undefined || cekWrap === undefined) return null;

      const match = this.keyRepository.matchIncomingTag(tag);
      if (!match) return null;

      // The event carries only eph_pub.x; recover the even-y point off-chain before the ECDH.
      const ephPub: Point<bigint> = recoverEvenY(ephemeralX);
      const cek = await unwrapCek(new Fr(cekWrap), match.inKey, ephPub);
      const commitment = toFr(event.args.commitment);
      const leafIndex = Number(event.args.leafIndex);
      // Rotation-independent by construction: the content key travels in `cekWrap`, wrapped to the
      // recipient, so this path never touches the compliance key.
      const outcome = await this.recover(
        cek,
        event.args.packedCiphertext,
        commitment,
        leafIndex,
        match.inKey,
        true,
        match.index,
      );
      if (outcome.kind !== "note") return null;
      this.keyRepository.recordIncomingMatch(match.index);
      return outcome.note;
    } catch (err) {
      this.warn("processMemo", event, err);
      return null;
    }
  }

  private async recover(
    cek: Fr,
    packedCiphertext: string[],
    commitment: Fr,
    leafIndex: number,
    spendScalar: Fr,
    isIncoming: boolean,
    derivationIndex: number,
  ): Promise<RecoverOutcome> {
    const ciphertext = packedCiphertext.map((h) => toFr(h));
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

    const rebuilt = await computeLeaf(note);
    if (!rebuilt.equals(commitment)) return { kind: "leafMismatch" };

    // Allowlist, not a MULTISIG denylist: this path proves spend authority from one BJJ scalar, so any
    // non-STANDARD type it accepted would park an unspendable phantom balance.
    if (note.noteType.toBigInt() !== NOTE_TYPE_STANDARD)
      return { kind: "rejected" };
    if (note.owner.toBigInt() === 0n) return { kind: "rejected" };
    if (note.assetId.toBigInt() >= ASSET_MODULUS) return { kind: "rejected" };
    const selfOwner = await pubkeyOwner(publicKey(spendScalar));
    if (!note.owner.equals(selfOwner)) return { kind: "rejected" };

    const nullifier = await computeNullifier(psi, new Fr(BigInt(leafIndex)));
    return {
      kind: "note",
      note: {
        note,
        commitment,
        leafIndex,
        nullifier,
        spendScalar,
        isIncoming,
        derivationIndex,
        spent: false,
      },
    };
  }

  /**
   * A note this wallet minted that no key version opens. Loud on purpose: the silent version of this was
   * a balance that shrank after a compliance-key rotation with nothing to diagnose it by.
   */
  private reportUnopenable(event: UnprocessedEvent, tried: number[]): void {
    this.#unopenable += 1;
    console.error(
      `[NoteProcessor] self-tagged note at leaf ${event.args.leafIndex} (block ${event.blockNumber}) ` +
        `could not be opened by any known compliance key (tried versions ${tried.join(", ")}). ` +
        `Balance is UNDER-reported. Rebuild the key ring from the pool's ComplianceKeyRotated log.`,
    );
  }

  private warn(where: string, event: UnprocessedEvent, err: unknown): void {
    const msg = err instanceof Error ? err.message : "unknown error";
    console.warn(
      `[NoteProcessor] ${where} failed (block=${event.blockNumber}, leaf=${event.args.leafIndex}): ${msg}`,
    );
  }
}
