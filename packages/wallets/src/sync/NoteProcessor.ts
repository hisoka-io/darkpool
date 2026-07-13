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
import { UnprocessedEvent } from "./types.js";

// asset ids are ERC20 addresses; anything at or above 2^160 cannot be a real asset.
const ASSET_MODULUS = 1n << 160n;

export class NoteProcessor {
  constructor(
    private readonly keyRepository: IKeyRepository,
    private readonly compliancePk: Point<bigint>,
  ) {}

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

      const cek = deriveCek(match.eph, this.compliancePk);
      const commitment = toFr(event.args.commitment);
      const leafIndex = Number(event.args.leafIndex);
      const walletNote = await this.recover(
        cek,
        event.args.packedCiphertext,
        commitment,
        leafIndex,
        await this.keyRepository.getSelfSpendScalar(),
        false,
        match.index,
      );
      return walletNote;
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
      const walletNote = await this.recover(
        cek,
        event.args.packedCiphertext,
        commitment,
        leafIndex,
        match.inKey,
        true,
        match.index,
      );
      if (walletNote) this.keyRepository.recordIncomingMatch(match.index);
      return walletNote;
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
  ): Promise<WalletNote | null> {
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

    // A tag collision or a corrupt event only yields a matching leaf for the true owner's note.
    const rebuilt = await computeLeaf(note);
    if (!rebuilt.equals(commitment)) return null;

    // Defense-in-depth: an unspendable (owner 0), out-of-range-asset, or non-self-owned note is dropped
    // even when its leaf matches, so a malformed on-chain commitment never enters the spendable set.
    if (note.owner.toBigInt() === 0n) return null;
    if (note.assetId.toBigInt() >= ASSET_MODULUS) return null;
    // WN-1: bind the note owner to the key that decrypted it. `spendScalar` is the self-spend key for a self note
    // and the incoming key for a memo; both are the scalar behind `owner` (owner = pubkeyOwner(publicKey(that
    // key))). Enforcing it on the incoming path too drops a mismatched incoming note (owner != recipient) instead
    // of registering it as a phantom, unspendable balance (an overstatement, not theft).
    const selfOwner = await pubkeyOwner(publicKey(spendScalar));
    if (!note.owner.equals(selfOwner)) return null;

    const nullifier = await computeNullifier(psi, new Fr(BigInt(leafIndex)));
    return {
      note,
      commitment,
      leafIndex,
      nullifier,
      spendScalar,
      isIncoming,
      derivationIndex,
      spent: false,
    };
  }

  private warn(where: string, event: UnprocessedEvent, err: unknown): void {
    const msg = err instanceof Error ? err.message : "unknown error";
    console.warn(
      `[NoteProcessor] ${where} failed (block=${event.blockNumber}, leaf=${event.args.leafIndex}): ${msg}`,
    );
  }
}
