import { Point } from "@zk-kit/baby-jubjub";
import { WalletNote } from "../state/types.js";
import { IKeyRepository } from "../repositories.js";
import {
  unpackNotePlaintext,
  unpackCiphertext,
  aes128Decrypt,
  kdfToAesKeyIV,
  deriveSharedSecret,
  recipientDecrypt3Party,
  deriveNullifierPathA,
  deriveNullifierPathB,
  toFr,
} from "../crypto/index.js";
import { UnprocessedEvent } from "./types.js";

export class NoteProcessor {
  constructor(
    private readonly keyRepository: IKeyRepository,
    private readonly compliancePk: Point<bigint>,
  ) {}

  public async process(event: UnprocessedEvent): Promise<WalletNote | null> {
    if (event.type === "NEW_NOTE") {
      return this.processNewNote(event);
    } else if (event.type === "NEW_MEMO") {
      return this.processMemo(event);
    }
    return null;
  }

  private async processNewNote(
    event: UnprocessedEvent,
  ): Promise<WalletNote | null> {
    try {
      const { epkX, epkY, packedCiphertext } = event.args;
      const match = this.keyRepository.tryMatchDeposit(epkX, epkY);
      if (!match) return null;

      const packed = packedCiphertext.map((h) => toFr(h));
      const ciphertext = unpackCiphertext(packed);
      const sharedSecret = await deriveSharedSecret(
        match.key,
        this.compliancePk,
      );
      const { key, iv } = await kdfToAesKeyIV(sharedSecret);
      const plaintext = await aes128Decrypt(ciphertext, key, iv);
      const note = unpackNotePlaintext(plaintext);
      const commitment = toFr(event.args.commitment);
      const leafIndex = Number(event.args.leafIndex);
      const nullifier = note.nullifier.isZero()
        ? await deriveNullifierPathB(sharedSecret, commitment, leafIndex)
        : await deriveNullifierPathA(note.nullifier, commitment, leafIndex);

      return {
        note,
        commitment,
        leafIndex,
        nullifier,
        spendingSecret: sharedSecret,
        isTransfer: false,
        derivationIndex: match.index,
        spent: false,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : "unknown error";
      console.warn(
        `[NoteProcessor] processNewNote failed (block=${event.blockNumber}, leaf=${event.args.leafIndex}): ${msg}`,
      );
      return null;
    }
  }

  private async processMemo(
    event: UnprocessedEvent,
  ): Promise<WalletNote | null> {
    try {
      const { tag, intermediateBobX, intermediateBobY, packedCiphertext } =
        event.args;
      if (!tag || !intermediateBobX || !intermediateBobY) return null;

      const match = this.keyRepository.tryMatchTransfer(tag);
      if (!match) return null;

      const intPoint: Point<bigint> = [
        BigInt(intermediateBobX),
        BigInt(intermediateBobY),
      ];
      const packed = packedCiphertext.map((h) => toFr(h));
      const ciphertext = unpackCiphertext(packed);

      const { note, sharedSecret } = await recipientDecrypt3Party(
        match.key,
        intPoint,
        ciphertext,
      );

      const commitment = toFr(event.args.commitment);
      const index = event.args.leafIndex;
      const nullifier = await deriveNullifierPathB(
        sharedSecret,
        commitment,
        Number(index),
      );

      return {
        note,
        commitment,
        leafIndex: Number(index),
        nullifier,
        spendingSecret: sharedSecret,
        isTransfer: true,
        derivationIndex: match.index,
        spent: false,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : "unknown error";
      console.warn(
        `[NoteProcessor] processMemo failed (block=${event.blockNumber}, leaf=${event.args.leafIndex}): ${msg}`,
      );
      return null;
    }
  }
}
