import { Point } from "@zk-kit/baby-jubjub";
import { Fr } from "@aztec/foundation/fields";
import { WalletNote } from "../state/types.js";
import { IKeyRepository } from "../repositories.js";
import {
  unpackNotePlaintext,
  unpackCiphertext,
  aes128Decrypt,
  kdfToAesKeyIV,
  deriveSharedSecret,
  recipientDecrypt3Party,
  deriveNullifier,
  toFr,
  PaddingError,
  NotePlaintext,
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
      const nk = await this.keyRepository.getNullifyingKey();
      const nullifier = await deriveNullifier(nk, commitment, leafIndex);

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
      const { intermediateBobX, intermediateBobY, packedCiphertext } =
        event.args;
      if (!intermediateBobX || !intermediateBobY) return null;

      const intPoint: Point<bigint> = [
        BigInt(intermediateBobX),
        BigInt(intermediateBobY),
      ];
      const packed = packedCiphertext.map((h) => toFr(h));
      const ciphertext = unpackCiphertext(packed);

      // No static tag: recover S_point = ivk * int_bob for each candidate ivk and trial-decrypt. A wrong
      // ivk yields a garbage AES key whose PKCS#7 padding fails (~2^-128 false-accept), so the first
      // candidate that decrypts cleanly owns the note.
      let decrypted: { note: NotePlaintext; sharedSecret: Fr } | null = null;
      let matchIndex = -1;
      for (const cand of this.keyRepository.getIncomingCandidates()) {
        try {
          decrypted = await recipientDecrypt3Party(
            cand.key,
            intPoint,
            ciphertext,
          );
          matchIndex = cand.index;
          break;
        } catch (e) {
          if (e instanceof PaddingError) continue;
          throw e;
        }
      }
      if (!decrypted) return null;

      this.keyRepository.recordIncomingMatch(matchIndex);

      const commitment = toFr(event.args.commitment);
      const index = event.args.leafIndex;
      const nk = await this.keyRepository.getNullifyingKey();
      const nullifier = await deriveNullifier(nk, commitment, Number(index));

      return {
        note: decrypted.note,
        commitment,
        leafIndex: Number(index),
        nullifier,
        spendingSecret: decrypted.sharedSecret,
        isTransfer: true,
        derivationIndex: matchIndex,
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
