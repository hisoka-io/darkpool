import { Fr } from "@aztec/foundation/fields";
import { Mnemonic, Signature } from "ethers";
import { Point } from "@zk-kit/baby-jubjub";
import { Kdf } from "../crypto/Kdf.js";
import { toReducedFr } from "../crypto/fields.js";
import { IDarkAccount } from "../interfaces.js";
import {
  CanonicalAddress,
  canonicalIncomingAddress,
  canonicalSelfTag,
  deriveIncomingKey,
  deriveSelfEphemeral,
  deriveSelfSpendKey,
  deriveViewKey,
  publicKey,
} from "../note/keys.js";

const MNEMONIC_LABEL = "hisoka.mnemonic";
const ROOT_LABEL = "hisoka.root";

async function mnemonicToSeed(mnemonic: string): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(mnemonic);
  const saltBytes = encoder.encode("mnemonic");
  return new Promise((resolve, reject) => {
    crypto.subtle
      .importKey("raw", passwordBytes, { name: "PBKDF2" }, false, [
        "deriveBits",
      ])
      .then((baseKey) =>
        crypto.subtle.deriveBits(
          {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 2048,
            hash: "SHA-512",
          },
          baseKey,
          512,
        ),
      )
      .then((bits) => resolve(new Uint8Array(bits)))
      .catch(reject);
  });
}

class DerivationError extends Error {
  constructor(msg: string) {
    super(`DarkAccount Derivation: ${msg}`);
  }
}

export class DarkAccount implements IDarkAccount {
  // #private (not TS `private`): key material is unreachable via spread/Object.keys/structuredClone.
  #skRoot: Fr;
  #skView?: Fr;
  #selfSpend?: Fr;

  private constructor(skRoot: Fr) {
    this.#skRoot = skRoot;
  }

  // Fail closed on JSON.stringify and redact on Node util.inspect -- the two key serialization/log paths.
  public toJSON(): never {
    throw new DerivationError("refusing to serialize key material");
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "DarkAccount <redacted>";
  }

  public async getViewKey(): Promise<Fr> {
    if (this.#skView === undefined) {
      this.#skView = await deriveViewKey(this.#skRoot);
    }
    return this.#skView;
  }

  public async getIncomingKey(index: bigint): Promise<Fr> {
    return deriveIncomingKey(await this.getViewKey(), index);
  }

  public async getIncomingPub(index: bigint): Promise<Point<bigint>> {
    return publicKey(await this.getIncomingKey(index));
  }

  public async getSelfEphemeral(index: bigint): Promise<Fr> {
    return deriveSelfEphemeral(await this.getViewKey(), index);
  }

  public async getSelfSpendKey(): Promise<Fr> {
    if (this.#selfSpend === undefined) {
      this.#selfSpend = await deriveSelfSpendKey(await this.getViewKey());
    }
    return this.#selfSpend;
  }

  public async getSelfSpendPub(): Promise<Point<bigint>> {
    return publicKey(await this.getSelfSpendKey());
  }

  public async canonicalIncomingAddress(
    startIndex: bigint,
  ): Promise<CanonicalAddress> {
    return canonicalIncomingAddress(await this.getViewKey(), startIndex);
  }

  public async canonicalSelfTag(startIndex: bigint): Promise<CanonicalAddress> {
    return canonicalSelfTag(await this.getViewKey(), startIndex);
  }

  public static async fromMnemonic(mnemonic: string): Promise<DarkAccount> {
    let canonicalPhrase: string;
    try {
      // Canonicalize via entropy: mixed case / whitespace variants of one mnemonic must derive one account.
      canonicalPhrase = Mnemonic.fromPhrase(mnemonic).phrase;
    } catch {
      throw new DerivationError("Invalid mnemonic");
    }
    const seedBytes = await mnemonicToSeed(canonicalPhrase);
    const seedHex = Array.from(seedBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const skRoot = await Kdf.derive(
      MNEMONIC_LABEL,
      toReducedFr("0x" + seedHex),
    );
    return new DarkAccount(skRoot);
  }

  // Sign-to-derive: signature IS the root secret -- MUST be deterministic AND never exposed/reused (its disclosure recovers sk_root).
  public static async fromSignature(signature: string): Promise<DarkAccount> {
    const sig = Signature.from(signature);
    const rHex = sig.r.slice(2);
    const sHex = sig.s.slice(2);
    const parityByte = sig.yParity ? "01" : "00";
    const sigHex = rHex + sHex + parityByte;
    const sigFr = toReducedFr("0x" + sigHex);
    const skRoot = await Kdf.derive(ROOT_LABEL, sigFr);
    return new DarkAccount(skRoot);
  }
}
