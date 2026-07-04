import { Fr } from "@aztec/foundation/fields";
import { Mnemonic, Signature } from "ethers";
import { Kdf } from "../crypto/Kdf.js";
import { toReducedFr } from "../crypto/fields.js";

import { Point, mulPointEscalar, Base8 } from "@zk-kit/baby-jubjub";
import { IDarkAccount } from "../interfaces.js";
import { toFr } from "../crypto/fields.js";
import {
  toBjjScalar,
  signSpendBinding,
  SpendBinding,
} from "../crypto/index.js";

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
  private _sk_spend?: Fr;
  private _sk_view?: Fr;
  private _vk_master?: Fr;
  private _nk?: Fr;

  private async getMasterViewingKey(): Promise<Fr> {
    if (this._vk_master === undefined) {
      const sk_view = await this.getViewKey();
      this._vk_master = await Kdf.derive("hisoka.ivkMaster", sk_view);
    }
    return this._vk_master;
  }

  public async getIncomingViewingKey(index: bigint): Promise<Fr> {
    const vk_master = await this.getMasterViewingKey();
    const tweak = await Kdf.derive("hisoka.ivkTweak", vk_master, toFr(index));
    return toBjjScalar(vk_master.add(tweak));
  }

  public async getPublicIncomingViewingKey(
    index: bigint,
  ): Promise<Point<bigint>> {
    const ivk = await this.getIncomingViewingKey(index);
    return mulPointEscalar(Base8, ivk.toBigInt());
  }

  public async getEphemeralOutgoingKey(index: bigint): Promise<Fr> {
    const vk_master = await this.getMasterViewingKey();
    const tweak = await Kdf.derive("hisoka.eskTweak", vk_master, toFr(index));
    return toBjjScalar(vk_master.add(tweak));
  }

  public async getPublicEphemeralOutgoingKey(
    index: bigint,
  ): Promise<Point<bigint>> {
    const esk = await this.getEphemeralOutgoingKey(index);
    return mulPointEscalar(Base8, esk.toBigInt());
  }

  private constructor(private readonly sk_root: Fr) {}

  // Fail closed on JSON.stringify and redact on Node util.inspect -- the two key serialization/log paths.
  // TS `private` is compile-time only, so field enumeration (spread, Object.keys, structuredClone) still
  // exposes these; closing that needs `#private` fields. Symbol.for avoids a Node-only util import.
  public toJSON(): never {
    throw new DerivationError("refusing to serialize key material");
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "DarkAccount <redacted>";
  }

  public async getSpendKey(): Promise<Fr> {
    if (this._sk_spend === undefined) {
      this._sk_spend = await Kdf.derive("hisoka.spend", this.sk_root);
    }
    return this._sk_spend;
  }

  public async getNullifyingKey(): Promise<Fr> {
    if (this._nk === undefined) {
      const sk_spend = await this.getSpendKey();
      this._nk = toBjjScalar(await Kdf.derive("hisoka.nullify", sk_spend));
    }
    return this._nk;
  }

  public async getPublicSpendKey(): Promise<Point<bigint>> {
    const nk = await this.getNullifyingKey();
    return mulPointEscalar(Base8, nk.toBigInt());
  }

  public async signSpendBinding(index: bigint): Promise<SpendBinding> {
    const ivk = await this.getIncomingViewingKey(index);
    const pkSpend = await this.getPublicSpendKey();
    const nonce = toBjjScalar(
      await Kdf.derive("hisoka.spendBindNonce", ivk, toFr(pkSpend[0])),
    );
    return signSpendBinding(ivk.toBigInt(), pkSpend, nonce.toBigInt());
  }

  public async getViewKey(): Promise<Fr> {
    if (this._sk_view === undefined) {
      this._sk_view = await Kdf.derive("hisoka.view", this.sk_root);
    }
    return this._sk_view;
  }

  public static async fromMnemonic(mnemonic: string): Promise<DarkAccount> {
    let canonicalPhrase: string;
    try {
      // ethers reconstructs .phrase from entropy, so non-canonical renderings (mixed case, repeated
      // whitespace) of one valid mnemonic collapse to a single phrase; seeding from the raw input would
      // derive divergent accounts.
      canonicalPhrase = Mnemonic.fromPhrase(mnemonic).phrase;
    } catch {
      throw new DerivationError("Invalid mnemonic");
    }
    const seedBytes = await mnemonicToSeed(canonicalPhrase);
    const seedHex = Array.from(seedBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const sk_root = await Kdf.derive(
      "hisoka.mnemonic",
      toReducedFr("0x" + seedHex),
    );
    return new DarkAccount(sk_root);
  }

  /// Sign-to-derive: the signing message and signer MUST be deterministic, or a different
  /// signature derives a different account.
  public static async fromSignature(signature: string): Promise<DarkAccount> {
    const sig = Signature.from(signature);
    const rHex = sig.r.slice(2);
    const sHex = sig.s.slice(2);
    const parityByte = sig.yParity ? "01" : "00";
    const sigHex = rHex + sHex + parityByte;
    const sigFr = toReducedFr("0x" + sigHex);
    const sk_root = await Kdf.derive("hisoka.root", sigFr);
    return new DarkAccount(sk_root);
  }
}
