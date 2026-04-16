import { Fr } from "@aztec/foundation/fields";
import { Mnemonic, Signature } from "ethers";
import { Kdf } from "../crypto/Kdf.js";
import { toReducedFr } from "../crypto/fields.js";

import { Point, mulPointEscalar, Base8 } from "@zk-kit/baby-jubjub";
import { IDarkAccount } from "../interfaces.js";
import { toFr } from "../crypto/fields.js";

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
    return vk_master.add(tweak);
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
    return vk_master.add(tweak);
  }

  public async getPublicEphemeralOutgoingKey(
    index: bigint,
  ): Promise<Point<bigint>> {
    const esk = await this.getEphemeralOutgoingKey(index);
    return mulPointEscalar(Base8, esk.toBigInt());
  }

  private constructor(private readonly sk_root: Fr) {}

  public async getSpendKey(): Promise<Fr> {
    if (this._sk_spend === undefined) {
      this._sk_spend = await Kdf.derive("hisoka.spend", this.sk_root);
    }
    return this._sk_spend;
  }

  public async getViewKey(): Promise<Fr> {
    if (this._sk_view === undefined) {
      this._sk_view = await Kdf.derive("hisoka.view", this.sk_root);
    }
    return this._sk_view;
  }

  public static async fromMnemonic(mnemonic: string): Promise<DarkAccount> {
    try {
      Mnemonic.fromPhrase(mnemonic);
    } catch {
      throw new DerivationError("Invalid mnemonic");
    }
    const seedBytes = await mnemonicToSeed(mnemonic);
    const seedHex = Array.from(seedBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const sk_root = await Kdf.derive(
      "hisoka.mnemonic",
      toReducedFr("0x" + seedHex),
    );
    return new DarkAccount(sk_root);
  }

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
