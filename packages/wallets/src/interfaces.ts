import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { CanonicalAddress } from "./note/keys.js";

export interface IKeyDeriver {
  derive(purpose: string, master: Fr, nonce?: Fr): Promise<Fr>;
}

export interface IUTXO {
  getNullifierHash(psi: Fr, leafIndex: number | bigint): Promise<Fr>;
}

export interface IDarkAccount {
  getViewKey(): Promise<Fr>;

  getIncomingKey(index: bigint): Promise<Fr>;
  getIncomingPub(index: bigint): Promise<Point<bigint>>;

  getSelfEphemeral(index: bigint): Promise<Fr>;
  getSelfSpendKey(): Promise<Fr>;
  getSelfSpendPub(): Promise<Point<bigint>>;

  canonicalIncomingAddress(startIndex: bigint): Promise<CanonicalAddress>;
  canonicalSelfTag(startIndex: bigint): Promise<CanonicalAddress>;
}
