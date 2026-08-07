import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { CanonicalAddress, PublicIncomingAddress } from "./note/keys.js";

export interface IUTXO {
  getNullifierHash(psi: Fr, leafIndex: number | bigint): Promise<Fr>;
}

export interface IDarkAccount {
  getViewKey(): Promise<Fr>;

  getIncomingKey(index: bigint): Promise<Fr>;
  getIncomingPub(index: bigint): Promise<Point<bigint>>;

  // A separate family from the incoming one: a public memo publishes its owner point, and an incoming
  // point's .x is the private discovery tag, so one key must never serve both.
  getPublicIncomingKey(index: bigint): Promise<Fr>;
  getPublicIncomingPub(index: bigint): Promise<Point<bigint>>;

  getSelfEphemeral(index: bigint): Promise<Fr>;
  getSelfSpendKey(): Promise<Fr>;
  getSelfSpendPub(): Promise<Point<bigint>>;

  getStateKey(): Promise<Fr>;

  canonicalIncomingAddress(startIndex: bigint): Promise<CanonicalAddress>;
  canonicalSelfTag(startIndex: bigint): Promise<CanonicalAddress>;
  canonicalPublicAddress(index: bigint): Promise<PublicIncomingAddress>;
}
