import { Fr } from '@aztec/foundation/fields';
import { Point } from '@zk-kit/baby-jubjub';

export interface IKeyDeriver {
  derive(purpose: string, master: Fr, nonce?: Fr): Promise<Fr>;
}

export interface IUTXO {
  getNullifierHash(): Promise<Fr>;
}

export interface IDarkAccount {
  getSpendKey(): Promise<Fr>;
  getViewKey(): Promise<Fr>;

  getIncomingViewingKey(index: bigint): Promise<Fr>;
  getPublicIncomingViewingKey(index: bigint): Promise<Point<bigint>>;
  getEphemeralOutgoingKey(index: bigint): Promise<Fr>;
  getPublicEphemeralOutgoingKey(index: bigint): Promise<Point<bigint>>;
}