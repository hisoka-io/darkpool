import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { NotePlaintext, DLEQProof } from "@hisoka/wallets";

export type { NotePlaintext };

export interface DepositInputs {
  notePlaintext: NotePlaintext;
  ephemeralSk: Fr;
  compliancePk: Point<bigint>;
}

export interface WithdrawInputs {
  withdrawValue: Fr;
  recipient: Fr;
  merkleRoot: Fr;
  currentTimestamp: number;
  intentHash: Fr;
  compliancePk: Point<bigint>;

  oldNote: NotePlaintext;
  oldSharedSecret: Fr;
  oldNoteIndex: number;
  oldNotePath: Fr[];
  hashlockPreimage: Fr;

  changeNote: NotePlaintext;
  changeEphemeralSk: Fr;
}

export interface TransferInputs {
  merkleRoot: Fr;
  currentTimestamp: number;
  compliancePk: Point<bigint>;

  recipientB: Point<bigint>;
  recipientP: Point<bigint>;
  recipientProof: DLEQProof;

  oldNote: NotePlaintext;
  oldSharedSecret: Fr;
  oldNoteIndex: number;
  oldNotePath: Fr[];
  hashlockPreimage: Fr;

  memoNote: NotePlaintext;
  memoEphemeralSk: Fr;

  changeNote: NotePlaintext;
  changeEphemeralSk: Fr;
}

export interface ProofData {
  proof: Uint8Array;
  publicInputs: string[];
  verified: boolean;
}

export interface JoinInputs {
  merkleRoot: Fr;
  currentTimestamp: number;
  compliancePk: Point<bigint>;

  noteA: NotePlaintext;
  secretA: Fr;
  indexA: number;
  pathA: Fr[];
  preimageA: Fr; // hashlock preimage

  noteB: NotePlaintext;
  secretB: Fr;
  indexB: number;
  pathB: Fr[];
  preimageB: Fr;

  noteOut: NotePlaintext;
  skOut: Fr;
}

export interface SplitInputs {
  merkleRoot: Fr;
  currentTimestamp: number;
  compliancePk: Point<bigint>;

  noteIn: NotePlaintext;
  secretIn: Fr;
  indexIn: number;
  pathIn: Fr[];
  preimageIn: Fr;

  noteOut1: NotePlaintext;
  skOut1: Fr;

  noteOut2: NotePlaintext;
  skOut2: Fr;
}
export interface GasPaymentInputs {
  merkleRoot: Fr;
  currentTimestamp: number;
  paymentValue: Fr;
  paymentAssetId: Fr;
  relayerAddress: Fr;
  executionHash: Fr;
  compliancePk: Point<bigint>;

  oldNote: NotePlaintext;
  oldSharedSecret: Fr;
  oldNoteIndex: number;
  oldNotePath: Fr[];
  hashlockPreimage: Fr;

  changeNote: NotePlaintext;
  changeEphemeralSk: Fr;
}

export interface PublicClaimInputs {
  memoId: Fr;
  compliancePk: Point<bigint>;

  val: Fr;
  assetId: Fr;
  timelock: Fr;
  ownerX: Fr;
  ownerY: Fr;
  salt: Fr;

  recipientSk: Fr;
  noteOut: NotePlaintext;
  skOut: Fr;
}
