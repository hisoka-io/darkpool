export enum SwapType {
  ExactInputSingle = 0,
  ExactInput = 1,
  ExactOutputSingle = 2,
  ExactOutput = 3,
}

export interface RecipientIdentity {
  ownerX: bigint;
  ownerY: bigint;
}

export interface ExactInputSingleParams {
  type: SwapType.ExactInputSingle;
  assetIn: string;
  assetOut: string;
  fee: number;
  recipient: RecipientIdentity;
  amountOutMin: bigint;
}

export interface ExactInputParams {
  type: SwapType.ExactInput;
  path: string;
  recipient: RecipientIdentity;
  amountOutMin: bigint;
}

export interface ExactOutputSingleParams {
  type: SwapType.ExactOutputSingle;
  assetIn: string;
  assetOut: string;
  fee: number;
  recipient: RecipientIdentity;
  amountOut: bigint;
  amountInMaximum: bigint;
}

export interface ExactOutputParams {
  type: SwapType.ExactOutput;
  path: string;
  recipient: RecipientIdentity;
  amountOut: bigint;
  amountInMaximum: bigint;
}

export type UniswapSwapParams =
  | ExactInputSingleParams
  | ExactInputParams
  | ExactOutputSingleParams
  | ExactOutputParams;
