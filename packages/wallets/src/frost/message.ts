// TS mirror of the per-operation FROST spend message m (shared/src/frost.nr msg_* helpers) and the multisig
// owner commitment. These preimages are recomputed IN-CIRCUIT from the constrained public IO, so a byte drift
// here makes a multisig proof unverifiable. Each op binds exactly the public values defining its spend that
// are not already committed inside an output leaf. The membership root is chain-specific (genesis slot0 seeds
// the chain id), so binding root is the cross-chain-replay defense -- there is no explicit chain_id field.

import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";
import { Point } from "../tss/bjj.js";
import {
  ACTION_WITHDRAW,
  ACTION_TRANSFER,
  ACTION_SPLIT,
  ACTION_JOIN,
} from "../tss/domains.js";

async function poseidonFields(fields: bigint[]): Promise<bigint> {
  return (await Poseidon.hash(fields.map((x) => new Fr(x)))).toBigInt();
}

/** owner = Poseidon2(gpk.x, gpk.y). Matches Noir owner::pubkey_owner(gpk). */
export async function multisigOwner(gpk: Point): Promise<bigint> {
  return poseidonFields([gpk[0], gpk[1]]);
}

export async function msgWithdraw(args: {
  root: bigint;
  nullifier: bigint;
  changeLeaf: bigint;
  publicOut: bigint;
  asset: bigint;
  recipient: bigint;
  intentHash: bigint;
}): Promise<bigint> {
  return poseidonFields([
    ACTION_WITHDRAW,
    args.root,
    args.nullifier,
    args.changeLeaf,
    args.publicOut,
    args.asset,
    args.recipient,
    args.intentHash,
  ]);
}

export async function msgTransfer(args: {
  root: bigint;
  nullifier: bigint;
  memoLeaf: bigint;
  changeLeaf: bigint;
  asset: bigint;
}): Promise<bigint> {
  return poseidonFields([
    ACTION_TRANSFER,
    args.root,
    args.nullifier,
    args.memoLeaf,
    args.changeLeaf,
    args.asset,
  ]);
}

export async function msgSplit(args: {
  root: bigint;
  nullifier: bigint;
  out1Leaf: bigint;
  out2Leaf: bigint;
  asset: bigint;
}): Promise<bigint> {
  return poseidonFields([
    ACTION_SPLIT,
    args.root,
    args.nullifier,
    args.out1Leaf,
    args.out2Leaf,
    args.asset,
  ]);
}

export async function msgJoin(args: {
  root: bigint;
  nullifierA: bigint;
  nullifierB: bigint;
  outLeaf: bigint;
  asset: bigint;
}): Promise<bigint> {
  return poseidonFields([
    ACTION_JOIN,
    args.root,
    args.nullifierA,
    args.nullifierB,
    args.outLeaf,
    args.asset,
  ]);
}
