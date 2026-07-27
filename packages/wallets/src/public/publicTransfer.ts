import { Fr } from "@aztec/foundation/fields";
import { Interface, getAddress } from "ethers";
import { Point } from "@zk-kit/baby-jubjub";
import { decodeHisokaPublicAddress, HisokaPublicAddress } from "../address.js";
import { addressToFr } from "../crypto/fields.js";
import { assertBjjSubgroupPoint } from "../note/keys.js";
import { randScalar } from "../tss/bjj.js";
import {
  assertMemoAsset,
  assertMemoTimelock,
  assertMemoValue,
  PublicMemo,
  PublicMemoError,
  publicMemoId,
  PublicMemoTerms,
} from "./memo.js";

// Argument ORDER is the ABI and differs from the memoId preimage order; both orders are pinned by tests.
const DARKPOOL_INTERFACE = new Interface([
  "function publicTransfer(uint256 ownerX, uint256 ownerY, address asset, uint256 value, uint256 timelock, uint256 salt)",
]);
const ERC20_INTERFACE = new Interface([
  "function approve(address spender, uint256 value) returns (bool)",
]);

/** A non-payable call any wallet can send as-is: `signer.sendTransaction(call)`. */
export interface EvmCall {
  to: string;
  data: string;
}

export interface PublicTransferRequest {
  darkPool: string;
  recipient: string | HisokaPublicAddress;
  asset: string;
  value: bigint;
  timelock?: bigint;
  /** Omit for a fresh random salt; supply one only to reproduce a specific memoId. */
  salt?: Fr;
}

export interface PublicTransferPlan {
  /** Exact-amount ERC20 approval; DarkPool pulls `value` inside publicTransfer. */
  approval: EvmCall;
  transfer: EvmCall;
  memo: PublicMemo;
  ownerPub: Point<bigint>;
  recipientIndex: bigint;
}

function requireAddress(value: string, field: string): string {
  try {
    return getAddress(value);
  } catch {
    throw new PublicMemoError(
      `publicTransfer ${field} is not a valid EVM address: ${value}`,
    );
  }
}

function resolveRecipient(
  recipient: string | HisokaPublicAddress,
): HisokaPublicAddress {
  if (typeof recipient !== "string") return recipient;
  try {
    return decodeHisokaPublicAddress(recipient);
  } catch (err) {
    const reason = err instanceof Error ? err.message : "unknown error";
    throw new PublicMemoError(`publicTransfer recipient rejected: ${reason}`);
  }
}

/** Everything a plain MetaMask sender needs to fund a Hisoka public address: no proof, no wallet state.
 *  The memo carries no depositor, so an owner point outside the prime-order subgroup burns the escrow
 *  unrecoverably and DarkPool only checks the curve equation; this validates before any gas is spent. */
export async function buildPublicTransfer(
  request: PublicTransferRequest,
): Promise<PublicTransferPlan> {
  const darkPool = requireAddress(request.darkPool, "darkPool");
  const asset = requireAddress(request.asset, "asset");
  const recipient = resolveRecipient(request.recipient);

  try {
    assertBjjSubgroupPoint(
      recipient.ownerPub,
      "publicTransfer recipient point",
    );
  } catch (err) {
    const reason = err instanceof Error ? err.message : "unknown error";
    throw new PublicMemoError(
      `${reason} Funds sent to it are claimable by no public_claim witness and are lost; re-check the recipient address.`,
    );
  }

  const timelock = request.timelock ?? 0n;
  assertMemoValue(request.value);
  assertMemoTimelock(timelock);
  const assetId = addressToFr(asset);
  assertMemoAsset(assetId);

  // memoId is the escrow key: repeating (owner, asset, value, timelock) under a reused salt hits the live
  // memo and DarkPool reverts MemoCollision, so every send draws a fresh one.
  const salt = request.salt ?? new Fr(randScalar());
  const terms: PublicMemoTerms = {
    assetId,
    value: request.value,
    timelock,
    salt,
  };
  const memoId = await publicMemoId(terms, recipient.ownerPub);

  return {
    approval: {
      to: asset,
      data: ERC20_INTERFACE.encodeFunctionData("approve", [
        darkPool,
        request.value,
      ]),
    },
    transfer: {
      to: darkPool,
      data: DARKPOOL_INTERFACE.encodeFunctionData("publicTransfer", [
        recipient.ownerPub[0],
        recipient.ownerPub[1],
        asset,
        request.value,
        timelock,
        salt.toBigInt(),
      ]),
    },
    memo: { ...terms, memoId },
    ownerPub: recipient.ownerPub,
    recipientIndex: recipient.index,
  };
}
