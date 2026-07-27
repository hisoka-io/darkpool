import { packPoint, unpackPoint, Point } from "@zk-kit/baby-jubjub";
import bs58check from "bs58check";
import { assertBjjSubgroupPoint, isEvenY } from "./note/keys.js";

export type HisokaAddress = {
  inPub: Point<bigint>;
  index: bigint;
};

/** Owner point of a `DarkPool.publicTransfer` memo: published in calldata, so it is a different key
 *  family from `HisokaAddress` and carries a different prefix to keep the two unmixable. */
export type HisokaPublicAddress = {
  ownerPub: Point<bigint>;
  index: bigint;
};

const ADDRESS_PREFIX = "hiso";
const PUBLIC_ADDRESS_PREFIX = "hisopub";
const FIELD_BYTES = 32;
const PAYLOAD_BYTES = FIELD_BYTES * 2;

function bigintTo32BufferBE(num: bigint): Buffer {
  if (num < 0n) {
    throw new Error("Cannot convert negative bigint to buffer.");
  }
  if (num >= 1n << 256n) {
    throw new Error("Value exceeds 32 bytes.");
  }
  let hex = num.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  const paddedHex = hex.padStart(64, "0");
  return Buffer.from(paddedHex, "hex");
}

function assertValidPoint(point: Point<bigint>): void {
  assertBjjSubgroupPoint(point, "Address point");
  if (!isEvenY(point)) {
    throw new Error("Address point has a non-canonical odd y.");
  }
}

function encodePayload(
  prefix: string,
  point: Point<bigint>,
  index: bigint,
): string {
  const payload = Buffer.concat([
    bigintTo32BufferBE(packPoint(point)),
    bigintTo32BufferBE(index),
  ]);
  return `${prefix}_${bs58check.encode(payload)}`;
}

function decodePayload(body: string): { point: Point<bigint>; index: bigint } {
  const payload = bs58check.decode(body);
  if (payload.length !== PAYLOAD_BYTES) {
    throw new Error(
      `Invalid payload length. Expected ${PAYLOAD_BYTES} bytes, got ${payload.length}.`,
    );
  }

  const sliceToBigInt = (start: number): bigint => {
    const slice = Buffer.from(payload.subarray(start, start + FIELD_BYTES));
    return BigInt("0x" + slice.toString("hex"));
  };

  const point = unpackPoint(sliceToBigInt(0));
  if (!point) {
    throw new Error(
      "Failed to unpack the address point. The address may be corrupted or invalid.",
    );
  }
  return { point, index: sliceToBigInt(FIELD_BYTES) };
}

function splitAddress(address: string): { prefix: string; body: string } {
  const parts = address.split("_");
  if (parts.length !== 2) {
    throw new Error("Invalid Hisoka address format or prefix.");
  }
  return { prefix: parts[0], body: parts[1] };
}

export function encodeHisokaAddress(addr: HisokaAddress): string {
  assertValidPoint(addr.inPub);
  return encodePayload(ADDRESS_PREFIX, addr.inPub, addr.index);
}

export function decodeHisokaAddress(address: string): HisokaAddress {
  const { prefix, body } = splitAddress(address);
  if (prefix === PUBLIC_ADDRESS_PREFIX) {
    throw new Error(
      `Wrong address kind: '${PUBLIC_ADDRESS_PREFIX}_' is a public receiving address, funded by DarkPool.publicTransfer from any wallet. Decode it with decodeHisokaPublicAddress; a private payment needs a '${ADDRESS_PREFIX}_' address.`,
    );
  }
  if (prefix !== ADDRESS_PREFIX) {
    throw new Error("Invalid Hisoka address format or prefix.");
  }

  const { point, index } = decodePayload(body);
  assertValidPoint(point);
  return { inPub: point, index };
}

export function encodeHisokaPublicAddress(addr: HisokaPublicAddress): string {
  // No even-y requirement: publicTransfer carries both owner coordinates, so `pub.x` never stands alone.
  assertBjjSubgroupPoint(addr.ownerPub, "Public address point");
  return encodePayload(PUBLIC_ADDRESS_PREFIX, addr.ownerPub, addr.index);
}

export function decodeHisokaPublicAddress(
  address: string,
): HisokaPublicAddress {
  const { prefix, body } = splitAddress(address);
  if (prefix === ADDRESS_PREFIX) {
    throw new Error(
      `Wrong address kind: '${ADDRESS_PREFIX}_' is a private payment address whose index belongs to the private discovery family, and publishing it in a public memo would deanonymize every private payment to that index. Use a '${PUBLIC_ADDRESS_PREFIX}_' address for publicTransfer.`,
    );
  }
  if (prefix !== PUBLIC_ADDRESS_PREFIX) {
    throw new Error("Invalid Hisoka public address format or prefix.");
  }

  const { point, index } = decodePayload(body);
  assertBjjSubgroupPoint(point, "Public address point");
  return { ownerPub: point, index };
}
