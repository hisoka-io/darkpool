import {
  packPoint,
  unpackPoint,
  Point,
  inCurve,
  mulPointEscalar,
  subOrder,
} from "@zk-kit/baby-jubjub";
import bs58check from "bs58check";

// Recipient's incoming discovery key in_pub_j plus the diversifier index j that produced it.
export type HisokaAddress = {
  inPub: Point<bigint>;
  index: bigint;
};

const ADDRESS_PREFIX = "hiso";
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
  if (!inCurve(point)) {
    throw new Error("Address point is not on the BabyJubJub curve.");
  }
  if (point[0] === 0n && point[1] === 1n) {
    throw new Error("Address point is the identity.");
  }
  const [ox, oy] = mulPointEscalar(point, subOrder);
  if (ox !== 0n || oy !== 1n) {
    throw new Error("Address point is not in the prime-order subgroup.");
  }
}

export function encodeHisokaAddress(addr: HisokaAddress): string {
  assertValidPoint(addr.inPub);
  const payload = Buffer.concat([
    bigintTo32BufferBE(packPoint(addr.inPub)),
    bigintTo32BufferBE(addr.index),
  ]);
  return `${ADDRESS_PREFIX}_${bs58check.encode(payload)}`;
}

export function decodeHisokaAddress(address: string): HisokaAddress {
  const parts = address.split("_");
  if (parts.length !== 2 || parts[0] !== ADDRESS_PREFIX) {
    throw new Error("Invalid Hisoka address format or prefix.");
  }

  const payload = bs58check.decode(parts[1]);
  if (payload.length !== PAYLOAD_BYTES) {
    throw new Error(
      `Invalid payload length. Expected ${PAYLOAD_BYTES} bytes, got ${payload.length}.`,
    );
  }

  const sliceToBigInt = (start: number): bigint => {
    const slice = Buffer.from(payload.subarray(start, start + FIELD_BYTES));
    return BigInt("0x" + slice.toString("hex"));
  };

  const inPub = unpackPoint(sliceToBigInt(0));
  if (!inPub) {
    throw new Error(
      "Failed to unpack the address point. The address may be corrupted or invalid.",
    );
  }
  assertValidPoint(inPub);

  return { inPub, index: sliceToBigInt(FIELD_BYTES) };
}
