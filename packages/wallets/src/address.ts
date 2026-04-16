import { packPoint, Point, unpackPoint } from "@zk-kit/baby-jubjub";
import bs58check from "bs58check";
import { DLEQProof } from "./crypto/dleq.js";

export type HisokaAddressData = {
  B: Point<bigint>;
  P: Point<bigint>;
  pi: DLEQProof;
};

const ADDRESS_PREFIX = "hiso";

function bigintTo32BufferBE(num: bigint): Buffer {
  if (num < 0n) {
    throw new Error("Cannot convert negative bigint to buffer.");
  }
  let hex = num.toString(16);
  if (hex.length % 2 !== 0) {
    hex = "0" + hex;
  }
  const paddedHex = hex.padStart(64, "0");
  return Buffer.from(paddedHex, "hex");
}

export function encodeHisokaAddress(data: HisokaAddressData): string {
  const { B, P, pi } = data;
  const { U, V, z } = pi;

  const payload = Buffer.concat([
    bigintTo32BufferBE(packPoint(B)),
    bigintTo32BufferBE(packPoint(P)),
    bigintTo32BufferBE(packPoint(U)),
    bigintTo32BufferBE(packPoint(V)),
    bigintTo32BufferBE(z),
  ]);


  return `${ADDRESS_PREFIX}_${bs58check.encode(payload)}`;
}

export function decodeHisokaAddress(address: string): HisokaAddressData {
  const parts = address.split("_");
  if (parts.length !== 2 || parts[0] !== ADDRESS_PREFIX) {
    throw new Error("Invalid Hisoka address format or prefix.");
  }

  const encodedPayload = parts[1];
  const payload = bs58check.decode(encodedPayload);

  if (payload.length !== 160) {
    throw new Error(
      `Invalid payload length. Expected 160 bytes, got ${payload.length}.`,
    );
  }

  const sliceToBigInt = (start: number): bigint => {
    const slice = payload.subarray(start, start + 32);
    const bufferSlice = Buffer.from(slice);
    return BigInt("0x" + bufferSlice.toString("hex"));
  };

  const packed_B = sliceToBigInt(0);
  const packed_P = sliceToBigInt(32);
  const packed_U = sliceToBigInt(64);
  const packed_V = sliceToBigInt(96);
  const z: bigint = sliceToBigInt(128);

  const B = unpackPoint(packed_B);
  const P = unpackPoint(packed_P);
  const U = unpackPoint(packed_U);
  const V = unpackPoint(packed_V);

  if (!B || !P || !U || !V) {
    throw new Error(
      "Failed to unpack one or more points from the address. The address may be corrupted or invalid.",
    );
  }

  const pi: DLEQProof = { U, V, z };

  return { B, P, pi };
}
