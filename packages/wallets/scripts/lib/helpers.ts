import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { toFr } from "../../src/crypto/fields.js";

/** Packs ciphertext buffer into Noir-compatible array format. */
export function packToNoir(ct: Buffer): string {
  const packed: string[] = [];
  let idx = 0;
  for (let p = 0; p < 7; p++) {
    let val = 0n;
    const bytesInThis = p < 6 ? 31 : 22;
    let power = 1n;
    for (let i = 0; i < bytesInThis; i++) {
      if (idx < ct.length) val += BigInt(ct[idx]) * power;
      power *= 256n;
      idx++;
    }
    packed.push(`0x${val.toString(16)}`);
  }
  return `[${packed.join(", ")}]`;
}

/** Formats a value as Fr string for Noir test output. */
export const fmt = (val: string | number | bigint | Fr) => {
  if (val instanceof Fr) return val.toString();
  return toFr(val).toString();
};

/** Formats a point for Noir test output. */
export const fmtPt = (p: Point<bigint>) =>
  `Point { x: ${fmt(p[0])}, y: ${fmt(p[1])} }`;
