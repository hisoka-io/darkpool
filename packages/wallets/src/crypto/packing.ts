import { Fr } from "@aztec/foundation/fields";
import { NotePlaintext, SizeError } from "./types.js";

export function packNotePlaintext(note: NotePlaintext): Buffer {
  const buf = Buffer.alloc(192); // 6 fields * 32 bytes
  let offset = 0;
  [
    note.asset_id,
    note.value,
    note.secret,
    note.nullifier,
    note.timelock,
    note.hashlock,
  ].forEach((fr) => {
    const b32 = fr.toBuffer();
    buf.set(b32, offset);
    offset += 32;
  });

  if (offset !== 192) throw new SizeError(192, offset, "packed plain");
  return buf;
}

export function unpackNotePlaintext(plain: Buffer): NotePlaintext {
  if (plain.length !== 192)
    throw new SizeError(192, plain.length, "unpacked plain");

  const frs: Fr[] = [];
  for (let i = 0; i < 6; i++) {
    const slice = Buffer.from(plain.slice(i * 32, (i + 1) * 32));
    frs.push(new Fr(slice));
  }

  return {
    asset_id: frs[0],
    value: frs[1],
    secret: frs[2],
    nullifier: frs[3],
    timelock: frs[4],
    hashlock: frs[5],
  };
}
