import type { IncomingMessage } from "node:http";

export type BodyRead =
  | { readonly ok: true; readonly bytes: Uint8Array }
  | { readonly ok: false; readonly failure: "too_large" | "unreadable" };

const TOO_LARGE: BodyRead = { ok: false, failure: "too_large" };
const UNREADABLE: BodyRead = { ok: false, failure: "unreadable" };

// The declared length decides before a single body byte is read. Accumulating first and destroying the
// socket on overflow delivers a connection reset instead of the status the client is owed, so the
// streamed cap below is only the second layer, for a request that declares nothing or declares a lie.
export function readBody(req: IncomingMessage, cap: number): Promise<BodyRead> {
  const declared = req.headers["content-length"];
  if (declared !== undefined) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0) {
      return Promise.resolve(UNREADABLE);
    }
    if (length > cap) return Promise.resolve(TOO_LARGE);
  }

  return new Promise<BodyRead>((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const settle = (result: BodyRead): void => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    req.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.length;
      if (total > cap) {
        req.pause();
        settle(TOO_LARGE);
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => settle({ ok: true, bytes: Buffer.concat(chunks) }));
    req.on("error", () => settle(UNREADABLE));
    req.on("aborted", () => settle(UNREADABLE));
  });
}

export function decodeJson(bytes: Uint8Array): unknown {
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}
