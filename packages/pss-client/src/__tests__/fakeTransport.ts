import { Collection } from "../wire/collection.js";
import { PssError } from "../wire/errors.js";
import {
  DeleteAccountRequest,
  GetBlobResponse,
  PutBlobRequest,
} from "../wire/types.js";
import { PssTransport } from "../sync/transport.js";

interface Slot {
  version: number;
  prevVersion: number;
  nonce: string;
  ciphertext: string;
}

// An honest server, in memory: the same compare-and-swap the SQLite store enforces, and nothing else.
// The lying one lives with the attacks it is written for.
export class FakeTransport implements PssTransport {
  readonly #slots = new Map<string, Slot>();
  readonly puts: PutBlobRequest[] = [];
  readonly #history = new Map<string, Map<number, Slot>>();
  serverTime = 1_785_900_000;
  failNext: PssError | null = null;
  /** Replays a genuine earlier version, the way a rolled-back server would. */
  rollbackTo: number | null = null;

  #key(accountPath: string, collection: Collection): string {
    return `${accountPath}/${collection}`;
  }

  getBlob(
    accountPath: string,
    collection: Collection,
  ): Promise<GetBlobResponse | null> {
    this.#maybeFail();
    const key = this.#key(accountPath, collection);
    if (this.rollbackTo !== null) {
      const kept = this.#history.get(key)?.get(this.rollbackTo);
      if (kept === undefined) {
        return Promise.reject(
          new Error(`no genuine version ${this.rollbackTo} to replay`),
        );
      }
      return Promise.resolve({ ...kept, serverTime: this.serverTime });
    }
    const slot = this.#slots.get(key);
    if (slot === undefined) return Promise.resolve(null);
    return Promise.resolve({ ...slot, serverTime: this.serverTime });
  }

  putBlob(
    accountPath: string,
    collection: Collection,
    body: PutBlobRequest,
  ): Promise<void> {
    this.#maybeFail();
    this.puts.push(body);
    const key = this.#key(accountPath, collection);
    const stored = this.#slots.get(key);
    const storedVersion = stored?.version ?? 0;
    if (body.prevVersion !== storedVersion || body.version <= storedVersion) {
      return Promise.reject(
        new PssError(
          { code: "version_conflict" },
          `stored ${storedVersion}, offered ${body.version} after ${body.prevVersion}`,
        ),
      );
    }
    const slot = {
      version: body.version,
      prevVersion: body.prevVersion,
      nonce: body.nonce,
      ciphertext: body.ciphertext,
    };
    this.#slots.set(key, slot);
    const kept = this.#history.get(key) ?? new Map<number, Slot>();
    kept.set(body.version, slot);
    this.#history.set(key, kept);
    return Promise.resolve();
  }

  deleteAccount(
    accountPath: string,
    _body: DeleteAccountRequest,
  ): Promise<void> {
    this.#maybeFail();
    for (const key of [...this.#slots.keys()]) {
      if (key.startsWith(`${accountPath}/`)) this.#slots.delete(key);
    }
    return Promise.resolve();
  }

  /** Drops a stored slot without touching the client, the way a TTL sweep or a delete would. */
  drop(accountPath: string, collection: Collection): void {
    this.#slots.delete(this.#key(accountPath, collection));
  }

  stored(accountPath: string, collection: Collection): Slot | null {
    return this.#slots.get(this.#key(accountPath, collection)) ?? null;
  }

  #maybeFail(): void {
    const failure = this.failNext;
    if (failure === null) return;
    this.failNext = null;
    throw failure;
  }
}
