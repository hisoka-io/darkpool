import { Collection } from "../wire/collection.js";
import {
  DeleteAccountRequest,
  GetBlobResponse,
  PutBlobRequest,
} from "../wire/types.js";
import { PssTransport } from "../sync/transport.js";
import { FakeTransport } from "./fakeTransport.js";

export type Lie =
  | { readonly kind: "none" }
  /** Serves a version already superseded. */
  | { readonly kind: "rollback"; readonly version: number }
  /** Answers 200 to every PUT and stores nothing, so GET returns the old version forever. */
  | { readonly kind: "drop_writes" }
  /** Serves whatever is stored for the other collection at this path. */
  | { readonly kind: "substitute_collection" }
  /** Replaces the response body wholesale. */
  | { readonly kind: "serve"; readonly body: GetBlobResponse }
  /** Replaces only the nonce, which the PUT preimage does not cover. */
  | { readonly kind: "swap_nonce"; readonly nonce: string }
  /** Flips one byte of the stored ciphertext. */
  | { readonly kind: "flip_ciphertext_byte" }
  /** Keeps the ciphertext and lies about the version in the envelope. */
  | { readonly kind: "wrong_version"; readonly version: number }
  /** 404 forever, whatever is stored. */
  | { readonly kind: "always_absent" };

/**
 * A server that lies. It is not an HTTP server: the point is deterministic lying, not a network. The
 * GET response carries no signature by design, so a transport can serve anything at all and the
 * client's integrity has to come from the AEAD, the version floor and the payload parser.
 */
export class HostileTransport implements PssTransport {
  readonly honest = new FakeTransport();
  lie: Lie = { kind: "none" };
  // Every version this server has ever held, so a rollback can replay a genuine old cell rather than
  // relabelling the current one. Relabelling is a different attack, and it is attack 11.
  readonly #history = new Map<string, Map<number, GetBlobResponse>>();

  /** Restores honest service, so every attack can assert recovery rather than assume it. */
  stopLying(): void {
    this.lie = { kind: "none" };
  }

  async getBlob(
    accountPath: string,
    collection: Collection,
  ): Promise<GetBlobResponse | null> {
    const lie = this.lie;
    if (lie.kind === "serve") return lie.body;
    if (lie.kind === "always_absent") return null;

    const honest = await this.honest.getBlob(accountPath, collection);
    if (honest === null) return null;

    switch (lie.kind) {
      case "rollback": {
        const kept = this.#history
          .get(`${accountPath}/${collection}`)
          ?.get(lie.version);
        if (kept === undefined) {
          throw new Error(
            `hostile rollback needs a genuine version ${lie.version} to replay`,
          );
        }
        return kept;
      }
      case "substitute_collection": {
        const other: Collection = collection === "state" ? "labels" : "state";
        const swapped = await this.honest.getBlob(accountPath, other);
        return swapped === null
          ? honest
          : { ...swapped, version: honest.version };
      }
      case "swap_nonce":
        return { ...honest, nonce: lie.nonce };
      case "flip_ciphertext_byte": {
        const raw = Buffer.from(honest.ciphertext, "base64");
        raw[0] ^= 0xff;
        return { ...honest, ciphertext: raw.toString("base64") };
      }
      case "wrong_version":
        return { ...honest, version: lie.version };
      default:
        return honest;
    }
  }

  async putBlob(
    accountPath: string,
    collection: Collection,
    body: PutBlobRequest,
  ): Promise<void> {
    // Answers 200 and keeps nothing. The client must not treat its own write as landed.
    if (this.lie.kind === "drop_writes") return;
    await this.honest.putBlob(accountPath, collection, body);
    const key = `${accountPath}/${collection}`;
    const kept = this.#history.get(key) ?? new Map<number, GetBlobResponse>();
    kept.set(body.version, {
      version: body.version,
      prevVersion: body.prevVersion,
      nonce: body.nonce,
      ciphertext: body.ciphertext,
      serverTime: 1_785_900_000,
    });
    this.#history.set(key, kept);
  }

  deleteAccount(
    accountPath: string,
    body: DeleteAccountRequest,
  ): Promise<void> {
    return this.honest.deleteAccount(accountPath, body);
  }
}
