import { createHash } from "node:crypto";
import type { Database, Statement } from "better-sqlite3";
import type { Collection } from "@hisoka/pss-client/wire";
import type {
  InviteGate,
  SlotStore,
  SlotWrite,
  StoredSlot,
  WriteOutcome,
} from "./slotStore.js";

const SELECT_SLOT =
  "SELECT version, prev_version, nonce, ciphertext FROM slots " +
  "WHERE account_id = ? AND collection = ?";

const SELECT_ACCOUNT_ROW = "SELECT 1 FROM slots WHERE account_id = ? LIMIT 1";

// One statement, so the predicate cannot be read by one writer and acted on by another. The insert arm
// creates the first row; the update arm advances only a slot whose stored version is exactly the
// prev_version the signature committed to.
const UPSERT_SLOT =
  "INSERT INTO slots " +
  "(account_id, collection, version, prev_version, nonce, ciphertext) " +
  "VALUES (?, ?, ?, ?, ?, ?) " +
  "ON CONFLICT(account_id, collection) DO UPDATE SET " +
  "version = excluded.version, prev_version = excluded.prev_version, " +
  "nonce = excluded.nonce, ciphertext = excluded.ciphertext " +
  "WHERE slots.version < excluded.version AND slots.version = excluded.prev_version";

const DELETE_ACCOUNT = "DELETE FROM slots WHERE account_id = ?";

const SELECT_INVITES_TABLE =
  "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'invites' LIMIT 1";

const SPEND_INVITE =
  "UPDATE invites SET spent = 1 WHERE code_hash = ? AND spent = 0";

interface SlotRow {
  readonly version: number;
  readonly prev_version: number;
  readonly nonce: Buffer;
  readonly ciphertext: Buffer;
}

// better-sqlite3 rolls a transaction back only when the body throws, so the rejected-invite arm signals
// by throwing and is converted at the seam. Returning a flag would commit the row it just created.
class InviteRejected extends Error {
  constructor() {
    super("PSS create carried no unspent invite code");
    this.name = "InviteRejected";
  }
}

function copyOf(value: Buffer): Uint8Array {
  return Uint8Array.from(value);
}

function blob(value: Uint8Array): Buffer {
  return Buffer.from(value);
}

function codeHash(code: string): Buffer {
  return createHash("sha256").update(code, "utf8").digest();
}

class SqliteSlotStore implements SlotStore {
  readonly #db: Database;
  readonly #selectSlot: Statement;
  readonly #selectAccountRow: Statement;
  readonly #upsert: Statement;
  readonly #deleteAccount: Statement;
  #selectInvitesTable: Statement | null = null;
  #spendInvite: Statement | null = null;

  constructor(db: Database) {
    this.#db = db;
    this.#selectSlot = db.prepare(SELECT_SLOT);
    this.#selectAccountRow = db.prepare(SELECT_ACCOUNT_ROW);
    this.#upsert = db.prepare(UPSERT_SLOT);
    this.#deleteAccount = db.prepare(DELETE_ACCOUNT);
  }

  get(accountId: Uint8Array, collection: Collection): StoredSlot | null {
    const row = this.#selectSlot.get(blob(accountId), collection) as
      | SlotRow
      | undefined;
    if (row === undefined) return null;
    return {
      version: row.version,
      prevVersion: row.prev_version,
      nonce: copyOf(row.nonce),
      ciphertext: copyOf(row.ciphertext),
    };
  }

  upsert(write: SlotWrite, gate: InviteGate): WriteOutcome {
    if (!gate.required) {
      return this.#cas(write) ? "written" : "conflict";
    }
    try {
      return this.#db.transaction(() => this.#gatedWrite(write, gate.code))();
    } catch (error) {
      if (error instanceof InviteRejected) return "invite_rejected";
      throw error;
    }
  }

  deleteAccount(accountId: Uint8Array): number {
    return this.#deleteAccount.run(blob(accountId)).changes;
  }

  #gatedWrite(write: SlotWrite, code: string | null): WriteOutcome {
    if (this.#hasAccountRow(write.accountId)) {
      return this.#cas(write) ? "written" : "conflict";
    }
    if (!this.#cas(write)) return "conflict";
    if (code === null || !this.#spend(code)) throw new InviteRejected();
    return "written";
  }

  #cas(write: SlotWrite): boolean {
    const changes = this.#upsert.run(
      blob(write.accountId),
      write.collection,
      write.version,
      write.prevVersion,
      blob(write.nonce),
      blob(write.ciphertext),
    ).changes;
    return changes === 1;
  }

  #hasAccountRow(accountId: Uint8Array): boolean {
    return this.#selectAccountRow.get(blob(accountId)) !== undefined;
  }

  // Prepared on first use and only on the create path, so an operator who drops the table the day the
  // gate is retired never touches a statement that names it.
  #spend(code: string): boolean {
    this.#selectInvitesTable ??= this.#db.prepare(SELECT_INVITES_TABLE);
    if (this.#selectInvitesTable.get() === undefined) return false;
    this.#spendInvite ??= this.#db.prepare(SPEND_INVITE);
    return this.#spendInvite.run(codeHash(code)).changes === 1;
  }
}

export function openSlotStore(db: Database): SlotStore {
  return new SqliteSlotStore(db);
}
