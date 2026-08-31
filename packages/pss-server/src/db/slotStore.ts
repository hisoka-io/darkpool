import type { Collection } from "@hisoka/pss-client/wire";

export interface StoredSlot {
  readonly version: number;
  readonly prevVersion: number;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export interface SlotWrite {
  readonly accountId: Uint8Array;
  readonly collection: Collection;
  readonly version: number;
  readonly prevVersion: number;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

// Consulted only when the account owns no row yet, which is why it travels with the write instead of
// being decided by the caller: the emptiness test and the spend must be one transaction, or a code is
// burned for a write that never lands, or a second create slips in beside a spend.
export type InviteGate =
  | { readonly required: false }
  | { readonly required: true; readonly code: string | null };

export type WriteOutcome = "written" | "conflict" | "invite_rejected";

export interface SlotStore {
  get(accountId: Uint8Array, collection: Collection): StoredSlot | null;
  upsert(write: SlotWrite, gate: InviteGate): WriteOutcome;
  deleteAccount(accountId: Uint8Array): number;
}
