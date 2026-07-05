import { Fr } from "@aztec/foundation/fields";
import { WalletNote } from "./types.js";
import { IUtxoRepository } from "../repositories.js";

export class UtxoRepository implements IUtxoRepository {
  private notes: Map<string, WalletNote> = new Map();

  public async addNote(note: WalletNote): Promise<void> {
    const key = note.nullifier.toString();

    const existing = this.notes.get(key);
    if (existing) {
      this.notes.set(key, { ...note, spent: existing.spent || note.spent });
      return;
    }
    this.notes.set(key, note);
  }

  public markSpent(nullifier: string | Fr): boolean {
    const key = nullifier.toString();
    const note = this.notes.get(key);

    if (note && !note.spent) {
      note.spent = true;
      this.notes.set(key, note);
      return true;
    }
    return false;
  }

  public getUnspentNotes(): WalletNote[] {
    const all = Array.from(this.notes.values());
    return all.filter((n) => !n.spent);
  }

  public getAllNotes(): WalletNote[] {
    return Array.from(this.notes.values());
  }

  public getBalance(assetId?: Fr | bigint | string): bigint {
    let total = 0n;
    const want =
      assetId === undefined
        ? undefined
        : typeof assetId === "bigint"
          ? assetId
          : typeof assetId === "string"
            ? BigInt(assetId)
            : assetId.toBigInt();

    for (const note of this.getUnspentNotes()) {
      if (want !== undefined && note.note.assetId.toBigInt() !== want) {
        continue;
      }
      total += note.note.value;
    }
    return total;
  }
}
