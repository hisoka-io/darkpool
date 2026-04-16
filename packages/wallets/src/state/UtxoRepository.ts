import { Fr } from '@aztec/foundation/fields';
import { WalletNote } from './types.js';
import { IUtxoRepository } from '../repositories.js';

export class UtxoRepository implements IUtxoRepository {
  // Nullifier -> Note
  private notes: Map<string, WalletNote> = new Map();

  public async addNote(note: WalletNote): Promise<void> {
    const key = note.nullifier.toString();

    if (this.notes.has(key)) {
      const existing = this.notes.get(key)!;
      if (existing.spent === note.spent) {
        return;
      }
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
    return all.filter(n => !n.spent);
  }

  public getAllNotes(): WalletNote[] {
    return Array.from(this.notes.values());
  }

  public getBalance(assetId?: string): bigint {
    let total = 0n;
    const unspent = this.getUnspentNotes();

    for (const note of unspent) {
      if (assetId && note.note.asset_id.toString() !== assetId) {
        continue;
      }
      const val = note.note.value.toBigInt();
      total += val;
    }
    return total;
  }
}