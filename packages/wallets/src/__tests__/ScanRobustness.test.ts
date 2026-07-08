import { describe, it, expect } from "vitest";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import { InMemoryEphemeralCounterStore } from "../state/EphemeralCounterStore";
import { UtxoRepository } from "../state/UtxoRepository";
import { toFr } from "../crypto/fields";
import { WalletNote } from "../state/types";

const MNEMONIC = "test test test test test test test test test test test junk";

describe("Scan robustness", () => {
  it("matches a registered even-y self tag and misses an unknown tag", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const repo = new KeyRepository(account, new InMemoryEphemeralCounterStore());

    const minted = await repo.nextSelfEphemeral();
    expect(repo.matchSelfTag(minted.ephPub[0])?.index).toBe(minted.index);
    expect(repo.matchSelfTag(minted.ephPub[0] + 1n)).toBeNull();
  });

  it("advances the self lookahead after a high match (gap-limit recenter)", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const repo = new KeyRepository(account, new InMemoryEphemeralCounterStore());

    await repo.ensureSelfLookahead(5);
    await repo.nextSelfEphemeral();
    const high = await repo.nextSelfEphemeral();
    repo.matchSelfTag(high.ephPub[0]);

    expect(await repo.ensureSelfLookahead(5)).toBe(true);
  });

  it("restores scan cursors so high-index self-notes stay matchable", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const repo = new KeyRepository(account, new InMemoryEphemeralCounterStore());

    const mints = [];
    for (let i = 0; i < 8; i++) mints.push(await repo.nextSelfEphemeral());
    const last = mints[mints.length - 1]!;

    const state = repo.getState();
    expect(state.selfMintCounter).toBe(last.index + 1);

    const fresh = new KeyRepository(account, new InMemoryEphemeralCounterStore());
    await fresh.restore(state);
    expect(fresh.matchSelfTag(last.ephPub[0])?.index).toBe(last.index);
  });

  it("never resurrects a spent note on re-add", async () => {
    const repo = new UtxoRepository();
    const note: WalletNote = {
      note: {
        noteVersion: toFr(1n),
        assetId: toFr(1n),
        noteType: toFr(0n),
        conditionsHash: toFr(0n),
        value: 100n,
        owner: toFr(7n),
        psi: toFr(9n),
        parents: toFr(0n),
      },
      commitment: toFr(5n),
      leafIndex: 0,
      nullifier: toFr(42n),
      spendScalar: toFr(0n),
      isIncoming: false,
      derivationIndex: 0,
      spent: false,
    };

    await repo.addNote(note);
    repo.markSpent(note.nullifier);
    await repo.addNote({ ...note, spent: false });

    expect(repo.getUnspentNotes().length).toBe(0);
    expect(repo.getAllNotes()[0]!.spent).toBe(true);
  });
});
