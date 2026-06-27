import { describe, it, expect } from "vitest";
import { Point, mulPointEscalar, Base8 } from "@zk-kit/baby-jubjub";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import { UtxoRepository } from "../state/UtxoRepository";
import { toFr } from "../crypto/fields";
import { WalletNote } from "../state/types";

const MNEMONIC = "test test test test test test test test test test test junk";
const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(Base8, 987654321n);

describe("Scan robustness", () => {
  it("recenters the ephemeral window on a match (gap-limit)", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const keyRepo = new KeyRepository(account, COMPLIANCE_PK);

    await keyRepo.ensureEphemeralLookahead(5);
    const epk4 = await account.getPublicEphemeralOutgoingKey(4n);
    expect(keyRepo.tryMatchDeposit(epk4[0], epk4[1])?.index).toBe(4);

    const advanced = await keyRepo.ensureEphemeralLookahead(5);
    expect(advanced).toBe(true);

    const epk9 = await account.getPublicEphemeralOutgoingKey(9n);
    expect(keyRepo.tryMatchDeposit(epk9[0], epk9[1])).not.toBeNull();
  });

  it("restores scan cursors so high-index self-notes stay matchable", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const repo = new KeyRepository(account, COMPLIANCE_PK);
    for (let i = 0; i < 8; i++) await repo.nextEphemeralParams();

    const state = repo.getState();
    expect(state.nextEphemeralNonce).toBe(8);

    const fresh = new KeyRepository(account, COMPLIANCE_PK);
    await fresh.restore(state);

    const epk7 = await account.getPublicEphemeralOutgoingKey(7n);
    expect(fresh.tryMatchDeposit(epk7[0], epk7[1])).not.toBeNull();
  });

  it("never resurrects a spent note on re-add", async () => {
    const repo = new UtxoRepository();
    const note: WalletNote = {
      note: {
        asset_id: toFr(1n),
        value: toFr(100n),
        secret: toFr(0n),
        nullifier: toFr(0n),
        timelock: toFr(0n),
        hashlock: toFr(0n),
      },
      commitment: toFr(5n),
      leafIndex: 0,
      nullifier: toFr(42n),
      spendingSecret: toFr(0n),
      isTransfer: false,
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
