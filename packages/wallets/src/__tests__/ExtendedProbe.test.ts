import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { Contract } from "ethers";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import { InMemoryEphemeralCounterStore } from "../state/EphemeralCounterStore";
import { UtxoRepository } from "../state/UtxoRepository";
import { ScanEngine } from "../sync/ScanEngine";
import { deriveCek } from "../crypto/kem";
import { demEncrypt } from "../crypto/dem";
import { computePsi } from "../note/nullifier";
import { leaf, Note } from "../note/note";
import { isEvenY, publicKey, pubkeyOwner } from "../note/keys";

const MNEMONIC = "test test test test test test test test test test test junk";
const COMPLIANCE_PK: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const ASSET = new Fr(0x1234567890123456789012345678901234567890n);

const STANDARD_WINDOW = 20;
const EXTRA_WINDOW = 20;

const hex = (f: Fr): string => "0x" + f.toBuffer().toString("hex");

// Only even-y self indices produce an on-chain discovery tag (eph_pub.x), so the wallet only ever
// registers even-y indices; a gap test must place the note at an even-y index past the window.
async function firstEvenYSelfIndex(
  account: DarkAccount,
  lo: number,
  hi: number,
): Promise<number> {
  for (let i = lo; i < hi; i++) {
    if (isEvenY(publicKey(await account.getSelfEphemeral(BigInt(i))))) return i;
  }
  throw new Error(`no even-y self index in [${lo}, ${hi})`);
}

async function selfNoteEvent(
  account: DarkAccount,
  derivationIndex: number,
  leafIndex: number,
  value: bigint,
) {
  const eph = await account.getSelfEphemeral(BigInt(derivationIndex));
  const ephPub = publicKey(eph);
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const owner = await pubkeyOwner(await account.getSelfSpendPub());
  const note: Note = {
    noteVersion: new Fr(1n),
    assetId: ASSET,
    noteType: new Fr(0n),
    conditionsHash: new Fr(0n),
    value,
    owner,
    psi,
    parents: new Fr(0n),
  };
  const ciphertext = await demEncrypt(cek, [
    new Fr(1n),
    ASSET,
    new Fr(0n),
    new Fr(0n),
    new Fr(value),
    owner,
    new Fr(0n),
  ]);

  return {
    blockNumber: 100 + leafIndex,
    index: leafIndex,
    transactionHash: "0xtx",
    fragment: { name: "NewNote" },
    args: {
      leafIndex: BigInt(leafIndex),
      commitment: hex(await leaf(note)),
      ephemeralPK_x: ephPub[0],
      ephemeralPK_y: ephPub[1],
      packedCiphertext: ciphertext.map(hex),
    },
  };
}

function fakeContract(noteLogs: unknown[]): Contract {
  return {
    runner: { provider: { getBlockNumber: async () => 1000 } },
    filters: {
      NewNote: () => "NewNote",
      NewPrivateMemo: () => "NewPrivateMemo",
      NullifierSpent: () => "NullifierSpent",
    },
    queryFilter: async (filter: string) =>
      filter === "NewNote" ? noteLogs : [],
  } as unknown as Contract;
}

describe("ScanEngine extended-probe recovery", () => {
  it("standard sync misses a post-gap self-note that the extended probe recovers", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const keyRepo = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const utxoRepo = new UtxoRepository();

    const gapIndex = await firstEvenYSelfIndex(
      account,
      STANDARD_WINDOW,
      STANDARD_WINDOW + EXTRA_WINDOW,
    );
    const evt = await selfNoteEvent(account, gapIndex, 0, 777n);
    const engine = new ScanEngine(
      fakeContract([evt]),
      keyRepo,
      utxoRepo,
      COMPLIANCE_PK,
      undefined,
      STANDARD_WINDOW,
    );

    await engine.sync(0);
    expect(utxoRepo.getAllNotes().length).toBe(0);

    expect(await engine.probe(0, EXTRA_WINDOW)).toBe(true);

    const notes = utxoRepo.getAllNotes();
    expect(notes.length).toBe(1);
    expect(notes[0]!.derivationIndex).toBe(gapIndex);
    expect(notes[0]!.note.value).toBe(777n);
  });

  it("probe returns false and adds nothing when no note hides past the window", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const keyRepo = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const utxoRepo = new UtxoRepository();

    const nearIndex = await firstEvenYSelfIndex(account, 0, STANDARD_WINDOW);
    const evt = await selfNoteEvent(account, nearIndex, 0, 5n);
    const engine = new ScanEngine(
      fakeContract([evt]),
      keyRepo,
      utxoRepo,
      COMPLIANCE_PK,
      undefined,
      STANDARD_WINDOW,
    );

    await engine.sync(0);
    expect(utxoRepo.getAllNotes().length).toBe(1);

    expect(await engine.probe(0, EXTRA_WINDOW)).toBe(false);
    expect(utxoRepo.getAllNotes().length).toBe(1);
  });
});
