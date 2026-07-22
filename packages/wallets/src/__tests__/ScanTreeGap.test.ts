import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { Contract } from "ethers";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import { InMemoryEphemeralCounterStore } from "../state/EphemeralCounterStore";
import { UtxoRepository } from "../state/UtxoRepository";
import { LeanIMT } from "../merkle/LeanIMT";
import { ScanEngine } from "../sync/ScanEngine";
import { toFr } from "../crypto/fields";
import { deriveCek } from "../crypto/kem";
import { demEncrypt } from "../crypto/dem";
import { computePsi, computeNullifier } from "../note/nullifier";
import { leaf, Note } from "../note/note";
import { isEvenY, publicKey, pubkeyOwner } from "../note/keys";

const MNEMONIC = "test test test test test test test test test test test junk";
const COMPLIANCE_PK: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];
const ASSET = new Fr(0x1234567890123456789012345678901234567890n);
const ASSET_MODULUS = 1n << 160n;
const STANDARD_WINDOW = 20;
const FOREIGN_COMMITMENT = "0x" + 0x1234abcdn.toString(16).padStart(64, "0");

const hex = (f: Fr): string => "0x" + f.toBuffer().toString("hex");

type FakeLog = {
  blockNumber: number;
  index: number;
  transactionHash?: string;
  fragment?: { name: string };
  args: Record<string, unknown>;
};

interface FakeState {
  // mainNotes = truncating un-indexed feed; indexedNotes = per-leafIndex repair feed; nulls mutable across syncs.
  mainNotes: FakeLog[];
  indexedNotes: Map<number, FakeLog>;
  nulls: FakeLog[];
}

function fakeContract(state: FakeState): Contract {
  const filterFor = (name: string) => (indices?: Array<number | bigint>) => ({
    name,
    indices,
  });
  return {
    runner: { provider: { getBlockNumber: async () => 100000 } },
    filters: {
      NewNote: filterFor("NewNote"),
      NewPrivateMemo: filterFor("NewPrivateMemo"),
      NullifierSpent: filterFor("NullifierSpent"),
    },
    queryFilter: async (filter: {
      name: string;
      indices?: Array<number | bigint>;
    }) => {
      if (filter.name === "NewNote") {
        if (filter.indices === undefined) return state.mainNotes;
        const out: FakeLog[] = [];
        for (const i of filter.indices) {
          const ev = state.indexedNotes.get(Number(i));
          if (ev) out.push(ev);
        }
        return out;
      }
      if (filter.name === "NullifierSpent") return state.nulls;
      return [];
    },
  } as unknown as Contract;
}

// Only even-y self indices produce an on-chain discovery tag, so an owned note must derive from one.
async function evenYSelfIndices(
  account: DarkAccount,
  count: number,
  hi: number,
): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < hi && out.length < count; i++) {
    if (isEvenY(publicKey(await account.getSelfEphemeral(BigInt(i))))) {
      out.push(i);
    }
  }
  if (out.length < count) {
    throw new Error(`only ${out.length} even-y self indices in [0, ${hi})`);
  }
  return out;
}

async function selfNoteLog(
  account: DarkAccount,
  derivationIndex: number,
  leafIndex: number,
  value: bigint,
  overrides: { owner?: Fr; assetId?: Fr } = {},
): Promise<{ log: FakeLog; commitment: string }> {
  const eph = await account.getSelfEphemeral(BigInt(derivationIndex));
  const ephPub = publicKey(eph);
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const assetId = overrides.assetId ?? ASSET;
  const owner =
    overrides.owner ?? (await pubkeyOwner(await account.getSelfSpendPub()));
  const note: Note = {
    noteVersion: new Fr(1n),
    assetId,
    noteType: new Fr(0n),
    conditionsHash: new Fr(0n),
    value,
    owner,
    psi,
    parents: new Fr(0n),
  };
  const ciphertext = await demEncrypt(cek, [
    new Fr(1n),
    assetId,
    new Fr(0n),
    new Fr(0n),
    new Fr(value),
    owner,
    new Fr(0n),
  ]);
  const commitment = hex(await leaf(note));
  return {
    log: {
      blockNumber: 100 + leafIndex,
      index: leafIndex,
      transactionHash: "0xtx",
      fragment: { name: "NewNote" },
      args: {
        leafIndex: BigInt(leafIndex),
        commitment,
        ephemeralPK_x: ephPub[0],
        ephemeralPK_y: ephPub[1],
        packedCiphertext: ciphertext.map(hex),
      },
    },
    commitment,
  };
}

function foreignNoteLog(leafIndex: number, commitment: string): FakeLog {
  return {
    blockNumber: 100 + leafIndex,
    index: leafIndex,
    transactionHash: "0xtx",
    fragment: { name: "NewNote" },
    args: {
      leafIndex: BigInt(leafIndex),
      commitment,
      // An ephemeral tag no self index owns, so this leaf is inserted but never decrypted as ours.
      ephemeralPK_x: 1n,
      ephemeralPK_y: 2n,
      packedCiphertext: ["0x0", "0x0", "0x0", "0x0", "0x0", "0x0", "0x0"],
    },
  };
}

async function selfNullifierHash(
  account: DarkAccount,
  derivationIndex: number,
  leafIndex: number,
): Promise<string> {
  const eph = await account.getSelfEphemeral(BigInt(derivationIndex));
  const cek = deriveCek(eph, COMPLIANCE_PK);
  const psi = await computePsi(cek);
  const nf = await computeNullifier(psi, new Fr(BigInt(leafIndex)));
  return nf.toString();
}

async function referenceRoot(commitments: string[]): Promise<Fr> {
  const tree = new LeanIMT(32);
  for (const c of commitments) await tree.insert(toFr(c));
  return tree.getRoot();
}

function freshRepos(account: DarkAccount): {
  keyRepo: KeyRepository;
  utxoRepo: UtxoRepository;
} {
  return {
    keyRepo: new KeyRepository(account, new InMemoryEphemeralCounterStore()),
    utxoRepo: new UtxoRepository(),
  };
}

describe("ScanEngine tree-gap repair (repairTreeGap / fetchLeafEvents)", () => {
  it("fetches and inserts the missing leaves in order, then discovers owned notes at the right leafIndex", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const { keyRepo, utxoRepo } = freshRepos(account);
    const [dA, dB, dC] = await evenYSelfIndices(account, 3, STANDARD_WINDOW);

    // Owned notes land at leaves 0, 2, 3; leaf 1 is foreign. The un-indexed feed truncates to {0, 3}
    // so the jump from 0 -> 3 forces repairTreeGap to fetch [1, 2] via the indexed filter.
    const n0 = await selfNoteLog(account, dA!, 0, 100n);
    const foreign1 = foreignNoteLog(1, FOREIGN_COMMITMENT);
    const n2 = await selfNoteLog(account, dB!, 2, 50n);
    const n3 = await selfNoteLog(account, dC!, 3, 25n);

    const state: FakeState = {
      mainNotes: [n0.log, n3.log],
      indexedNotes: new Map<number, FakeLog>([
        [1, foreign1],
        [2, n2.log],
      ]),
      nulls: [],
    };

    const tree = new LeanIMT(32);
    const engine = new ScanEngine(
      fakeContract(state),
      keyRepo,
      utxoRepo,
      COMPLIANCE_PK,
      tree,
      STANDARD_WINDOW,
    );

    await engine.sync(0);

    const expectedRoot = await referenceRoot([
      n0.commitment,
      FOREIGN_COMMITMENT,
      n2.commitment,
      n3.commitment,
    ]);
    expect(tree.nextLeafIndex).toBe(4);
    expect(tree.getRoot().equals(expectedRoot)).toBe(true);

    const notes = utxoRepo.getAllNotes();
    expect(notes.length).toBe(3);
    const byLeaf = new Map(notes.map((n) => [n.leafIndex, n]));
    expect([...byLeaf.keys()].sort((a, b) => a - b)).toEqual([0, 2, 3]);
    expect(byLeaf.get(0)!.note.value).toBe(100n);
    expect(byLeaf.get(2)!.note.value).toBe(50n);
    expect(byLeaf.get(3)!.note.value).toBe(25n);
    expect(utxoRepo.getBalance(ASSET)).toBe(175n);
  });

  it("throws when the indexed fetch cannot supply a missing leaf", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const { keyRepo, utxoRepo } = freshRepos(account);
    const [dA, dC] = await evenYSelfIndices(account, 2, STANDARD_WINDOW);

    const n0 = await selfNoteLog(account, dA!, 0, 100n);
    const foreign1 = foreignNoteLog(1, FOREIGN_COMMITMENT);
    const n3 = await selfNoteLog(account, dC!, 3, 25n);

    // Indexed feed is missing leaf 2, so repairTreeGap can never close the 1 -> 2 gap and gives up.
    const state: FakeState = {
      mainNotes: [n0.log, n3.log],
      indexedNotes: new Map<number, FakeLog>([[1, foreign1]]),
      nulls: [],
    };

    const engine = new ScanEngine(
      fakeContract(state),
      keyRepo,
      utxoRepo,
      COMPLIANCE_PK,
      new LeanIMT(32),
      STANDARD_WINDOW,
    );

    await expect(engine.sync(0)).rejects.toThrow(
      /could not fetch all leaves up to 2/,
    );
  });
});

describe("ScanEngine NullifierSpent handling", () => {
  it("marks an owned note spent when its NullifierSpent log later arrives", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const { keyRepo, utxoRepo } = freshRepos(account);
    const [d] = await evenYSelfIndices(account, 1, STANDARD_WINDOW);

    const note = await selfNoteLog(account, d!, 0, 100n);
    const state: FakeState = {
      mainNotes: [note.log],
      indexedNotes: new Map(),
      nulls: [],
    };

    const engine = new ScanEngine(
      fakeContract(state),
      keyRepo,
      utxoRepo,
      COMPLIANCE_PK,
    );

    await engine.sync(0);
    expect(utxoRepo.getUnspentNotes().length).toBe(1);
    expect(utxoRepo.getBalance(ASSET)).toBe(100n);

    const nullifierHash = await selfNullifierHash(account, d!, 0);
    state.nulls.push({
      blockNumber: 500,
      index: 0,
      args: { nullifierHash },
    });

    await engine.sync(0);

    expect(utxoRepo.getBalance(ASSET)).toBe(0n);
    expect(utxoRepo.getUnspentNotes().length).toBe(0);
    expect(utxoRepo.getAllNotes()[0]!.spent).toBe(true);
  });
});

describe("ScanEngine NoteProcessor rejects (owner==0, assetId out of range)", () => {
  it("drops a note whose committed owner is zero", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const { keyRepo, utxoRepo } = freshRepos(account);
    const [d] = await evenYSelfIndices(account, 1, STANDARD_WINDOW);

    // Real leaf/tag/CEK so decryption and the leaf-match pass; the owner==0 guard is what drops it.
    const note = await selfNoteLog(account, d!, 0, 100n, { owner: new Fr(0n) });
    const state: FakeState = {
      mainNotes: [note.log],
      indexedNotes: new Map(),
      nulls: [],
    };

    const engine = new ScanEngine(
      fakeContract(state),
      keyRepo,
      utxoRepo,
      COMPLIANCE_PK,
    );

    await engine.sync(0);

    expect(utxoRepo.getAllNotes().length).toBe(0);
    expect(utxoRepo.getBalance()).toBe(0n);
  });

  it("drops a note whose committed assetId is >= 2^160", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const { keyRepo, utxoRepo } = freshRepos(account);
    const [d] = await evenYSelfIndices(account, 1, STANDARD_WINDOW);

    // owner is the real self owner (so the owner check would pass); only the asset-range guard drops it.
    const note = await selfNoteLog(account, d!, 0, 100n, {
      assetId: new Fr(ASSET_MODULUS),
    });
    const state: FakeState = {
      mainNotes: [note.log],
      indexedNotes: new Map(),
      nulls: [],
    };

    const engine = new ScanEngine(
      fakeContract(state),
      keyRepo,
      utxoRepo,
      COMPLIANCE_PK,
    );

    await engine.sync(0);

    expect(utxoRepo.getAllNotes().length).toBe(0);
    expect(utxoRepo.getBalance()).toBe(0n);
  });
});
