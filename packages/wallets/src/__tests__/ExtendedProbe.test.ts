import { describe, it, expect } from "vitest";
import { Point, mulPointEscalar, Base8 } from "@zk-kit/baby-jubjub";
import { Contract } from "ethers";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import { UtxoRepository } from "../state/UtxoRepository";
import { ScanEngine } from "../sync/ScanEngine";
import { BJJ_SUBGROUP_ORDER } from "../crypto/constants";
import { toFr } from "../crypto/fields";
import { deriveSharedSecret, kdfToAesKeyIV } from "../crypto/ecdh";
import { aes128Encrypt } from "../crypto/aes";
import { packNotePlaintext } from "../crypto/packing";
import { NotePlaintext } from "../crypto/types";

const MNEMONIC = "test test test test test test test test test test test junk";
const COMPLIANCE_PK: Point<bigint> = mulPointEscalar(Base8, 987654321n);

const STANDARD_WINDOW = 20;
const GAP_DERIVATION_INDEX = 30; // unused self-note indices 0..29 > STANDARD_WINDOW
const EXTRA_WINDOW = 20; // probe window 40 registers 0..39, crossing the gap

// Inverse of ScanEngine's unpackCiphertext: 208-byte buffer -> 7 little-endian Frs (31*6 + 22).
function packCiphertext(ciphertext: Buffer): string[] {
  const out: string[] = [];
  let idx = 0;
  for (let p = 0; p < 7; p++) {
    const bytesInThis = p < 6 ? 31 : 22;
    let val = 0n;
    for (let i = 0; i < bytesInThis; i++) {
      val += BigInt(ciphertext[idx]) << BigInt(8 * i);
      idx++;
    }
    out.push(toFr(val).toString());
  }
  return out;
}

async function selfNoteEvent(
  account: DarkAccount,
  derivationIndex: number,
  leafIndex: number,
  note: NotePlaintext,
) {
  const ephPk = await account.getPublicEphemeralOutgoingKey(
    BigInt(derivationIndex),
  );
  const ephSk = await account.getEphemeralOutgoingKey(BigInt(derivationIndex));
  const ephSkMod = toFr(ephSk.toBigInt() % BJJ_SUBGROUP_ORDER);
  const sharedSecret = await deriveSharedSecret(ephSkMod, COMPLIANCE_PK);
  const { key, iv } = await kdfToAesKeyIV(sharedSecret);
  const ciphertext = await aes128Encrypt(packNotePlaintext(note), key, iv);

  return {
    blockNumber: 100 + leafIndex,
    index: leafIndex,
    transactionHash: "0xtx",
    fragment: { name: "NewNote" },
    args: {
      leafIndex: BigInt(leafIndex),
      commitment: toFr(BigInt(1000 + leafIndex)).toString(),
      ephemeralPK_x: ephPk[0],
      ephemeralPK_y: ephPk[1],
      packedCiphertext: packCiphertext(ciphertext),
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
    const keyRepo = new KeyRepository(account, COMPLIANCE_PK);
    const utxoRepo = new UtxoRepository();

    const note: NotePlaintext = {
      asset_id: toFr(1n),
      value: toFr(777n),
      secret: toFr(42n),
      owner: toFr(0n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };
    const evt = await selfNoteEvent(account, GAP_DERIVATION_INDEX, 0, note);
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

    const found = await engine.probe(0, EXTRA_WINDOW);
    expect(found).toBe(true);

    const notes = utxoRepo.getAllNotes();
    expect(notes.length).toBe(1);
    expect(notes[0]!.derivationIndex).toBe(GAP_DERIVATION_INDEX);
    expect(notes[0]!.note.value.toBigInt()).toBe(777n);
  });

  it("probe returns false and adds nothing when no note hides past the standard window", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const keyRepo = new KeyRepository(account, COMPLIANCE_PK);
    const utxoRepo = new UtxoRepository();

    const note: NotePlaintext = {
      asset_id: toFr(1n),
      value: toFr(5n),
      secret: toFr(9n),
      owner: toFr(0n),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };
    const evt = await selfNoteEvent(account, 3, 0, note);
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

    const found = await engine.probe(0, EXTRA_WINDOW);
    expect(found).toBe(false);
    expect(utxoRepo.getAllNotes().length).toBe(1);
  });
});
