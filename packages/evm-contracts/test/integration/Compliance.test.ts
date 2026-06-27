import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  COMPLIANCE_SK,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  toFr,
  LeanIMT,
  deriveSharedSecret,
  NotePlaintext,
  generateDLEQProof,
  complianceDecryptNote,
  complianceDecrypt3Party,
  deriveNullifierPathA,
  deriveNullifierPathB,
} from "@hisoka/wallets";
import {
  proveTransfer,
  TransferInputs,
  unpackCiphertext,
} from "@hisoka/prover";
import { Point } from "@zk-kit/baby-jubjub";
import { DarkPool } from "../../typechain-types";

class ComplianceTool {
  // Map of NullifierHash -> DecryptedNote
  public observedNotes: Map<
    string,
    { note: NotePlaintext; type: "DEPOSIT" | "MEMO" | "CHANGE" }
  > = new Map();
  public spentNullifiers: Set<string> = new Set();

  constructor(
    public readonly complianceSk: bigint,
    public readonly contract: DarkPool,
  ) {}

  // Simulate indexing by fetching all events
  async sync() {
    // NewNote: deposits / changes
    const noteEvents = await this.contract.queryFilter(
      this.contract.filters.NewNote(),
    );
    for (const ev of noteEvents) {
      await this.tryDecryptNote(ev);
    }

    // NewPrivateMemo: transfers
    const memoEvents = await this.contract.queryFilter(
      this.contract.filters.NewPrivateMemo(),
    );
    for (const ev of memoEvents) {
      await this.tryDecryptMemo(ev);
    }

    const nullEvents = await this.contract.queryFilter(
      this.contract.filters.NullifierSpent(),
    );
    for (const ev of nullEvents) {
      this.spentNullifiers.add(ev.args.nullifierHash);
    }
  }

  // 2-party decryption (deposit/change)
  async tryDecryptNote(event: any) {
    const { ephemeralPK_x, ephemeralPK_y, packedCiphertext } = event.args;
    const epk: Point<bigint> = [ephemeralPK_x, ephemeralPK_y];
    const packedFr = packedCiphertext.map((h: string) => toFr(h));
    const ciphertext = unpackCiphertext(packedFr);

    try {
      const note = await complianceDecryptNote(
        this.complianceSk,
        epk,
        ciphertext,
      );

      // Path A nullifier indexes this note
      const commitment = toFr(event.args.commitment);
      const leafIndex = Number(event.args.leafIndex);
      const nf = await deriveNullifierPathA(
        note.nullifier,
        commitment,
        leafIndex,
      );
      this.observedNotes.set(nf.toString(), { note, type: "DEPOSIT" });
    } catch {
      // Compliance should read all NewNotes; ignore any that fail to decrypt
    }
  }

  // 3-party decryption (transfer)
  async tryDecryptMemo(event: any) {
    const {
      packedCiphertext,
      intermediateCompliance_x,
      intermediateCompliance_y,
      leafIndex,
      commitment,
    } = event.args;

    const intermediate: Point<bigint> = [
      intermediateCompliance_x,
      intermediateCompliance_y,
    ];
    const packedFr = packedCiphertext.map((h: string) => toFr(h));
    const ciphertext = unpackCiphertext(packedFr);

    try {
      const { note, sharedSecret } = await complianceDecrypt3Party(
        this.complianceSk,
        intermediate,
        ciphertext,
      );

      // Path B nullifier = Hash(sharedSecret, commitment, index)
      const nf = await deriveNullifierPathB(
        sharedSecret,
        toFr(commitment),
        leafIndex,
      );

      this.observedNotes.set(nf.toString(), { note, type: "MEMO" });
    } catch {
      // Ignore notes that fail to decrypt
    }
  }

  generateReport() {
    const report = [];
    for (const [nf, data] of this.observedNotes.entries()) {
      report.push({
        type: data.type,
        amount: data.note.value.toBigInt(), // Use bigint for cleaner assertion
        asset: data.note.asset_id.toString(),
        status: this.spentNullifiers.has(nf) ? "SPENT" : "UNSPENT",
        nullifier: nf,
      });
    }
    return report;
  }
}

describe("Integration: Compliance God View", function () {
  it("should successfully trace a Deposit -> Transfer flow", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);

    // --- 1. ALICE DEPOSITS 100 ---
    const { depositPlain, ephemeralSk, commitment } = await makeDeposit(
      darkPool,
      token,
      alice,
      100n,
    );

    // --- 2. ALICE TRANSFERS 40 TO BOB ---
    // (This spends the 100 note, creates 40 Memo + 60 Change)
    const tree = new LeanIMT(32);
    await tree.insert(commitment);
    const bob_dleq = await generateDLEQProof(555n, COMPLIANCE_PK);

    const transferInputs: TransferInputs = {
      merkleRoot: tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      recipientB: bob_dleq.B,
      recipientP: bob_dleq.P,
      recipientProof: bob_dleq.pi,
      oldNote: depositPlain,
      oldSharedSecret: await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK),
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      hashlockPreimage: toFr(0n),
      memoNote: { ...depositPlain, value: toFr(40n), nullifier: toFr(0n) }, // 40 to Bob
      memoEphemeralSk: toFr(12n),
      changeNote: { ...depositPlain, value: toFr(60n), nullifier: toFr(999n) }, // 60 Change
      changeEphemeralSk: toFr(34n),
    };
    const trfProof = await proveTransfer(transferInputs);
    await darkPool
      .connect(alice)
      .privateTransfer(trfProof.proof, trfProof.publicInputs);

    // --- 3. COMPLIANCE AUDIT ---
    const tool = new ComplianceTool(COMPLIANCE_SK, darkPool);
    await tool.sync();

    const report = tool.generateReport();

    expect(report.length).to.equal(3); // Deposit, Memo, Change

    // 1. The Deposit (100) -> Should be SPENT
    const depEntry = report.find((r) => r.amount === 100n);
    expect(depEntry).to.not.equal(undefined);
    expect(depEntry?.status).to.equal("SPENT");

    // 2. The Memo (40) -> Should be UNSPENT
    const memoEntry = report.find((r) => r.amount === 40n && r.type === "MEMO");
    expect(memoEntry).to.not.equal(undefined);
    expect(memoEntry?.status).to.equal("UNSPENT");

    // 3. The Change (60) -> Should be UNSPENT
    const changeEntry = report.find((r) => r.amount === 60n); // Default type is DEPOSIT in logic but logic treats change as 'DEPOSIT' type currently due to same event
    expect(changeEntry).to.not.equal(undefined);
    expect(changeEntry?.status).to.equal("UNSPENT");
  });
});
