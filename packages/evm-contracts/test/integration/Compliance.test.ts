import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  mintIncomingNote,
  evenYEphemeral,
  subgroupScalar,
  COMPLIANCE_SK,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import {
  Fr,
  toFr,
  addressToFr,
  publicKey,
  deriveCek,
  demDecrypt,
  computePsi,
  computeNullifier,
  Note,
} from "@hisoka/wallets";
import { proveTransfer, TransferInputs } from "@hisoka/prover";
import { Point } from "@zk-kit/baby-jubjub";
import { DarkPool } from "../../typechain-types";

// Compliance reads every note structurally: CEK = (complianceSk * eph_pub).x, psi -> nullifier follows.
class ComplianceTool {
  public observedNotes: Map<string, { note: Note; type: "NOTE" | "MEMO" }> =
    new Map();
  public spentNullifiers: Set<string> = new Set();

  constructor(
    public readonly complianceSk: bigint,
    public readonly contract: DarkPool,
  ) {}

  async sync() {
    const noteEvents = await this.contract.queryFilter(
      this.contract.filters.NewNote(),
    );
    for (const ev of noteEvents) await this.decrypt(ev, "NOTE");

    const memoEvents = await this.contract.queryFilter(
      this.contract.filters.NewPrivateMemo(),
    );
    for (const ev of memoEvents) await this.decrypt(ev, "MEMO");

    const nullEvents = await this.contract.queryFilter(
      this.contract.filters.NullifierSpent(),
    );
    for (const ev of nullEvents) {
      this.spentNullifiers.add(ev.args.nullifierHash);
    }
  }

  private async decrypt(event: any, type: "NOTE" | "MEMO") {
    const ephPub: Point<bigint> = [
      BigInt(event.args.ephemeralPK_x),
      BigInt(event.args.ephemeralPK_y),
    ];
    const ciphertext = (event.args.packedCiphertext as string[]).map((h) =>
      toFr(h),
    );
    try {
      const cek = deriveCek(new Fr(this.complianceSk), ephPub);
      const plaintext = await demDecrypt(cek, ciphertext);
      const psi = await computePsi(cek);
      const leafIndex = Number(event.args.leafIndex);
      const note: Note = {
        noteVersion: plaintext[0],
        assetId: plaintext[1],
        noteType: plaintext[2],
        conditionsHash: plaintext[3],
        value: plaintext[4].toBigInt(),
        owner: plaintext[5],
        psi,
        parents: plaintext[6],
      };
      const nf = await computeNullifier(psi, new Fr(BigInt(leafIndex)));
      this.observedNotes.set(nf.toString(), { note, type });
    } catch {
      /* undecryptable note skipped */
    }
  }

  report() {
    return Array.from(this.observedNotes.entries()).map(([nf, data]) => ({
      type: data.type,
      amount: data.note.value,
      status: this.spentNullifiers.has(nf) ? "SPENT" : "UNSPENT",
    }));
  }
}

describe("Integration: Compliance God View", function () {
  it("should successfully trace a Deposit -> Transfer flow", async function () {
    const { darkPool, token, alice } = await loadFixture(deployDarkPoolFixture);
    const assetFr = addressToFr(await token.getAddress());

    const dep = await makeDeposit(darkPool, token, alice, 100n);

    const bobInKey = evenYEphemeral(555n);
    const bobInPub = publicKey(bobInKey);

    const memo = await mintIncomingNote(
      subgroupScalar(12n),
      40n,
      bobInPub,
      bobInKey,
      assetFr,
    );
    const change = await mintSelfNote(
      evenYEphemeral(34n),
      60n,
      dep.spendScalar,
      assetFr,
    );

    const transferInputs: TransferInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      recipientInPub: bobInPub,
      oldNote: dep.built.note,
      spendScalar: dep.spendScalar,
      oldNoteIndex: 0,
      oldNotePath: Array(32).fill(toFr(0n)),
      memoNote: memo.note,
      memoEph: memo.eph,
      changeNote: change.note,
      changeEph: change.eph,
    };
    const trfProof = await proveTransfer(transferInputs);
    await darkPool
      .connect(alice)
      .privateTransfer(trfProof.proof, trfProof.publicInputs);

    const tool = new ComplianceTool(COMPLIANCE_SK, darkPool);
    await tool.sync();
    const report = tool.report();

    expect(report.length).to.equal(3); // Deposit, Memo, Change

    const depEntry = report.find((r) => r.amount === 100n);
    expect(depEntry).to.not.equal(undefined);
    expect(depEntry?.status).to.equal("SPENT");

    const memoEntry = report.find((r) => r.amount === 40n && r.type === "MEMO");
    expect(memoEntry).to.not.equal(undefined);
    expect(memoEntry?.status).to.equal("UNSPENT");

    const changeEntry = report.find((r) => r.amount === 60n);
    expect(changeEntry).to.not.equal(undefined);
    expect(changeEntry?.status).to.equal("UNSPENT");
  });
});
