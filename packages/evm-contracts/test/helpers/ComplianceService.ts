import { Contract, EventLog } from "ethers";
import {
  Fr,
  toFr,
  deriveCek,
  demDecrypt,
  computePsi,
  computeNullifier,
  leaf,
  NoteV2,
} from "@hisoka/wallets";
import { Point } from "@zk-kit/baby-jubjub";

interface DecryptedRecord {
  commitment: string;
  nullifier: string;
  note: NoteV2;
  txHash: string;
  blockNumber: number;
  isTransfer: boolean;
}

interface TransactionGraph {
  txHash: string;
  inputs: DecryptedRecord[];
  outputs: DecryptedRecord[];
}

/** Compliance decrypts every note STRUCTURALLY: the content key is (complianceSk * eph_pub).x == (eph * C).x,
 * so no per-recipient wrap or DLEQ is needed. psi (hence the nullifier) follows from the same key. */
export class ComplianceService {
  private db: Map<string, DecryptedRecord> = new Map();
  private nullifierMap: Map<string, string> = new Map();

  constructor(
    private readonly complianceSk: bigint,
    private readonly contract: Contract,
    private readonly fromBlock: number = 0,
  ) {}

  async sync() {
    const noteEvents = await this.contract.queryFilter(
      this.contract.filters.NewNote(),
      this.fromBlock,
    );
    const memoEvents = await this.contract.queryFilter(
      this.contract.filters.NewPrivateMemo(),
      this.fromBlock,
    );

    for (const ev of noteEvents) {
      await this.decrypt(ev as EventLog, false);
    }
    for (const ev of memoEvents) {
      await this.decrypt(ev as EventLog, true);
    }
  }

  async traceTransactions(): Promise<TransactionGraph[]> {
    const spendEvents = await this.contract.queryFilter(
      this.contract.filters.NullifierSpent(),
      this.fromBlock,
    );

    const txs = new Map<string, { inputs: string[]; outputs: string[] }>();
    const getTx = (hash: string) => {
      if (!txs.has(hash)) txs.set(hash, { inputs: [], outputs: [] });
      return txs.get(hash)!;
    };

    for (const ev of spendEvents) {
      const tx = getTx(ev.transactionHash);
      const nf = (ev as EventLog).args.nullifierHash;
      const commitment = this.nullifierMap.get(nf);
      if (commitment) tx.inputs.push(commitment);
    }

    for (const rec of this.db.values()) {
      const tx = getTx(rec.txHash);
      tx.outputs.push(rec.commitment);
    }

    const graph: TransactionGraph[] = [];
    for (const [hash, data] of txs.entries()) {
      graph.push({
        txHash: hash,
        inputs: data.inputs.map((c) => this.db.get(c)!),
        outputs: data.outputs.map((c) => this.db.get(c)!),
      });
    }
    return graph;
  }

  private async decrypt(event: EventLog, isTransfer: boolean): Promise<void> {
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
      const commitment = toFr(event.args.commitment);
      const leafIndex = Number(event.args.leafIndex);

      const note: NoteV2 = {
        noteVersion: plaintext[0],
        assetId: plaintext[1],
        noteType: plaintext[2],
        conditionsHash: plaintext[3],
        value: plaintext[4].toBigInt(),
        owner: plaintext[5],
        psi,
        parents: plaintext[6],
      };

      const rebuilt = await leaf(note);
      if (!rebuilt.equals(commitment)) return;

      const nullifier = await computeNullifier(psi, new Fr(BigInt(leafIndex)));
      this.store(event, note, nullifier, isTransfer);
    } catch {
      /* a note this key cannot decrypt is skipped */
    }
  }

  private store(
    event: EventLog,
    note: NoteV2,
    nullifier: Fr,
    isTransfer: boolean,
  ): void {
    const commitStr = event.args.commitment as string;
    const nfStr = nullifier.toString();
    this.db.set(commitStr, {
      commitment: commitStr,
      nullifier: nfStr,
      note,
      txHash: event.transactionHash,
      blockNumber: event.blockNumber,
      isTransfer,
    });
    this.nullifierMap.set(nfStr, commitStr);
  }
}
