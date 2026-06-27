import { Contract, EventLog } from "ethers";
import {
  NotePlaintext,
  toFr,
  unpackCiphertext,
  complianceDecryptNote,
  complianceDecrypt3Party,
  deriveNullifierPathA,
  deriveNullifierPathB,
  Fr,
} from "@hisoka/wallets";
import { Point } from "@zk-kit/baby-jubjub";

interface DecryptedRecord {
  commitment: string;
  nullifier: string;
  note: NotePlaintext;
  txHash: string;
  blockNumber: number;
  isTransfer: boolean;
}

interface TransactionGraph {
  txHash: string;
  inputs: DecryptedRecord[]; // Notes spent in this tx
  outputs: DecryptedRecord[]; // Notes created in this tx
}

export class ComplianceService {
  // DB: Commitment -> Decrypted Note
  private db: Map<string, DecryptedRecord> = new Map();
  // DB: Nullifier -> Commitment (Reverse lookup to find source of a spend)
  private nullifierMap: Map<string, string> = new Map();

  constructor(
    private readonly complianceSk: bigint,
    private readonly contract: Contract,
    private readonly fromBlock: number = 0,
  ) {}

  /**
   * Scans the chain, decrypts everything, and builds the state.
   */
  async sync() {
    // Query from deployment block to avoid RPC range limits on forks
    const noteEvents = await this.contract.queryFilter(
      this.contract.filters.NewNote(),
      this.fromBlock,
    );
    const memoEvents = await this.contract.queryFilter(
      this.contract.filters.NewPrivateMemo(),
      this.fromBlock,
    );

    // Path A: deposits/changes
    for (const ev of noteEvents) {
      await this.processNewNote(ev as EventLog);
    }

    // Path B: transfers
    for (const ev of memoEvents) {
      await this.processMemo(ev as EventLog);
    }
  }

  /**
   * Reconstructs the flow of funds by grouping events by Transaction Hash.
   */
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

    // Inputs: map each spent nullifier back to its source commitment
    for (const ev of spendEvents) {
      const tx = getTx(ev.transactionHash);
      const nf = (ev as EventLog).args.nullifierHash;
      const commitment = this.nullifierMap.get(nf);
      if (commitment) {
        tx.inputs.push(commitment);
      }
    }

    // Outputs: notes created in each tx
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

  private async processNewNote(event: EventLog) {
    const { ephemeralPK_x, ephemeralPK_y, packedCiphertext } = event.args;
    const epk: Point<bigint> = [ephemeralPK_x, ephemeralPK_y];
    const packed = packedCiphertext.map((h: string) => toFr(h));
    const ct = unpackCiphertext(packed);

    try {
      const note = await complianceDecryptNote(this.complianceSk, epk, ct);
      const commitment = toFr(event.args.commitment);
      const leafIndex = Number(event.args.leafIndex);
      const nf = await deriveNullifierPathA(
        note.nullifier,
        commitment,
        leafIndex,
      );
      this.storeRecord(event, note, nf, false);
    } catch {
      /* Ignore failures */
    }
  }

  private async processMemo(event: EventLog) {
    const {
      commitment,
      packedCiphertext,
      leafIndex,
      intermediateCompliance_x,
      intermediateCompliance_y,
    } = event.args;

    const intermediate: Point<bigint> = [
      intermediateCompliance_x,
      intermediateCompliance_y,
    ];
    const packed = packedCiphertext.map((h: string) => toFr(h));
    const ct = unpackCiphertext(packed);

    try {
      const { note, sharedSecret } = await complianceDecrypt3Party(
        this.complianceSk,
        intermediate,
        ct,
      );
      const nf = await deriveNullifierPathB(
        sharedSecret,
        toFr(commitment),
        Number(leafIndex),
      );
      this.storeRecord(event, note, nf, true);
    } catch {
      /* Ignore */
    }
  }

  private storeRecord(
    event: EventLog,
    note: NotePlaintext,
    nullifier: Fr,
    isTransfer: boolean,
  ) {
    const commitStr = event.args.commitment;
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
