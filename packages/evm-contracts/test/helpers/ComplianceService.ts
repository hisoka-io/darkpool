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
    // 1. Fetch All Events (from deployment block to avoid RPC limits on forks)
    const noteEvents = await this.contract.queryFilter(
      this.contract.filters.NewNote(),
      this.fromBlock,
    );
    const memoEvents = await this.contract.queryFilter(
      this.contract.filters.NewPrivateMemo(),
      this.fromBlock,
    );

    // 2. Decrypt & Index (Path A: Deposits/Changes)
    for (const ev of noteEvents) {
      await this.processNewNote(ev as EventLog);
    }

    // 3. Decrypt & Index (Path B: Transfers)
    for (const ev of memoEvents) {
      await this.processMemo(ev as EventLog);
    }
  }

  /**
   * Reconstructs the flow of funds by grouping events by Transaction Hash.
   */
  async traceTransactions(): Promise<TransactionGraph[]> {
    // 1. Fetch Spend Events
    const spendEvents = await this.contract.queryFilter(
      this.contract.filters.NullifierSpent(),
      this.fromBlock,
    );

    // 2. Group Spends by TxHash
    const txs = new Map<string, { inputs: string[]; outputs: string[] }>();

    // Helper to get/init tx entry
    const getTx = (hash: string) => {
      if (!txs.has(hash)) txs.set(hash, { inputs: [], outputs: [] });
      return txs.get(hash)!;
    };

    // Map Inputs (Spends)
    for (const ev of spendEvents) {
      const tx = getTx(ev.transactionHash);
      const nf = (ev as EventLog).args.nullifierHash;
      // Find which note this nullifier belongs to
      const commitment = this.nullifierMap.get(nf);
      if (commitment) {
        tx.inputs.push(commitment);
      }
    }

    // Map Outputs (Creations)
    for (const rec of this.db.values()) {
      const tx = getTx(rec.txHash);
      tx.outputs.push(rec.commitment);
    }

    // 3. Build Rich Graph
    const graph: TransactionGraph[] = [];
    for (const [hash, data] of txs.entries()) {
      // Sort by block number/index logic if needed, for now just raw dump
      graph.push({
        txHash: hash,
        inputs: data.inputs.map((c) => this.db.get(c)!),
        outputs: data.outputs.map((c) => this.db.get(c)!),
      });
    }

    return graph;
  }

  // --- INTERNAL PROCESSORS ---

  private async processNewNote(event: EventLog) {
    const { ephemeralPK_x, ephemeralPK_y, packedCiphertext } = event.args;
    const epk: Point<bigint> = [ephemeralPK_x, ephemeralPK_y];
    const packed = packedCiphertext.map((h: string) => toFr(h));
    const ct = unpackCiphertext(packed);

    try {
      const note = await complianceDecryptNote(this.complianceSk, epk, ct);
      const nf = await deriveNullifierPathA(note.nullifier);
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
