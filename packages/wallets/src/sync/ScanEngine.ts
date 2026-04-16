import { EventLog, Log } from "ethers";
import { NoteProcessor } from "./NoteProcessor.js";
import { UnprocessedEvent } from "./types.js";
import { Point } from "@zk-kit/baby-jubjub";
import { LeanIMT } from "../merkle/LeanIMT.js";
import { toFr } from "../crypto/fields.js";
import { Contract } from "ethers";
import { IKeyRepository, IUtxoRepository } from "../repositories.js";

export class ScanEngine {
  private processor: NoteProcessor;
  private readonly lookaheadWindow: number;

  constructor(
    private contract: Contract,
    private keyRepo: IKeyRepository,
    private utxoRepo: IUtxoRepository,
    compliancePk: Point<bigint>,
    private merkleTree?: LeanIMT,
    lookaheadWindow: number = 20
  ) {
    this.lookaheadWindow = lookaheadWindow;
    this.processor = new NoteProcessor(keyRepo, compliancePk);
  }

  public async sync(fromBlock: number): Promise<void> {
    await this.keyRepo.advanceEphemeralKeys(this.lookaheadWindow);
    await this.keyRepo.advanceIncomingKeys(this.lookaheadWindow);

    const noteLogs = await this.contract.queryFilter(this.contract.filters.NewNote(), fromBlock);

    const tags = this.keyRepo.getAllTags();
    let memoLogs: Array<EventLog | Log> = [];

    if (tags.length > 0) {
      if (this.merkleTree) {
        memoLogs = await this.contract.queryFilter(this.contract.filters.NewPrivateMemo(), fromBlock);
      } else {
        const filter = this.contract.filters.NewPrivateMemo(null, null, tags);
        memoLogs = await this.contract.queryFilter(filter, fromBlock);
      }
    } else if (this.merkleTree) {
      memoLogs = await this.contract.queryFilter(this.contract.filters.NewPrivateMemo(), fromBlock);
    }

    const nullLogs = await this.contract.queryFilter(this.contract.filters.NullifierSpent(), fromBlock);

    const allLogs = [...noteLogs, ...memoLogs].sort((a, b) => {
      if (a.blockNumber !== b.blockNumber) return a.blockNumber - b.blockNumber;
      return a.index - b.index;
    });

    for (const log of allLogs) {
      if (!('args' in log)) continue;
      const eventLog = log as EventLog;

      if (this.merkleTree) {
        const eventLeafIndex = Number(eventLog.args['leafIndex']);
        const currentTreeIndex = this.merkleTree.nextLeafIndex;

        if (eventLeafIndex > currentTreeIndex) {
          await this.repairTreeGap(fromBlock, currentTreeIndex, eventLeafIndex - 1);
        }
        if (eventLeafIndex === this.merkleTree.nextLeafIndex) {
          const comm = eventLog.args['commitment'] as string;
          await this.merkleTree.insert(toFr(comm));
        }
      }

      await this.processLog(eventLog, log);
    }

    for (const log of nullLogs) {
      if ('args' in log) {
        const eventLog = log as EventLog;
        const nfHash = eventLog.args['nullifierHash'] as string;
        this.utxoRepo.markSpent(nfHash);
      }
    }
  }

  private async repairTreeGap(fromBlock: number, startIndex: number, endIndex: number): Promise<void> {
    if (!this.merkleTree) return;
    const indices: number[] = [];
    for (let i = startIndex; i <= endIndex; i++) indices.push(i);

    const missingNotes = await this.contract.queryFilter(this.contract.filters.NewNote(indices), fromBlock);
    const missingMemos = await this.contract.queryFilter(this.contract.filters.NewPrivateMemo(indices), fromBlock);

    const missingLogs = [...missingNotes, ...missingMemos].sort(
      (a, b) => Number((a as EventLog).args['leafIndex']) - Number((b as EventLog).args['leafIndex'])
    );

    for (const log of missingLogs) {
      const eventLog = log as EventLog;
      const idx = Number(eventLog.args['leafIndex']);

      if (idx === this.merkleTree.nextLeafIndex) {
        const comm = eventLog.args['commitment'] as string;
        await this.merkleTree.insert(toFr(comm));
        await this.processLog(eventLog, log);
      }
    }
  }

  private async processLog(eventLog: EventLog, rawLog: Log | EventLog): Promise<void> {
    let eventType: 'NEW_NOTE' | 'NEW_MEMO' | null = null;
    const name = eventLog.fragment.name;

    if (name === 'NewNote') eventType = 'NEW_NOTE';
    if (name === 'NewPrivateMemo') eventType = 'NEW_MEMO';
    if (!eventType) return;

    const rawEvent: UnprocessedEvent = {
      type: eventType,
      blockNumber: rawLog.blockNumber,
      txHash: rawLog.transactionHash,
      args: {
        leafIndex: BigInt(eventLog.args['leafIndex']),
        commitment: eventLog.args['commitment'] as string,
        epkX: BigInt(eventLog.args['ephemeralPK_x']),
        epkY: BigInt(eventLog.args['ephemeralPK_y']),
        packedCiphertext: eventLog.args['packedCiphertext'] as string[],
        tag: eventType === 'NEW_MEMO' ? BigInt(eventLog.args['recipientP_x']) : undefined,
        intermediateBobX: eventType === 'NEW_MEMO' ? BigInt(eventLog.args['intermediateBob_x']) : undefined,
        intermediateBobY: eventType === 'NEW_MEMO' ? BigInt(eventLog.args['intermediateBob_y']) : undefined
      }
    };

    const walletNote = await this.processor.process(rawEvent);
    if (walletNote) {
      await this.utxoRepo.addNote(walletNote);
    }
  }
}
