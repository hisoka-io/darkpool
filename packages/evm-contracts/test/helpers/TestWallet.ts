import { ethers } from "ethers";
import {
  DarkAccount,
  LeanIMT,
  Fr,
  toFr,
  addressToFr,
  KeyRepository,
  UtxoRepository,
  ScanEngine,
  WalletNote,
} from "@hisoka/wallets";
import {
  proveDeposit,
  proveWithdraw,
  proveTransfer,
  provePublicClaim,
  WithdrawInputs,
  TransferInputs,
  PublicClaimInputs,
  ProofData,
} from "@hisoka/prover";
import { Point } from "@zk-kit/baby-jubjub";
import {
  COMPLIANCE_PK,
  mintSelfNote,
  mintIncomingNote,
  noteToInput,
  subgroupScalar,
} from "./fixtures";
import { DarkPool, MockERC20 } from "../../typechain-types";

export interface WithdrawOptions {
  asset?: string;
  recipient?: string;
  intentHash?: Fr;
}

/** The static receive handle a recipient hands a sender: the sender encrypts the memo to `inPub`. */
export interface ReceiveAddress {
  inKey: Fr;
  inPub: Point<bigint>;
  index: number;
}

export class TestWallet {
  public account!: DarkAccount;
  public keyRepo!: KeyRepository;
  public utxoRepo!: UtxoRepository;
  public scanEngine!: ScanEngine;
  public tree!: LeanIMT;
  public fromBlock: number = 0;

  private constructor(
    public readonly signer: ethers.ContractRunner & { address: string },
    public readonly darkPool: DarkPool,
    public readonly token: MockERC20,
  ) {}

  static async create(
    signer: ethers.ContractRunner & { address: string; signMessage: (m: string) => Promise<string> },
    darkPool: DarkPool,
    token: MockERC20,
    fromBlock?: number,
  ) {
    const wallet = new TestWallet(signer, darkPool, token);
    const signature = await signer.signMessage("Hisoka Test Login");
    wallet.account = await DarkAccount.fromSignature(signature);

    wallet.tree = new LeanIMT(32);
    wallet.keyRepo = new KeyRepository(wallet.account);
    wallet.utxoRepo = new UtxoRepository();
    wallet.fromBlock = fromBlock ?? 0;

    wallet.scanEngine = new ScanEngine(
      darkPool as unknown as ethers.Contract,
      wallet.keyRepo,
      wallet.utxoRepo,
      COMPLIANCE_PK,
      wallet.tree,
    );

    return wallet;
  }

  async syncTree(commitment: Fr) {
    await this.tree.insert(commitment);
  }

  get notes(): WalletNote[] {
    return this.utxoRepo.getAllNotes();
  }

  async sync() {
    await this.scanEngine.sync(this.fromBlock);
  }

  getBalance(asset?: string): bigint {
    return this.utxoRepo.getBalance(
      asset ? addressToFr(asset) : undefined,
    );
  }

  private async assetFr(asset?: string): Promise<Fr> {
    return addressToFr(asset ?? (await this.token.getAddress()));
  }

  private pickNote(assetFr: Fr, minValue: bigint): WalletNote {
    const note = this.utxoRepo
      .getUnspentNotes()
      .find(
        (n) =>
          n.note.assetId.equals(assetFr) && n.note.value >= minValue,
      );
    if (!note) {
      throw new Error(
        `Insufficient funds: need >= ${minValue} of ${assetFr.toString()}`,
      );
    }
    return note;
  }

  /** Issue the next incoming receive address (rolls to even-y, registers the discovery tag). */
  async getReceiveAddress(): Promise<ReceiveAddress> {
    const addr = await this.keyRepo.nextIncomingAddress();
    return { inKey: addr.inKey, inPub: addr.inPub, index: addr.index };
  }

  async deposit(amount: bigint, asset?: string) {
    const assetFr = await this.assetFr(asset);
    const { eph } = await this.keyRepo.nextSelfEphemeral();
    const spendScalar = await this.account.getSelfSpendKey();
    const built = await mintSelfNote(eph, amount, spendScalar, assetFr);

    const proof = await proveDeposit({
      compliancePk: COMPLIANCE_PK,
      note: built.note,
      eph,
    });

    let tokenContract = this.token;
    if (asset && asset !== (await this.token.getAddress())) {
      tokenContract = new ethers.Contract(
        asset,
        this.token.interface,
        this.signer,
      ) as unknown as MockERC20;
    }

    await (
      await tokenContract
        .connect(this.signer)
        .approve(await this.darkPool.getAddress(), amount)
    ).wait();
    const tx = await this.darkPool
      .connect(this.signer)
      .deposit(proof.proof, proof.publicInputs);
    const receipt = await tx.wait();

    return { commitment: built.commitment, receipt };
  }

  async withdraw(
    amount: bigint,
    options: WithdrawOptions = {},
  ): Promise<ProofData> {
    const assetFr = await this.assetFr(options.asset);
    const recipient = options.recipient ?? this.signer.address;
    const intentHash = options.intentHash ?? toFr(0n);

    const input = this.pickNote(assetFr, amount);
    const { eph: changeEph } = await this.keyRepo.nextSelfEphemeral();
    const spendScalar = await this.account.getSelfSpendKey();
    const change = await mintSelfNote(
      changeEph,
      input.note.value - amount,
      spendScalar,
      assetFr,
    );

    const inputs: WithdrawInputs = {
      withdrawValue: toFr(amount),
      recipient: addressToFr(recipient),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: noteToInput(input.note),
      spendScalar: input.spendScalar,
      oldNoteIndex: input.leafIndex,
      oldNotePath: this.tree.getMerklePath(input.leafIndex),
      changeNote: change.note,
      changeEph,
    };

    const proof = await proveWithdraw(inputs);

    if (!intentHash.isZero()) {
      return proof;
    }

    await this.darkPool
      .connect(this.signer)
      .withdraw(proof.proof, proof.publicInputs);
    return proof;
  }

  async transfer(
    amount: bigint,
    recipientInPub: Point<bigint>,
    asset?: string,
  ) {
    const assetFr = await this.assetFr(asset);
    const input = this.pickNote(assetFr, amount);

    const memoEph = subgroupScalar(ethers.toBigInt(ethers.randomBytes(16)));
    const memo = await mintIncomingNote(
      memoEph,
      amount,
      recipientInPub,
      toFr(0n),
      assetFr,
    );

    const { eph: changeEph } = await this.keyRepo.nextSelfEphemeral();
    const spendScalar = await this.account.getSelfSpendKey();
    const change = await mintSelfNote(
      changeEph,
      input.note.value - amount,
      spendScalar,
      assetFr,
    );

    const inputs: TransferInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      recipientInPub,
      oldNote: noteToInput(input.note),
      spendScalar: input.spendScalar,
      oldNoteIndex: input.leafIndex,
      oldNotePath: this.tree.getMerklePath(input.leafIndex),
      memoNote: memo.note,
      memoEph,
      changeNote: change.note,
      changeEph,
    };

    const proof = await proveTransfer(inputs);
    await this.darkPool
      .connect(this.signer)
      .privateTransfer(proof.proof, proof.publicInputs);

    return {
      memoCommitment: memo.commitment,
      changeCommitment: change.commitment,
      publicInputs: proof.publicInputs,
    };
  }

  async claimPublic(
    args: {
      memoId: string;
      ownerX: bigint;
      ownerY: bigint;
      asset: string;
      value: bigint;
      timelock: bigint;
      salt: bigint;
    },
    recipientSk: Fr,
  ) {
    const assetFr = addressToFr(args.asset);
    const { eph } = await this.keyRepo.nextSelfEphemeral();
    const spendScalar = await this.account.getSelfSpendKey();
    const noteOut = await mintSelfNote(eph, args.value, spendScalar, assetFr);

    const inputs: PublicClaimInputs = {
      memoId: toFr(args.memoId),
      compliancePk: COMPLIANCE_PK,
      currentTimestamp: Math.floor(Date.now() / 1000),
      val: toFr(args.value),
      assetId: assetFr,
      timelock: toFr(args.timelock),
      ownerX: toFr(args.ownerX),
      ownerY: toFr(args.ownerY),
      salt: toFr(args.salt),
      recipientSk,
      noteOut: noteOut.note,
      eph,
    };

    const proof = await provePublicClaim(inputs);
    await this.darkPool
      .connect(this.signer)
      .publicClaim(proof.proof, proof.publicInputs);

    return { commitment: noteOut.commitment };
  }
}
