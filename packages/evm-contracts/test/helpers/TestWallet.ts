import { ethers } from "ethers";
import {
  DarkAccount,
  LeanIMT,
  Fr,
  toFr,
  addressToFr,
  packParents,
  KeyRepository,
  InMemoryEphemeralCounterStore,
  UtxoRepository,
  ScanEngine,
  WalletNote,
} from "@hisoka/wallets";
import {
  proveDeposit,
  proveWithdraw,
  proveTransfer,
  proveSplit,
  proveJoin,
  provePublicClaim,
  WithdrawInputs,
  TransferInputs,
  SplitInputs,
  JoinInputs,
  PublicClaimInputs,
  ProofData,
} from "@hisoka/prover";
import { Point } from "@zk-kit/baby-jubjub";
import {
  COMPLIANCE_PK,
  HARDHAT_CHAIN_ID,
  newSeededTree,
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
    signer: ethers.ContractRunner & {
      address: string;
      signMessage: (m: string) => Promise<string>;
    },
    darkPool: DarkPool,
    token: MockERC20,
    fromBlock?: number,
  ) {
    const wallet = new TestWallet(signer, darkPool, token);
    const signature = await signer.signMessage("Hisoka Test Login");
    wallet.account = await DarkAccount.fromSignature(signature);

    const provider = signer.provider;
    const chainId = provider
      ? (await provider.getNetwork()).chainId
      : HARDHAT_CHAIN_ID;
    wallet.tree = await newSeededTree(chainId);
    wallet.keyRepo = new KeyRepository(
      wallet.account,
      new InMemoryEphemeralCounterStore(),
    );
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
    return this.utxoRepo.getBalance(asset ? addressToFr(asset) : undefined);
  }

  private async assetFr(asset?: string): Promise<Fr> {
    return addressToFr(asset ?? (await this.token.getAddress()));
  }

  private pickNote(assetFr: Fr, minValue: bigint): WalletNote {
    const note = this.utxoRepo
      .getUnspentNotes()
      .find((n) => n.note.assetId.equals(assetFr) && n.note.value >= minValue);
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
      packParents([{ leafIndex: Number(input.leafIndex) }, { leafIndex: 0 }]),
    );

    const inputs: WithdrawInputs = {
      withdrawValue: toFr(amount),
      recipient: addressToFr(recipient),
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
    const parents = packParents([
      { leafIndex: Number(input.leafIndex) },
      { leafIndex: 0 },
    ]);

    const memoEph = subgroupScalar(ethers.toBigInt(ethers.randomBytes(16)));
    const memo = await mintIncomingNote(
      memoEph,
      amount,
      recipientInPub,
      toFr(0n),
      assetFr,
      parents,
    );

    const { eph: changeEph } = await this.keyRepo.nextSelfEphemeral();
    const spendScalar = await this.account.getSelfSpendKey();
    const change = await mintSelfNote(
      changeEph,
      input.note.value - amount,
      spendScalar,
      assetFr,
      parents,
    );

    const inputs: TransferInputs = {
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

  async split(amountA: bigint, amountB: bigint, asset?: string) {
    const assetFr = await this.assetFr(asset);
    const input = this.pickNote(assetFr, amountA + amountB);
    const parents = packParents([
      { leafIndex: Number(input.leafIndex) },
      { leafIndex: 0 },
    ]);
    const spendScalar = await this.account.getSelfSpendKey();

    const { eph: eph1 } = await this.keyRepo.nextSelfEphemeral();
    const out1 = await mintSelfNote(
      eph1,
      amountA,
      spendScalar,
      assetFr,
      parents,
    );
    const { eph: eph2 } = await this.keyRepo.nextSelfEphemeral();
    const out2 = await mintSelfNote(
      eph2,
      amountB,
      spendScalar,
      assetFr,
      parents,
    );

    const inputs: SplitInputs = {
      compliancePk: COMPLIANCE_PK,
      noteIn: noteToInput(input.note),
      spendScalar: input.spendScalar,
      indexIn: input.leafIndex,
      pathIn: this.tree.getMerklePath(input.leafIndex),
      noteOut1: out1.note,
      eph1,
      noteOut2: out2.note,
      eph2,
    };

    const proof = await proveSplit(inputs);
    await this.darkPool
      .connect(this.signer)
      .split(proof.proof, proof.publicInputs);

    return { commitment1: out1.commitment, commitment2: out2.commitment };
  }

  async join(asset?: string) {
    const assetFr = await this.assetFr(asset);
    const notes = this.utxoRepo
      .getUnspentNotes()
      .filter((n) => n.note.assetId.equals(assetFr))
      .sort((a, b) => Number(a.leafIndex) - Number(b.leafIndex));
    if (notes.length < 2) {
      throw new Error("join requires >= 2 unspent notes of the asset");
    }
    const [noteA, noteB] = notes;
    const parents = packParents([
      { leafIndex: Number(noteA.leafIndex) },
      { leafIndex: Number(noteB.leafIndex) },
    ]);
    const spendScalar = await this.account.getSelfSpendKey();
    const { eph: ephOut } = await this.keyRepo.nextSelfEphemeral();
    const out = await mintSelfNote(
      ephOut,
      noteA.note.value + noteB.note.value,
      spendScalar,
      assetFr,
      parents,
    );

    const inputs: JoinInputs = {
      compliancePk: COMPLIANCE_PK,
      noteA: noteToInput(noteA.note),
      spendScalarA: noteA.spendScalar,
      indexA: noteA.leafIndex,
      pathA: this.tree.getMerklePath(noteA.leafIndex),
      noteB: noteToInput(noteB.note),
      spendScalarB: noteB.spendScalar,
      indexB: noteB.leafIndex,
      pathB: this.tree.getMerklePath(noteB.leafIndex),
      noteOut: out.note,
      ephOut,
    };

    const proof = await proveJoin(inputs);
    await this.darkPool
      .connect(this.signer)
      .join(proof.proof, proof.publicInputs);

    return { commitment: out.commitment };
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
