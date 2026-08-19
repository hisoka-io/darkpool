import { ethers } from "ethers";
import {
  DarkAccount,
  LeanIMT,
  Fr,
  toFr,
  addressToFr,
  isEvenY,
  publicKey,
} from "@hisoka/wallets";
import {
  assembleDeposit,
  assembleWithdraw,
  assembleTransfer,
  assembleSplit,
  assembleJoin,
  LocalTreeWitnessSource,
} from "@hisoka/wallets/tx";
import type { AssemblyContext } from "@hisoka/wallets/tx";
import {
  KeyRepository,
  InMemoryEphemeralCounterStore,
  UtxoRepository,
  ScanEngine,
  WalletNote,
} from "@hisoka/wallets/reference";
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
  noteToInput,
  subgroupScalar,
} from "./fixtures";
import { DarkPool, MockERC20 } from "../../typechain-types";

export interface WithdrawOptions {
  asset?: string;
  recipient?: string;
  intentHash?: Fr;
}

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

    // `scanFloor` is min(fromBlock, deploymentBlock), so leaving deploymentBlock at 0 discards the caller's
    // start block and scans from genesis. Harmless on a fresh chain; on a mainnet fork it is ~25M blocks and
    // every real RPC caps eth_getLogs well below that.
    wallet.scanEngine = new ScanEngine(
      darkPool as unknown as ethers.Contract,
      wallet.keyRepo,
      wallet.utxoRepo,
      COMPLIANCE_PK,
      wallet.tree,
      undefined,
      wallet.fromBlock,
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

  /** The assembler's ports, backed by this wallet's own synced tree. */
  private assemblyCtx(): AssemblyContext {
    return {
      compliancePk: COMPLIANCE_PK,
      merkle: new LocalTreeWitnessSource(this.tree),
    };
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

  async getReceiveAddress(): Promise<ReceiveAddress> {
    const addr = await this.keyRepo.nextIncomingAddress();
    return { inKey: addr.inKey, inPub: addr.inPub, index: addr.index };
  }

  async deposit(amount: bigint, asset?: string) {
    const assetFr = await this.assetFr(asset);
    const { eph } = await this.keyRepo.nextSelfEphemeral();
    const spendScalar = await this.account.getSelfSpendKey();
    const assembled = await assembleDeposit(this.assemblyCtx(), {
      value: amount,
      assetId: assetFr,
      spendScalar,
      eph,
    });
    const built = assembled.minted;

    const proof = await proveDeposit(assembled.inputs);

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

    // Delegated to the shipped assembler, so this suite grades @hisoka/wallets rather than a parallel copy.
    // Change derivation, parents packing and the merkle-index cross-check all live there now.
    const assembled = await assembleWithdraw(this.assemblyCtx(), {
      input: {
        note: noteToInput(input.note),
        leaf: input.commitment,
        leafIndex: Number(input.leafIndex),
        spendScalar: input.spendScalar,
      },
      value: amount,
      recipient: addressToFr(recipient),
      selfSpendScalar: await this.account.getSelfSpendKey(),
      changeEph,
      intentHash,
    });
    const inputs = assembled.inputs as unknown as WithdrawInputs;

    const proof = await proveWithdraw(inputs);

    if (!intentHash.isZero()) {
      return proof;
    }

    const tx = await this.darkPool
      .connect(this.signer)
      .withdraw(proof.proof, proof.publicInputs);
    await tx.wait();
    return proof;
  }

  async transfer(
    amount: bigint,
    recipientInPub: Point<bigint>,
    asset?: string,
  ) {
    const assetFr = await this.assetFr(asset);
    const input = this.pickNote(assetFr, amount);

    // The emitted memo eph_pub must be even-y so its y is recoverable off-chain; roll until even.
    let memoEph = subgroupScalar(ethers.toBigInt(ethers.randomBytes(16)));
    while (!isEvenY(publicKey(memoEph))) {
      memoEph = subgroupScalar(ethers.toBigInt(ethers.randomBytes(16)));
    }

    const { eph: changeEph } = await this.keyRepo.nextSelfEphemeral();
    // PARENTS_HIDDEN on the memo and the change parents packing are the assembler's job now.
    const assembled = await assembleTransfer(this.assemblyCtx(), {
      input: {
        note: noteToInput(input.note),
        leaf: input.commitment,
        leafIndex: Number(input.leafIndex),
        spendScalar: input.spendScalar,
      },
      value: amount,
      recipientInPub,
      recipientInKey: toFr(0n),
      selfSpendScalar: await this.account.getSelfSpendKey(),
      memoEph,
      changeEph,
    });
    const memo = assembled.memo;
    const change = assembled.change;
    const inputs = assembled.inputs as unknown as TransferInputs;

    const proof = await proveTransfer(inputs);
    const tx = await this.darkPool
      .connect(this.signer)
      .privateTransfer(proof.proof, proof.publicInputs);
    await tx.wait();

    return {
      memoCommitment: memo.commitment,
      changeCommitment: change.commitment,
      publicInputs: proof.publicInputs,
    };
  }

  async split(amountA: bigint, amountB: bigint, asset?: string) {
    const assetFr = await this.assetFr(asset);
    const input = this.pickNote(assetFr, amountA + amountB);
    const { eph: eph1 } = await this.keyRepo.nextSelfEphemeral();
    const { eph: eph2 } = await this.keyRepo.nextSelfEphemeral();

    // amountB is implied: the assembler derives output 2 as the remainder, which is what the circuit
    // conserves. Passing both would let a caller state a total that does not add up.
    const assembled = await assembleSplit(this.assemblyCtx(), {
      input: {
        note: noteToInput(input.note),
        leaf: input.commitment,
        leafIndex: Number(input.leafIndex),
        spendScalar: input.spendScalar,
      },
      value1: amountA,
      selfSpendScalar: await this.account.getSelfSpendKey(),
      eph1,
      eph2,
    });
    const out1 = assembled.out1;
    const out2 = assembled.out2;
    if (out2.note.value.toBigInt() !== amountB) {
      throw new Error(
        `split remainder ${out2.note.value.toBigInt()} does not match requested ${amountB}`,
      );
    }
    const inputs = assembled.inputs as unknown as SplitInputs;

    const proof = await proveSplit(inputs);
    const tx = await this.darkPool
      .connect(this.signer)
      .split(proof.proof, proof.publicInputs);
    await tx.wait();

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
    const { eph: ephOut } = await this.keyRepo.nextSelfEphemeral();
    // The assembler sorts the pair ascending itself, so the sort above is belt and braces.
    const assembled = await assembleJoin(this.assemblyCtx(), {
      inputA: {
        note: noteToInput(noteA.note),
        leaf: noteA.commitment,
        leafIndex: Number(noteA.leafIndex),
        spendScalar: noteA.spendScalar,
      },
      inputB: {
        note: noteToInput(noteB.note),
        leaf: noteB.commitment,
        leafIndex: Number(noteB.leafIndex),
        spendScalar: noteB.spendScalar,
      },
      selfSpendScalar: await this.account.getSelfSpendKey(),
      ephOut,
    });
    const out = assembled.out;
    const inputs = assembled.inputs as unknown as JoinInputs;

    const proof = await proveJoin(inputs);
    const tx = await this.darkPool
      .connect(this.signer)
      .join(proof.proof, proof.publicInputs);
    await tx.wait();

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
    const tx = await this.darkPool
      .connect(this.signer)
      .publicClaim(proof.proof, proof.publicInputs);
    await tx.wait();

    return { commitment: noteOut.commitment };
  }
}
