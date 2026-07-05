import { ethers as ethersLib } from "ethers";
import { toFr, addressToFr, Fr } from "@hisoka/wallets";
import {
  proveGasPayment,
  proveWithdraw,
  proveSplit,
  proveJoin,
  proveTransfer,
  GasPaymentInputs,
  ProofData,
} from "@hisoka/prover";
import { Point } from "@zk-kit/baby-jubjub";
import { TestWallet } from "./TestWallet";
import {
  COMPLIANCE_PK,
  mintSelfNote,
  mintIncomingNote,
  noteToInput,
  subgroupScalar,
} from "./fixtures";
import type { DarkPool, MockERC20 } from "../../typechain-types";

const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Wraps TestWallet with gas-paid RelayerMulticall transport: every non-deposit action is bundled with a
 * payRelayer proof that spends a separate shielded note to fund the relayer. */
export class MixnetWallet {
  public readonly base: TestWallet;
  private gasPaymentFee = 1n;

  private constructor(
    base: TestWallet,
    public multicallAddress: string,
    public relayerAddress: string,
  ) {
    this.base = base;
  }

  static async create(
    signer: ethersLib.ContractRunner & {
      address: string;
      signMessage: (m: string) => Promise<string>;
    },
    darkPool: DarkPool,
    token: MockERC20,
    multicallAddress: string,
    relayerAddress: string,
    fromBlock?: number,
  ): Promise<MixnetWallet> {
    const base = await TestWallet.create(signer, darkPool, token, fromBlock);
    return new MixnetWallet(base, multicallAddress, relayerAddress);
  }

  get signer() {
    return this.base.signer;
  }
  get tree() {
    return this.base.tree;
  }
  get utxoRepo() {
    return this.base.utxoRepo;
  }
  get keyRepo() {
    return this.base.keyRepo;
  }
  get account() {
    return this.base.account;
  }

  getBalance(asset?: string) {
    return this.base.getBalance(asset);
  }
  async deposit(amount: bigint, asset?: string) {
    return this.base.deposit(amount, asset);
  }
  async sync() {
    return this.base.sync();
  }
  async getReceiveAddress() {
    return this.base.getReceiveAddress();
  }

  private computeExecutionHash(actionCalldata: string): Fr {
    return toFr(
      BigInt(ethersLib.keccak256(actionCalldata)) % BN254_FR_MODULUS,
    );
  }

  private async assetFr(): Promise<Fr> {
    return addressToFr(await this.base.token.getAddress());
  }

  private async buildGasProof(
    executionHash: Fr,
    excludeLeafIndices: number[],
  ): Promise<ProofData> {
    const fee = this.gasPaymentFee;
    const assetFr = await this.assetFr();
    const exclude = new Set(excludeLeafIndices);

    const note = this.utxoRepo
      .getUnspentNotes()
      .find(
        (n) =>
          n.note.assetId.equals(assetFr) &&
          n.note.value >= fee &&
          !exclude.has(n.leafIndex),
      );
    if (!note) {
      throw new Error(
        `No gas payment note (need >= ${fee}, excluding [${excludeLeafIndices.join(", ")}])`,
      );
    }

    const { eph: changeEph } = await this.keyRepo.nextSelfEphemeral();
    const change = await mintSelfNote(
      changeEph,
      note.note.value - fee,
      await this.account.getSelfSpendKey(),
      assetFr,
    );

    const gasInputs: GasPaymentInputs = {
      currentTimestamp: Math.floor(Date.now() / 1000),
      paymentValue: toFr(fee),
      paymentAssetId: assetFr,
      relayerAddress: addressToFr(this.relayerAddress),
      executionHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: noteToInput(note.note),
      spendScalar: note.spendScalar,
      oldNoteIndex: note.leafIndex,
      oldNotePath: this.tree.getMerklePath(note.leafIndex),
      changeNote: change.note,
      changeEph,
    };

    return proveGasPayment(gasInputs);
  }

  private async submitPaidAction(
    actionCalldata: string,
    excludeLeafIndices: number[],
  ): Promise<string> {
    const darkPoolAddr = await this.base.darkPool.getAddress();
    const executionHash = this.computeExecutionHash(actionCalldata);
    const gasProof = await this.buildGasProof(
      executionHash,
      excludeLeafIndices,
    );

    const iface = this.base.darkPool.interface;
    const payRelayerData = iface.encodeFunctionData("payRelayer", [
      ethersLib.hexlify(gasProof.proof),
      gasProof.publicInputs,
    ]);

    const multicallContract = new ethersLib.Contract(
      this.multicallAddress,
      [
        "function multicall((address target, bytes data, uint256 value, bool requireSuccess)[] calls)",
      ],
      this.signer as unknown as ethersLib.ContractRunner,
    );

    const tx = await multicallContract.multicall([
      {
        target: darkPoolAddr,
        data: payRelayerData,
        value: 0n,
        requireSuccess: true,
      },
      {
        target: darkPoolAddr,
        data: actionCalldata,
        value: 0n,
        requireSuccess: true,
      },
    ]);
    const receipt = await tx.wait();
    return receipt.hash;
  }

  async splitViaMixnet(
    amountA: bigint,
    amountB: bigint,
  ): Promise<{ com1: Fr; com2: Fr; txHash: string }> {
    const assetFr = await this.assetFr();
    const total = amountA + amountB;
    const input = this.utxoRepo
      .getUnspentNotes()
      .find((n) => n.note.assetId.equals(assetFr) && n.note.value >= total);
    if (!input) throw new Error(`No note with >= ${total} for split`);

    const spendScalar = await this.account.getSelfSpendKey();
    const { eph: eph1 } = await this.keyRepo.nextSelfEphemeral();
    const out1 = await mintSelfNote(eph1, amountA, spendScalar, assetFr);
    const { eph: eph2 } = await this.keyRepo.nextSelfEphemeral();
    const out2 = await mintSelfNote(eph2, amountB, spendScalar, assetFr);

    const proof = await proveSplit({
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      noteIn: noteToInput(input.note),
      spendScalar: input.spendScalar,
      indexIn: input.leafIndex,
      pathIn: this.tree.getMerklePath(input.leafIndex),
      noteOut1: out1.note,
      eph1,
      noteOut2: out2.note,
      eph2,
    });

    const actionCalldata = this.base.darkPool.interface.encodeFunctionData(
      "split",
      [proof.proof, proof.publicInputs],
    );
    const txHash = await this.submitPaidAction(actionCalldata, [
      input.leafIndex,
    ]);
    return { com1: out1.commitment, com2: out2.commitment, txHash };
  }

  async joinViaMixnet(
    noteAIndex: number,
    noteBIndex: number,
  ): Promise<{ com: Fr; txHash: string }> {
    const notes = this.utxoRepo.getUnspentNotes();
    const noteA = notes[noteAIndex];
    const noteB = notes[noteBIndex];
    if (!noteA || !noteB) throw new Error("Invalid note indices for join");

    const assetFr = noteA.note.assetId;
    const spendScalar = await this.account.getSelfSpendKey();
    const { eph: ephOut } = await this.keyRepo.nextSelfEphemeral();
    const out = await mintSelfNote(
      ephOut,
      noteA.note.value + noteB.note.value,
      spendScalar,
      assetFr,
    );

    const proof = await proveJoin({
      currentTimestamp: Math.floor(Date.now() / 1000),
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
    });

    const actionCalldata = this.base.darkPool.interface.encodeFunctionData(
      "join",
      [proof.proof, proof.publicInputs],
    );
    const txHash = await this.submitPaidAction(actionCalldata, [
      noteA.leafIndex,
      noteB.leafIndex,
    ]);
    return { com: out.commitment, txHash };
  }

  async withdrawViaMixnet(
    amount: bigint,
    recipient?: string,
  ): Promise<{ txHash: string; changeCom: Fr }> {
    const target = recipient ?? this.signer.address;
    const assetFr = await this.assetFr();
    const input = this.utxoRepo
      .getUnspentNotes()
      .find((n) => n.note.assetId.equals(assetFr) && n.note.value >= amount);
    if (!input) throw new Error(`No note with >= ${amount} for withdraw`);

    const spendScalar = await this.account.getSelfSpendKey();
    const { eph: changeEph } = await this.keyRepo.nextSelfEphemeral();
    const change = await mintSelfNote(
      changeEph,
      input.note.value - amount,
      spendScalar,
      assetFr,
    );

    const proof = await proveWithdraw({
      withdrawValue: toFr(amount),
      recipient: addressToFr(target),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0n),
      compliancePk: COMPLIANCE_PK,
      oldNote: noteToInput(input.note),
      spendScalar: input.spendScalar,
      oldNoteIndex: input.leafIndex,
      oldNotePath: this.tree.getMerklePath(input.leafIndex),
      changeNote: change.note,
      changeEph,
    });

    const actionCalldata = this.base.darkPool.interface.encodeFunctionData(
      "withdraw",
      [proof.proof, proof.publicInputs],
    );
    const txHash = await this.submitPaidAction(actionCalldata, [
      input.leafIndex,
    ]);
    return { txHash, changeCom: change.commitment };
  }

  async transferViaMixnet(
    amount: bigint,
    recipientInPub: Point<bigint>,
  ): Promise<{
    memoCommitment: Fr;
    changeCommitment: Fr;
    txHash: string;
    publicInputs: string[];
  }> {
    const assetFr = await this.assetFr();
    const input = this.utxoRepo
      .getUnspentNotes()
      .find((n) => n.note.assetId.equals(assetFr) && n.note.value >= amount);
    if (!input) throw new Error(`Insufficient funds for transfer: ${amount}`);

    const memoEph = subgroupScalar(
      ethersLib.toBigInt(ethersLib.randomBytes(16)),
    );
    const memo = await mintIncomingNote(
      memoEph,
      amount,
      recipientInPub,
      toFr(0n),
      assetFr,
    );

    const spendScalar = await this.account.getSelfSpendKey();
    const { eph: changeEph } = await this.keyRepo.nextSelfEphemeral();
    const change = await mintSelfNote(
      changeEph,
      input.note.value - amount,
      spendScalar,
      assetFr,
    );

    const proof = await proveTransfer({
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
    });

    const actionCalldata = this.base.darkPool.interface.encodeFunctionData(
      "privateTransfer",
      [proof.proof, proof.publicInputs],
    );
    const txHash = await this.submitPaidAction(actionCalldata, [
      input.leafIndex,
    ]);
    return {
      memoCommitment: memo.commitment,
      changeCommitment: change.commitment,
      txHash,
      publicInputs: proof.publicInputs,
    };
  }
}
