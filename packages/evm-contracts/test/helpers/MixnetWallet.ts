 
/**
 * MixnetWallet — wraps TestWallet with gas-paid multicall transport.
 *
 * All non-deposit operations use RelayerMulticall:
 *   1. Build action proof locally (withdraw/transfer/split/join)
 *   2. Build gas payment proof (pays relayer from shielded note)
 *   3. Bundle both into multicall: [payRelayer, action]
 *   4. Submit atomically on-chain
 *
 * Uses composition (wraps TestWallet) because TestWallet has a private constructor.
 */

import { ethers as ethersLib } from "ethers";
import {
  toFr,
  addressToFr,
  deriveSharedSecret,
  Poseidon,
  Fr,
  NotePlaintext,
} from "@hisoka/wallets";
import {
  proveGasPayment,
  proveWithdraw,
  proveSplit,
  proveJoin,
  proveTransfer,
  GasPaymentInputs,
} from "@hisoka/prover";
import { TestWallet } from "./TestWallet";
import { COMPLIANCE_PK } from "./fixtures";
import type { DarkPool, MockERC20 } from "../../typechain-types";

const BN254_FR_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const BJJ_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

export class MixnetWallet {
  public readonly base: TestWallet;
  public multicallAddress: string;
  public relayerAddress: string;
  private gasPaymentFee = 1n; // Fixed 1-token fee for testing

  private constructor(
    base: TestWallet,
    multicallAddress: string,
    relayerAddress: string,
  ) {
    this.base = base;
    this.multicallAddress = multicallAddress;
    this.relayerAddress = relayerAddress;
  }

  static async create(
    signer: any,
    darkPool: DarkPool,
    token: MockERC20,
    multicallAddress: string,
    relayerAddress: string,
    fromBlock?: number,
  ): Promise<MixnetWallet> {
    const base = await TestWallet.create(signer, darkPool, token, fromBlock);
    return new MixnetWallet(base, multicallAddress, relayerAddress);
  }

  // ---- Delegated accessors ----
  get signer() { return this.base.signer; }
  get tree() { return this.base.tree; }
  get utxoRepo() { return this.base.utxoRepo; }
  get keyRepo() { return this.base.keyRepo; }
  get account() { return this.base.account; }

  getBalance(asset?: string) { return this.base.getBalance(asset); }
  async deposit(amount: bigint, asset?: string) { return this.base.deposit(amount, asset); }
  async syncTree(commitment: Fr) { return this.base.syncTree(commitment); }
  async sync() { return this.base.sync(); }
  async transfer(amount: bigint, B: any, P: any, pi: any, asset?: string) {
    return this.base.transfer(amount, B, P, pi, asset);
  }
  async withdraw(amount: bigint, options?: any) { return this.base.withdraw(amount, options); }

  // ---- Gas payment helpers ----

  private computeExecutionHash(actionCalldata: string): Fr {
    return toFr(
      BigInt(ethersLib.keccak256(actionCalldata)) % BN254_FR_MODULUS,
    );
  }

  private async buildGasPaymentInputs(
    executionHash: Fr,
    excludeLeafIndices: number[] = [],
    paymentAmount?: bigint,
  ): Promise<{ gasInputs: GasPaymentInputs; paymentNote: any }> {
    const fee = paymentAmount ?? this.gasPaymentFee;
    const tokenAddr = await this.base.token.getAddress();
    const tokenFr = addressToFr(tokenAddr);

    const excludeSet = new Set(excludeLeafIndices);
    const notes = this.utxoRepo.getUnspentNotes();
    const candidates = notes.filter(
      (n) =>
        n.note.asset_id.toString() === tokenFr.toString() &&
        n.note.value.toBigInt() >= fee &&
        !excludeSet.has(n.leafIndex),
    );
    const paymentNote = candidates[0];

    if (!paymentNote) {
      throw new Error(
        `No gas payment note (need >= ${fee}, excluding leaves [${excludeLeafIndices.join(", ")}]). ` +
        `Available: ${notes.map((n) => `leaf=${n.leafIndex} val=${n.note.value.toBigInt()}`).join(", ")}`,
      );
    }

    const oldSecret = paymentNote.isTransfer
      ? paymentNote.spendingSecret
      : await deriveSharedSecret(paymentNote.spendingSecret, COMPLIANCE_PK);

    const changeValue = paymentNote.note.value.toBigInt() - fee;
    const changeNote: NotePlaintext = {
      asset_id: paymentNote.note.asset_id,
      value: toFr(changeValue),
      secret: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      nullifier: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      timelock: toFr(0),
      hashlock: toFr(0),
    };
    const { sk: changeEphSk } = await this.keyRepo.nextEphemeralParams();

    const gasInputs: GasPaymentInputs = {
      merkleRoot: this.tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      paymentValue: toFr(fee),
      paymentAssetId: tokenFr,
      relayerAddress: addressToFr(this.relayerAddress),
      executionHash,
      compliancePk: COMPLIANCE_PK,
      oldNote: paymentNote.note,
      oldSharedSecret: oldSecret,
      oldNoteIndex: paymentNote.leafIndex,
      oldNotePath: this.tree.getMerklePath(paymentNote.leafIndex),
      hashlockPreimage: toFr(0),
      changeNote,
      changeEphemeralSk: changeEphSk,
    };

    return { gasInputs, paymentNote };
  }

  /**
   * Submit a paid action: [payRelayer, actionCall] via RelayerMulticall.
   */
  private async submitPaidAction(
    actionCalldata: string,
    excludeLeafIndices: number[] = [],
    paymentAmount?: bigint,
  ): Promise<{ txHash: string; gasProof: any }> {
    const darkPoolAddr = await this.base.darkPool.getAddress();
    const executionHash = this.computeExecutionHash(actionCalldata);

    const { gasInputs, paymentNote } = await this.buildGasPaymentInputs(
      executionHash,
      excludeLeafIndices,
      paymentAmount,
    );

    console.log(
      `      [gas] payment note: leaf=${paymentNote.leafIndex}, val=${paymentNote.note.value.toBigInt()}, fee=${this.gasPaymentFee}`,
    );
    console.log(
      `      [gas] merkleRoot=${gasInputs.merkleRoot.toString().slice(0, 20)}..., isTransfer=${paymentNote.isTransfer}`,
    );

    console.log(`      [gas] note fields: value=${gasInputs.oldNote.value.toBigInt()}, payment=${gasInputs.paymentValue.toBigInt()}, change=${gasInputs.changeNote.value.toBigInt()}`);
    console.log(`      [gas] note: nullifier=${gasInputs.oldNote.nullifier.toBigInt() !== 0n ? "nonzero" : "ZERO"}, secret=${gasInputs.oldNote.secret.toBigInt() !== 0n ? "nonzero" : "ZERO"}`);
    console.log(`      [gas] pathLen=${gasInputs.oldNotePath.length}, idx=${gasInputs.oldNoteIndex}`);
    const gasProof = await proveGasPayment(gasInputs);

    // Encode payRelayer calldata
    const iface = this.base.darkPool.interface;
    const payRelayerData = iface.encodeFunctionData("payRelayer", [
      ethersLib.hexlify(gasProof.proof),
      gasProof.publicInputs.map((v: string) => ethersLib.zeroPadValue(v, 32)),
    ]);

    // Submit multicall: [payRelayer, action]
    const multicallContract = new ethersLib.Contract(
      this.multicallAddress,
      [
        "function multicall((address target, bytes data, uint256 value, bool requireSuccess)[] calls)",
      ],
      this.signer as any,
    );

    const tx = await multicallContract.multicall([
      { target: darkPoolAddr, data: payRelayerData, value: 0n, requireSuccess: true },
      { target: darkPoolAddr, data: actionCalldata, value: 0n, requireSuccess: true },
    ]);
    const receipt = await tx.wait();

    return { txHash: receipt.hash, gasProof };
  }

  // =========================================================================
  // Paid Operations
  // =========================================================================

  async splitViaMixnet(
    amountA: bigint,
    amountB: bigint,
  ): Promise<{ com1: Fr; com2: Fr; txHash: string }> {
    const notes = this.utxoRepo.getUnspentNotes();
    const total = amountA + amountB;
    const inputNote = notes.find((n) => n.note.value.toBigInt() >= total);
    if (!inputNote) throw new Error(`No note with >= ${total} for split`);

    const oldSecret = inputNote.isTransfer
      ? inputNote.spendingSecret
      : await deriveSharedSecret(inputNote.spendingSecret, COMPLIANCE_PK);

    const noteOut1: NotePlaintext = {
      asset_id: inputNote.note.asset_id,
      value: toFr(amountA),
      secret: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      nullifier: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      timelock: toFr(0),
      hashlock: toFr(0),
    };
    const { sk: skOut1 } = await this.keyRepo.nextEphemeralParams();

    const noteOut2: NotePlaintext = {
      asset_id: inputNote.note.asset_id,
      value: toFr(amountB),
      secret: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      nullifier: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      timelock: toFr(0),
      hashlock: toFr(0),
    };
    const { sk: skOut2 } = await this.keyRepo.nextEphemeralParams();

    const proof = await proveSplit({
      merkleRoot: this.tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      noteIn: inputNote.note,
      secretIn: oldSecret,
      indexIn: inputNote.leafIndex,
      pathIn: this.tree.getMerklePath(inputNote.leafIndex),
      preimageIn: toFr(0),
      noteOut1, skOut1, noteOut2, skOut2,
    });

    const actionCalldata = this.base.darkPool.interface.encodeFunctionData(
      "split", [proof.proof, proof.publicInputs],
    );

    const { txHash } = await this.submitPaidAction(actionCalldata, [inputNote.leafIndex]);

    const pub = proof.publicInputs.map((s) => toFr(s));
    const com1 = await Poseidon.hash(pub.slice(7, 14));
    const com2 = await Poseidon.hash(pub.slice(16, 23));
    return { com1, com2, txHash };
  }

  async withdrawViaMixnet(
    amount: bigint,
    recipient?: string,
  ): Promise<{ txHash: string; changeCom: Fr }> {
    const targetRecipient = recipient ?? this.signer.address;
    const tokenAddr = await this.base.token.getAddress();
    const tokenFr = addressToFr(tokenAddr);

    const notes = this.utxoRepo.getUnspentNotes();
    const inputNote = notes.find(
      (n) => n.note.asset_id.toString() === tokenFr.toString() && n.note.value.toBigInt() >= amount,
    );
    if (!inputNote) throw new Error(`No note with >= ${amount} for withdraw`);

    const oldSecret = inputNote.isTransfer
      ? inputNote.spendingSecret
      : await deriveSharedSecret(inputNote.spendingSecret, COMPLIANCE_PK);

    const changeValue = inputNote.note.value.toBigInt() - amount;
    const changeNote: NotePlaintext = {
      ...inputNote.note,
      value: toFr(changeValue),
      secret: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      nullifier: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      timelock: toFr(0), hashlock: toFr(0),
    };
    const { sk: changeEphSk } = await this.keyRepo.nextEphemeralParams();

    const proof = await proveWithdraw({
      withdrawValue: toFr(amount),
      recipient: addressToFr(targetRecipient),
      merkleRoot: this.tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: toFr(0),
      compliancePk: COMPLIANCE_PK,
      oldNote: inputNote.note,
      oldSharedSecret: oldSecret,
      oldNoteIndex: inputNote.leafIndex,
      oldNotePath: this.tree.getMerklePath(inputNote.leafIndex),
      hashlockPreimage: toFr(0),
      changeNote, changeEphemeralSk: changeEphSk,
    });

    const actionCalldata = this.base.darkPool.interface.encodeFunctionData(
      "withdraw", [proof.proof, proof.publicInputs],
    );

    const { txHash } = await this.submitPaidAction(actionCalldata, [inputNote.leafIndex]);

    const pub = proof.publicInputs.map((s) => toFr(s));
    const changeCom = await Poseidon.hash(pub.slice(10, 17));
    return { txHash, changeCom };
  }

  async joinViaMixnet(
    noteAIndex: number,
    noteBIndex: number,
  ): Promise<{ com: Fr; txHash: string }> {
    const notes = this.utxoRepo.getUnspentNotes();
    const noteA = notes[noteAIndex];
    const noteB = notes[noteBIndex];
    if (!noteA || !noteB) throw new Error("Invalid note indices for join");

    const secretA = noteA.isTransfer
      ? noteA.spendingSecret
      : await deriveSharedSecret(noteA.spendingSecret, COMPLIANCE_PK);
    const secretB = noteB.isTransfer
      ? noteB.spendingSecret
      : await deriveSharedSecret(noteB.spendingSecret, COMPLIANCE_PK);

    const totalValue = noteA.note.value.toBigInt() + noteB.note.value.toBigInt();
    const noteOut: NotePlaintext = {
      asset_id: noteA.note.asset_id,
      value: toFr(totalValue),
      secret: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      nullifier: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      timelock: toFr(0), hashlock: toFr(0),
    };
    const { sk: skOut } = await this.keyRepo.nextEphemeralParams();

    const proof = await proveJoin({
      merkleRoot: this.tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      noteA: noteA.note, secretA, indexA: noteA.leafIndex,
      pathA: this.tree.getMerklePath(noteA.leafIndex), preimageA: toFr(0),
      noteB: noteB.note, secretB, indexB: noteB.leafIndex,
      pathB: this.tree.getMerklePath(noteB.leafIndex), preimageB: toFr(0),
      noteOut, skOut,
    });

    const actionCalldata = this.base.darkPool.interface.encodeFunctionData(
      "join", [proof.proof, proof.publicInputs],
    );

    // Exclude both join input notes from gas payment selection
    const { txHash } = await this.submitPaidAction(actionCalldata, [noteA.leafIndex, noteB.leafIndex]);

    const pub = proof.publicInputs.map((s) => toFr(s));
    const com = await Poseidon.hash(pub.slice(7, 14));
    return { com, txHash };
  }

  async transferViaMixnet(
    amount: bigint,
    recipientB: any,
    recipientP: any,
    recipientProof: any,
  ): Promise<{ memoCommitment: Fr; changeCommitment: Fr; txHash: string; publicInputs: string[] }> {
    const tokenAddr = await this.base.token.getAddress();
    const tokenFr = addressToFr(tokenAddr);

    const notes = this.utxoRepo.getUnspentNotes();
    const inputData = notes.find(
      (n) => n.note.asset_id.toString() === tokenFr.toString() && n.note.value.toBigInt() >= amount,
    );
    if (!inputData) throw new Error(`Insufficient funds for transfer: ${amount}`);

    const oldSecret = inputData.isTransfer
      ? inputData.spendingSecret
      : await deriveSharedSecret(inputData.spendingSecret, COMPLIANCE_PK);

    const changeValue = inputData.note.value.toBigInt() - amount;

    const memoNote: NotePlaintext = {
      asset_id: inputData.note.asset_id, value: toFr(amount),
      secret: toFr(0), nullifier: toFr(0), timelock: toFr(0), hashlock: toFr(0),
    };
    const memoEphSk = toFr(ethersLib.toBigInt(ethersLib.randomBytes(31)) % BJJ_SUBGROUP_ORDER);

    const changeNote: NotePlaintext = {
      asset_id: inputData.note.asset_id, value: toFr(changeValue),
      secret: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      nullifier: toFr(ethersLib.toBigInt(ethersLib.randomBytes(31))),
      timelock: toFr(0), hashlock: toFr(0),
    };
    const { sk: changeEphSk } = await this.keyRepo.nextEphemeralParams();

    const proof = await proveTransfer({
      merkleRoot: this.tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK,
      recipientB, recipientP, recipientProof,
      oldNote: inputData.note, oldSharedSecret: oldSecret,
      oldNoteIndex: inputData.leafIndex,
      oldNotePath: this.tree.getMerklePath(inputData.leafIndex),
      hashlockPreimage: toFr(0),
      memoNote, memoEphemeralSk: memoEphSk,
      changeNote, changeEphemeralSk: changeEphSk,
    });

    const actionCalldata = this.base.darkPool.interface.encodeFunctionData(
      "privateTransfer", [proof.proof, proof.publicInputs],
    );

    const { txHash } = await this.submitPaidAction(actionCalldata, [inputData.leafIndex]);

    const pub = proof.publicInputs.map((s) => toFr(s));
    const memoCommitment = await Poseidon.hash(pub.slice(11, 18));
    const changeCommitment = await Poseidon.hash(pub.slice(24, 31));
    return { memoCommitment, changeCommitment, txHash, publicInputs: proof.publicInputs };
  }
}
