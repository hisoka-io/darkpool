import { ContractRunner, ethers } from "ethers";
import {
  DarkAccount,
  NotePlaintext,
  LeanIMT,
  toFr,
  encryptNoteDeposit,
  deriveSharedSecret,
  KeyRepository,
  UtxoRepository,
  ScanEngine,
  addressToFr,
  recipientDecrypt3Party,
  WalletNote,
  calculatePublicMemoId,
  deriveNullifierPathA,
  deriveNullifierPathB,
  Poseidon,
  Fr,
} from "@hisoka/wallets";
import {
  proveDeposit,
  proveTransfer,
  proveWithdraw,
  provePublicClaim,
  PublicClaimInputs,
  DepositInputs,
  TransferInputs,
  WithdrawInputs,
  unpackCiphertext,
} from "@hisoka/prover";
import { Base8, mulPointEscalar, Point } from "@zk-kit/baby-jubjub";
import { DarkPool, MockERC20 } from "../../typechain-types";

const COMPLIANCE_PK_POINT: Point<bigint> = mulPointEscalar(Base8, 987654321n);

export interface WithdrawOptions {
  asset?: string; // Address of token to withdraw (default: wallet's default token)
  recipient?: string; // Address to send funds to (default: wallet signer)
  intentHash?: Fr; // Intent hash for DeFi binding (default: 0)
}

export class TestWallet {
  public account!: DarkAccount;
  public keyRepo!: KeyRepository;
  public utxoRepo!: UtxoRepository;
  public scanEngine!: ScanEngine;
  public tree!: LeanIMT;
  public fromBlock: number = 0;

  private constructor(
    public readonly signer: ContractRunner & { address: string },
    public readonly darkPool: DarkPool,
    public readonly token: MockERC20, // Default token
  ) {}

  static async create(
    signer: any,
    darkPool: DarkPool,
    token: MockERC20,
    fromBlock?: number,
  ) {
    const wallet = new TestWallet(signer, darkPool, token);
    const signature = await signer.signMessage("Hisoka Test Login");
    wallet.account = await DarkAccount.fromSignature(signature);

    wallet.tree = new LeanIMT(32);
    wallet.keyRepo = new KeyRepository(wallet.account, COMPLIANCE_PK_POINT);
    wallet.utxoRepo = new UtxoRepository();

    // Store the block from which to scan (important for mainnet forks)
    wallet.fromBlock = fromBlock ?? 0;

    wallet.scanEngine = new ScanEngine(
      darkPool as unknown as ethers.Contract,
      wallet.keyRepo,
      wallet.utxoRepo,
      COMPLIANCE_PK_POINT,
      wallet.tree,
    );

    return wallet;
  }

  // --- HELPERS ---
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
    const safeAsset = asset || undefined;
    return this.utxoRepo.getBalance(
      safeAsset ? addressToFr(safeAsset).toString() : undefined,
    );
  }

  // --- ACTIONS ---

  async deposit(amount: bigint, asset?: string) {
    const { sk: ephemeralSk, nonce } = await this.keyRepo.nextEphemeralParams();
    const skView = await this.account.getViewKey();

    // Use provided asset or default
    const tokenAddress = asset || (await this.token.getAddress());
    const assetFr = addressToFr(tokenAddress);

    const note: NotePlaintext = {
      value: toFr(amount),
      asset_id: assetFr,
      secret: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      nullifier: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };

    await encryptNoteDeposit(skView, nonce, note, COMPLIANCE_PK_POINT);
    const inputs: DepositInputs = {
      notePlaintext: note,
      ephemeralSk,
      compliancePk: COMPLIANCE_PK_POINT,
    };

    const proof = await proveDeposit(inputs);

    // We need to get the contract instance for the specific token if it's not the default one
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

    const pub = proof.publicInputs.map((s) => toFr(s));
    const packedCt = pub.slice(6, 13);
    const commitment = await Poseidon.hash(packedCt);

    return { commitment, receipt };
  }

  async transfer(
    amount: bigint,
    recipientB: Point<bigint>,
    recipientP: Point<bigint>,
    recipientProof: any,
    asset?: string,
  ) {
    const targetAssetFr = asset
      ? addressToFr(asset)
      : addressToFr(await this.token.getAddress());

    const notes = this.utxoRepo.getUnspentNotes();
    const assetNotes = notes.filter((n) =>
      n.note.asset_id.equals(targetAssetFr),
    );

    const inputData = assetNotes.find((n) => n.note.value.toBigInt() >= amount);
    if (!inputData)
      throw new Error(
        `Insufficient funds: Needed ${amount}, have notes: ${assetNotes.map((n) => n.note.value.toBigInt())}`,
      );

    const oldSharedSecret = inputData.isTransfer
      ? inputData.spendingSecret
      : await deriveSharedSecret(inputData.spendingSecret, COMPLIANCE_PK_POINT);

    const path = this.tree.getMerklePath(inputData.leafIndex);
    const root = this.tree.getRoot();
    const changeValue = inputData.note.value.toBigInt() - amount;

    const memoNote: NotePlaintext = {
      asset_id: inputData.note.asset_id,
      value: toFr(amount),
      secret: toFr(0),
      nullifier: toFr(0),
      timelock: toFr(0),
      hashlock: toFr(0),
    };
    // BJJ subgroup order - ephemeral keys must be reduced to this range
    const BJJ_SUBGROUP_ORDER =
      2736030358979909402780800718157159386076813972158567259200215660948447373041n;
    const memoEphSk = toFr(
      ethers.toBigInt(ethers.randomBytes(31)) % BJJ_SUBGROUP_ORDER,
    );

    const changeNote: NotePlaintext = {
      asset_id: inputData.note.asset_id,
      value: toFr(changeValue),
      secret: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      nullifier: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      timelock: toFr(0),
      hashlock: toFr(0),
    };
    const { sk: changeEphSk } = await this.keyRepo.nextEphemeralParams();

    const inputs: TransferInputs = {
      merkleRoot: root,
      currentTimestamp: Math.floor(Date.now() / 1000),
      compliancePk: COMPLIANCE_PK_POINT,
      recipientB,
      recipientP,
      recipientProof,
      oldNote: inputData.note,
      oldSharedSecret,
      oldNoteIndex: inputData.leafIndex,
      oldNotePath: path,
      hashlockPreimage: toFr(0),
      memoNote,
      memoEphemeralSk: memoEphSk,
      changeNote,
      changeEphemeralSk: changeEphSk,
    };

    const proof = await proveTransfer(inputs);
    const tx = await this.darkPool
      .connect(this.signer)
      .privateTransfer(proof.proof, proof.publicInputs);
    await tx.wait();

    const pub = proof.publicInputs.map((s) => toFr(s));
    const memoCom = await Poseidon.hash(pub.slice(11, 18));
    const changeCom = await Poseidon.hash(pub.slice(24, 31));

    return {
      memoCommitment: memoCom,
      changeCommitment: changeCom,
      publicInputs: proof.publicInputs,
    };
  }

  async receiveTransfer(
    publicInputs: string[],
    leafIndex: number,
    recipientSk: bigint,
  ) {
    const frInputs = publicInputs.map((s) => toFr(s));
    const packedCt = frInputs.slice(11, 18);
    const intBobX = frInputs[18];
    const intBobY = frInputs[19];

    const ct = unpackCiphertext(packedCt);
    const intBobPoint: Point<bigint> = [intBobX.toBigInt(), intBobY.toBigInt()];
    const { note, sharedSecret } = await recipientDecrypt3Party(
      recipientSk,
      intBobPoint,
      ct,
    );
    const commitment = await Poseidon.hash(packedCt);

    await this.utxoRepo.addNote({
      note,
      commitment,
      leafIndex,
      nullifier: await deriveNullifierPathB(
        sharedSecret,
        commitment,
        leafIndex,
      ),
      spendingSecret: sharedSecret,
      isTransfer: true,
      derivationIndex: 0,
      spent: false,
    });
  }

  /**
   * Withdraw funds. If intentHash is set (DeFi), the proof is returned
   * without submitting the TX (caller must submit to Adaptor).
   */
  async withdraw(amount: bigint, options: WithdrawOptions = {}) {
    const targetAsset = options.asset || (await this.token.getAddress());
    const targetRecipient = options.recipient || this.signer.address;
    const intentHash = options.intentHash || toFr(0);

    const targetAssetFr = addressToFr(targetAsset);

    // 1. Select Note
    const notes = this.utxoRepo.getUnspentNotes();
    const assetNotes = notes.filter((n) =>
      n.note.asset_id.equals(targetAssetFr),
    );

    const inputData = assetNotes.find((n) => n.note.value.toBigInt() >= amount);
    if (!inputData)
      throw new Error(
        `Insufficient funds for withdraw: Needed ${amount}, found ${assetNotes.length} notes`,
      );

    const oldSharedSecret = inputData.isTransfer
      ? inputData.spendingSecret
      : await deriveSharedSecret(inputData.spendingSecret, COMPLIANCE_PK_POINT);

    const changeValue = inputData.note.value.toBigInt() - amount;

    const changeNote: NotePlaintext = {
      ...inputData.note,
      value: toFr(changeValue),
      secret: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      nullifier: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      timelock: toFr(0),
      hashlock: toFr(0),
    };

    // Use deterministic key for recovery
    const { sk: changeEphSk } = await this.keyRepo.nextEphemeralParams();

    const inputs: WithdrawInputs = {
      withdrawValue: toFr(amount),
      recipient: addressToFr(targetRecipient),
      merkleRoot: this.tree.getRoot(),
      currentTimestamp: Math.floor(Date.now() / 1000),
      intentHash: intentHash,
      compliancePk: COMPLIANCE_PK_POINT,
      oldNote: inputData.note,
      oldSharedSecret,
      oldNoteIndex: inputData.leafIndex,
      oldNotePath: this.tree.getMerklePath(inputData.leafIndex),
      hashlockPreimage: toFr(0),
      changeNote,
      changeEphemeralSk: changeEphSk,
    };

    const proof = await proveWithdraw(inputs);

    // If this is a DeFi intent (Hash != 0), we return the proof for the caller to use.
    // If standard withdraw, we execute it directly on DarkPool.
    if (!intentHash.isZero()) {
      return proof;
    }

    await this.darkPool
      .connect(this.signer)
      .withdraw(proof.proof, proof.publicInputs);
    return proof; // Return proof anyway
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
    const valFr = toFr(args.value);
    const assetFr = addressToFr(args.asset);
    const timeFr = toFr(args.timelock);
    const ownerXFr = toFr(args.ownerX);
    const ownerYFr = toFr(args.ownerY);
    const saltFr = toFr(args.salt);
    const memoIdFr = toFr(args.memoId);

    const calcId = await calculatePublicMemoId(
      valFr,
      assetFr,
      timeFr,
      ownerXFr,
      ownerYFr,
      saltFr,
    );
    if (!calcId.equals(memoIdFr)) throw new Error("Local Memo ID mismatch");

    const noteOut: NotePlaintext = {
      value: valFr,
      asset_id: assetFr,
      secret: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      nullifier: toFr(ethers.toBigInt(ethers.randomBytes(31))),
      timelock: toFr(0),
      hashlock: toFr(0),
    };

    const { sk: skOut, nonce } = await this.keyRepo.nextEphemeralParams();

    const inputs: PublicClaimInputs = {
      memoId: memoIdFr,
      compliancePk: COMPLIANCE_PK_POINT,
      currentTimestamp: Math.floor(Date.now() / 1000),
      val: valFr,
      assetId: assetFr,
      timelock: timeFr,
      ownerX: ownerXFr,
      ownerY: ownerYFr,
      salt: saltFr,
      recipientSk,
      noteOut,
      skOut,
    };

    const proof = await provePublicClaim(inputs);
    await this.darkPool
      .connect(this.signer)
      .publicClaim(proof.proof, proof.publicInputs);

    const pub = proof.publicInputs.map((s) => toFr(s));
    const packedCt = pub.slice(6, 13);
    const commitment = await Poseidon.hash(packedCt);
    const nullifierHash = await deriveNullifierPathA(noteOut.nullifier);

    const walletNote: WalletNote = {
      note: noteOut,
      leafIndex: this.tree.nextLeafIndex,
      commitment,
      nullifier: nullifierHash,
      spendingSecret: skOut,
      isTransfer: false,
      derivationIndex: Number(nonce.toBigInt()),
      spent: false,
    };

    await this.utxoRepo.addNote(walletNote);
    await this.tree.insert(commitment);

    return { commitment };
  }
}
