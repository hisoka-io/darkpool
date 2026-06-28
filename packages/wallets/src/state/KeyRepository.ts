import { Fr } from "@aztec/foundation/fields";
import { Point, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { DarkAccount } from "../keys/DarkAccount.js";
import { toFr } from "../crypto/fields.js";
import { BJJ_SUBGROUP_ORDER } from "../crypto/constants.js";
import { IKeyRepository, KeyRepoState } from "../repositories.js";

const DEFAULT_LOOKAHEAD_WINDOW = 20;

export class KeyRepository implements IKeyRepository {
  private _ephemeralIndex: number = 0;
  private _incomingIndex: number = 0;
  private _nextEphemeralNonce: number = 0;
  private _highestMatchedEphemeral: number = -1;
  private _highestMatchedIncoming: number = -1;

  private ephemeralKeyMap: Map<string, { key: Fr; index: number }> = new Map();
  private recipientKeyMap: Map<string, { key: bigint; index: number }> =
    new Map();

  constructor(
    private readonly account: DarkAccount,
    private readonly compliancePk: Point<bigint>,
  ) {}

  public get ephemeralIndex(): number {
    return this._ephemeralIndex;
  }
  public get incomingIndex(): number {
    return this._incomingIndex;
  }

  public async nextEphemeralParams(): Promise<{ sk: Fr; nonce: Fr }> {
    const idx = this._nextEphemeralNonce++;
    const nonce = toFr(idx);
    const sk = await this.account.getEphemeralOutgoingKey(BigInt(idx));
    const skMod = toFr(sk.toBigInt() % BJJ_SUBGROUP_ORDER);
    await this.registerEphemeralKey(idx);
    return { sk: skMod, nonce };
  }

  public async advanceEphemeralKeys(count: number = 1): Promise<void> {
    for (let i = 0; i < count; i++) {
      await this.registerEphemeralKey(this._ephemeralIndex++);
    }
  }

  public async advanceIncomingKeys(count: number = 1): Promise<void> {
    for (let i = 0; i < count; i++) {
      await this.registerIncomingKey(this._incomingIndex++);
    }
  }

  public async ensureEphemeralLookahead(window: number): Promise<boolean> {
    const target = Math.max(
      this._ephemeralIndex,
      this._highestMatchedEphemeral + 1 + window,
    );
    let advanced = false;
    while (this._ephemeralIndex < target) {
      await this.registerEphemeralKey(this._ephemeralIndex++);
      advanced = true;
    }
    return advanced;
  }

  public async ensureIncomingLookahead(window: number): Promise<boolean> {
    const target = Math.max(
      this._incomingIndex,
      this._highestMatchedIncoming + 1 + window,
    );
    let advanced = false;
    while (this._incomingIndex < target) {
      await this.registerIncomingKey(this._incomingIndex++);
      advanced = true;
    }
    return advanced;
  }

  private async registerEphemeralKey(index: number): Promise<void> {
    const idxBi = BigInt(index);
    const ephPk = await this.account.getPublicEphemeralOutgoingKey(idxBi);
    const lookupKey = this.formatPointKey(ephPk);

    if (!this.ephemeralKeyMap.has(lookupKey)) {
      const ephSk = await this.account.getEphemeralOutgoingKey(idxBi);
      const ephSkMod = toFr(ephSk.toBigInt() % BJJ_SUBGROUP_ORDER);
      this.ephemeralKeyMap.set(lookupKey, { key: ephSkMod, index });
    }
  }

  private async registerIncomingKey(index: number): Promise<void> {
    const idxBi = BigInt(index);
    const recipientSk = await this.account.getIncomingViewingKey(idxBi);
    const recipientSkMod = recipientSk.toBigInt() % BJJ_SUBGROUP_ORDER;
    const P = mulPointEscalar(this.compliancePk, recipientSkMod);
    const tagKey = toFr(P[0]).toString();

    if (!this.recipientKeyMap.has(tagKey)) {
      this.recipientKeyMap.set(tagKey, { key: recipientSkMod, index });
    }
  }

  public tryMatchDeposit(
    epkX: bigint | string,
    epkY: bigint | string,
  ): { key: Fr; index: number } | null {
    const key = this.formatPointKey([BigInt(epkX), BigInt(epkY)]);
    const match = this.ephemeralKeyMap.get(key) || null;
    if (match && match.index > this._highestMatchedEphemeral) {
      this._highestMatchedEphemeral = match.index;
    }
    return match;
  }

  public tryMatchTransfer(
    tagPx: bigint | string,
  ): { key: bigint; index: number } | null {
    const key = toFr(tagPx).toString();
    const match = this.recipientKeyMap.get(key) || null;
    if (match && match.index > this._highestMatchedIncoming) {
      this._highestMatchedIncoming = match.index;
    }
    return match;
  }

  public getAllTags(): string[] {
    return Array.from(this.recipientKeyMap.keys());
  }

  public getState(): KeyRepoState {
    return {
      nextEphemeralNonce: this._nextEphemeralNonce,
      ephemeralIndex: this._ephemeralIndex,
      incomingIndex: this._incomingIndex,
      highestMatchedEphemeral: this._highestMatchedEphemeral,
      highestMatchedIncoming: this._highestMatchedIncoming,
    };
  }

  public async restore(state: KeyRepoState): Promise<void> {
    this._nextEphemeralNonce = Math.max(
      this._nextEphemeralNonce,
      state.nextEphemeralNonce,
    );
    this._highestMatchedEphemeral = Math.max(
      this._highestMatchedEphemeral,
      state.highestMatchedEphemeral,
    );
    this._highestMatchedIncoming = Math.max(
      this._highestMatchedIncoming,
      state.highestMatchedIncoming,
    );
    const ephTarget = Math.max(state.ephemeralIndex, this._nextEphemeralNonce);
    while (this._ephemeralIndex < ephTarget) {
      await this.registerEphemeralKey(this._ephemeralIndex++);
    }
    while (this._incomingIndex < state.incomingIndex) {
      await this.registerIncomingKey(this._incomingIndex++);
    }

    await this.ensureEphemeralLookahead(DEFAULT_LOOKAHEAD_WINDOW);
    await this.ensureIncomingLookahead(DEFAULT_LOOKAHEAD_WINDOW);
  }

  private formatPointKey(p: Point<bigint>): string {
    const x = toFr(p[0]).toString();
    const y = toFr(p[1]).toString();
    return `${x}_${y}`;
  }
}
