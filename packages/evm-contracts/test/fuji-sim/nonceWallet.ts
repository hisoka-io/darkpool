import { ethers } from "ethers";
import { withRetry } from "./poolLogs";

/**
 * A wallet that counts its own nonces: it reads the chain's count once, then advances it for every transaction the
 * endpoint accepts. Each wallet sends from this one process, one transaction at a time, so the local count is exact,
 * while a node's reported count can lag a mined transaction (an anvil fork does; so can a load-balanced endpoint).
 * A refusal for a stale nonce drops the local count, so the next send reads the chain again.
 */
export class CountingNonceWallet extends ethers.Wallet {
  #next: number | null = null;

  override async getNonce(): Promise<number> {
    if (this.#next === null)
      this.#next = await withRetry("nonce", () =>
        this.provider!.getTransactionCount(this.address, "latest"),
      );
    return this.#next;
  }

  override async sendTransaction(
    tx: ethers.TransactionRequest,
  ): Promise<ethers.TransactionResponse> {
    const nonce = await this.getNonce();
    try {
      const sent = await super.sendTransaction({ ...tx, nonce });
      this.#next = nonce + 1;
      return sent;
    } catch (e: unknown) {
      if (ethers.isError(e, "NONCE_EXPIRED")) this.#next = null;
      throw e;
    }
  }
}
