import { beforeAll, describe, expect, it } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  addressToFr,
  derivePublicIncomingKey,
  publicKey,
  publicMemoId,
} from "@hisoka/wallets";
import { RpcChainReader } from "../chain/chainReader.js";
import { RpcLogSource } from "../chain/logs.js";
import { readPublicMemos } from "../history/publicMemos.js";
import { configFor, FakeChain } from "./fixtures/chain.js";

const VIEW_KEY = new Fr(0x5ca1ab1en);
const OTHER_VIEW_KEY = new Fr(0xdeadn);
const ASSET = "0x00000000000000000000000000000000000a55e7";
const DEPLOY = 2;

interface Posted {
  readonly memoId: Fr;
  readonly block: number;
}

async function post(
  chain: FakeChain,
  block: number,
  viewKey: Fr,
  index: bigint,
  terms: { value: bigint; timelock: bigint; salt: bigint },
): Promise<Posted> {
  const owner = publicKey(await derivePublicIncomingKey(viewKey, index));
  const memoId = await publicMemoId(
    {
      assetId: addressToFr(ASSET),
      value: terms.value,
      timelock: terms.timelock,
      salt: new Fr(terms.salt),
    },
    owner,
  );
  chain.emit(block, "NewPublicMemo", [
    memoId.toString(),
    ASSET,
    terms.value,
    terms.timelock,
    terms.salt,
  ]);
  return { memoId, block };
}

let chain: FakeChain;
let atIndex3: Posted;
let atIndex22: Posted;
let beyondGap: Posted;
let spentMemo: Posted;
let lockedMemo: Posted;
let freshMemo: Posted;

beforeAll(async () => {
  chain = new FakeChain(60, 1_000_000);
  const now = BigInt(chain.blocks[60]!.timestamp);
  atIndex3 = await post(chain, 10, VIEW_KEY, 3n, {
    value: 5n,
    timelock: 0n,
    salt: 1n,
  });
  atIndex22 = await post(chain, 11, VIEW_KEY, 22n, {
    value: 6n,
    timelock: now - 1n,
    salt: 2n,
  });
  beyondGap = await post(chain, 12, VIEW_KEY, 60n, {
    value: 7n,
    timelock: 0n,
    salt: 3n,
  });
  spentMemo = await post(chain, 13, VIEW_KEY, 0n, {
    value: 8n,
    timelock: 0n,
    salt: 4n,
  });
  lockedMemo = await post(chain, 14, VIEW_KEY, 1n, {
    value: 9n,
    timelock: now + 1n,
    salt: 5n,
  });
  freshMemo = await post(chain, 59, VIEW_KEY, 2n, {
    value: 10n,
    timelock: 0n,
    salt: 6n,
  });
  await post(chain, 15, OTHER_VIEW_KEY, 0n, {
    value: 11n,
    timelock: 0n,
    salt: 7n,
  });
  chain.emit(20, "PublicMemoSpent", [spentMemo.memoId.toString()]);
});

describe("public memos", () => {
  it("finds this wallet's memos over a gap-limited window with spent, matured and claimable from chain state", async () => {
    const config = configFor(DEPLOY, { kind: "depth", blocks: 3 });
    const read = await readPublicMemos(
      {
        config,
        chain: RpcChainReader.over(chain.rpc, config),
        logs: RpcLogSource.over(chain.rpc, config),
      },
      VIEW_KEY,
    );

    expect(read.head.number).toBe(60);
    expect(read.confirmedHead).toBe(57);
    const byId = new Map(read.memos.map((m) => [m.memoId.toString(), m]));
    expect(read.memos.map((m) => m.block.number)).toEqual([10, 11, 13, 14, 59]);
    expect(byId.has(beyondGap.memoId.toString())).toBe(false);

    const three = byId.get(atIndex3.memoId.toString())!;
    expect(three).toMatchObject({
      ownerIndex: 3n,
      value: 5n,
      spent: false,
      matured: true,
      claimable: true,
    });
    expect(three.assetId.equals(addressToFr(ASSET))).toBe(true);
    expect(byId.get(atIndex22.memoId.toString())).toMatchObject({
      ownerIndex: 22n,
      matured: true,
      claimable: true,
    });
    expect(byId.get(spentMemo.memoId.toString())).toMatchObject({
      spent: true,
      claimable: false,
    });
    expect(byId.get(lockedMemo.memoId.toString())).toMatchObject({
      matured: false,
      claimable: false,
    });
    expect(byId.get(freshMemo.memoId.toString())).toMatchObject({
      matured: true,
      claimable: false,
    });
  });

  it("drops a memo whose block was reorged away", async () => {
    const forked = new FakeChain(60, 1_000_000);
    await post(forked, 10, VIEW_KEY, 0n, { value: 5n, timelock: 0n, salt: 1n });
    await post(forked, 40, VIEW_KEY, 1n, { value: 6n, timelock: 0n, salt: 2n });
    const config = configFor(DEPLOY);
    const d = {
      config,
      chain: RpcChainReader.over(forked.rpc, config),
      logs: RpcLogSource.over(forked.rpc, config),
    };
    expect((await readPublicMemos(d, VIEW_KEY)).memos).toHaveLength(2);
    forked.reorgFrom(30);
    expect(
      (await readPublicMemos(d, VIEW_KEY)).memos.map((m) => m.block.number),
    ).toEqual([10]);
  });
});
