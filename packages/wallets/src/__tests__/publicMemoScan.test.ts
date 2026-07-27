import { describe, it, expect, beforeAll, vi, afterEach } from "vitest";
import { Contract } from "ethers";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { DarkAccount } from "../keys/DarkAccount";
import {
  canonicalPublicAddress,
  deriveIncomingKey,
  publicKey,
} from "../note/keys";
import { addressToFr } from "../crypto/fields";
import { calculatePublicMemoId } from "../crypto/index";
import {
  PublicMemoScanner,
  PublicMemoScanError,
} from "../sync/PublicMemoScanner";

const MNEMONIC = "test test test test test test test test test test test junk";
const OTHER_MNEMONIC =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";
const ASSET = "0x1234567890123456789012345678901234567890";
const NOW = 1_800_000_000n;

interface MemoLogSpec {
  memoId: string;
  asset: string;
  value: bigint;
  timelock: bigint;
  salt: bigint;
  block: number;
  index: number;
}

interface RawLogSpec {
  block: number;
  index: number;
}

const frHex = (f: Fr): string => "0x" + f.toBuffer().toString("hex");

async function memoLog(
  ownerPub: Point<bigint>,
  fields: {
    value: bigint;
    timelock?: bigint;
    salt?: bigint;
    asset?: string;
    block?: number;
    index?: number;
  },
): Promise<MemoLogSpec> {
  const asset = fields.asset ?? ASSET;
  const timelock = fields.timelock ?? 0n;
  const salt = fields.salt ?? 12345n;
  const memoId = await calculatePublicMemoId(
    new Fr(fields.value),
    addressToFr(asset),
    new Fr(timelock),
    new Fr(ownerPub[0]),
    new Fr(ownerPub[1]),
    new Fr(salt),
  );
  return {
    memoId: frHex(memoId),
    asset,
    value: fields.value,
    timelock,
    salt,
    block: fields.block ?? 10,
    index: fields.index ?? 0,
  };
}

function fakeContract(
  memos: MemoLogSpec[],
  spentIds: string[] = [],
  extra: {
    rawLogs?: RawLogSpec[];
    timestamp?: bigint;
    noProvider?: boolean;
  } = {},
): Contract {
  const memoLogs: unknown[] = memos.map((m) => ({
    blockNumber: m.block,
    index: m.index,
    transactionHash: "0xmemo",
    fragment: { name: "NewPublicMemo" },
    args: {
      memoId: m.memoId,
      asset: m.asset,
      value: m.value,
      timelock: m.timelock,
      salt: m.salt,
    },
  }));
  for (const raw of extra.rawLogs ?? []) {
    memoLogs.push({
      blockNumber: raw.block,
      index: raw.index,
      transactionHash: "0xraw",
    });
  }

  const spentLogs = spentIds.map((id, i) => ({
    blockNumber: 20,
    index: i,
    transactionHash: "0xspend",
    fragment: { name: "PublicMemoSpent" },
    args: { memoId: id },
  }));

  return {
    runner: extra.noProvider
      ? {}
      : {
          provider: {
            getBlock: async () => ({
              timestamp: Number(extra.timestamp ?? NOW),
            }),
          },
        },
    filters: {
      NewPublicMemo: () => "NewPublicMemo",
      PublicMemoSpent: () => "PublicMemoSpent",
    },
    queryFilter: async (filter: string) =>
      filter === "NewPublicMemo" ? memoLogs : spentLogs,
  } as unknown as Contract;
}

describe("public memo discovery", () => {
  let viewKey: Fr;
  let otherViewKey: Fr;

  beforeAll(async () => {
    viewKey = await (await DarkAccount.fromMnemonic(MNEMONIC)).getViewKey();
    otherViewKey = await (
      await DarkAccount.fromMnemonic(OTHER_MNEMONIC)
    ).getViewKey();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("recognises a memo addressed to this wallet and returns the claim witness", async () => {
    const mine = await canonicalPublicAddress(viewKey, 3n);
    const log = await memoLog(mine.pub, { value: 500n, salt: 77n });
    const scanner = new PublicMemoScanner(fakeContract([log]), viewKey);

    const found = await scanner.scan(0);

    expect(found).toHaveLength(1);
    const memo = found[0];
    expect(memo.ownerIndex).toBe(3n);
    expect(memo.ownerPub[0]).toBe(mine.pub[0]);
    expect(memo.ownerPub[1]).toBe(mine.pub[1]);
    expect(publicKey(memo.recipientSk)[0]).toBe(mine.pub[0]);
    expect(memo.value).toBe(500n);
    expect(memo.assetId.equals(addressToFr(ASSET))).toBe(true);
    expect(memo.salt.toBigInt()).toBe(77n);
    expect(memo.claimable).toBe(true);
    expect(memo.spent).toBe(false);
    expect(memo.blockNumber).toBe(10);
    expect(memo.txHash).toBe("0xmemo");
  });

  it("re-derives the emitted memo id from the recovered witness", async () => {
    const mine = await canonicalPublicAddress(viewKey, 1n);
    const log = await memoLog(mine.pub, { value: 42n, timelock: 999n });
    const scanner = new PublicMemoScanner(fakeContract([log]), viewKey);

    const memo = (await scanner.scan(0, 1000n))[0];
    const rebuilt = await calculatePublicMemoId(
      new Fr(memo.value),
      memo.assetId,
      new Fr(memo.timelock),
      new Fr(memo.ownerPub[0]),
      new Fr(memo.ownerPub[1]),
      memo.salt,
    );
    expect(frHex(rebuilt)).toBe(log.memoId);
  });

  it("ignores a memo addressed to another wallet", async () => {
    const theirs = await canonicalPublicAddress(otherViewKey, 0n);
    const log = await memoLog(theirs.pub, { value: 100n });
    const scanner = new PublicMemoScanner(fakeContract([log]), viewKey);

    expect(await scanner.scan(0)).toHaveLength(0);
  });

  it("ignores a memo addressed to this wallet's private incoming family", async () => {
    const privatePub = publicKey(await deriveIncomingKey(viewKey, 0n));
    const log = await memoLog(privatePub, { value: 100n });
    const scanner = new PublicMemoScanner(fakeContract([log]), viewKey);

    expect(await scanner.scan(0)).toHaveLength(0);
  });

  it("reports an already-claimed memo as spent and not claimable", async () => {
    const mine = await canonicalPublicAddress(viewKey, 0n);
    const log = await memoLog(mine.pub, { value: 100n });
    const scanner = new PublicMemoScanner(
      fakeContract([log], [log.memoId]),
      viewKey,
    );

    const memo = (await scanner.scan(0))[0];
    expect(memo.spent).toBe(true);
    expect(memo.matured).toBe(true);
    expect(memo.claimable).toBe(false);
  });

  it("reports an immature timelock as not claimable until it matures", async () => {
    const mine = await canonicalPublicAddress(viewKey, 0n);
    const log = await memoLog(mine.pub, { value: 100n, timelock: NOW + 60n });
    const scanner = new PublicMemoScanner(fakeContract([log]), viewKey);

    const early = (await scanner.scan(0))[0];
    expect(early.timelock).toBe(NOW + 60n);
    expect(early.matured).toBe(false);
    expect(early.claimable).toBe(false);

    const late = (await scanner.scan(0, NOW + 60n))[0];
    expect(late.matured).toBe(true);
    expect(late.claimable).toBe(true);
  });

  it("defaults the maturity clock to the latest block timestamp", async () => {
    const mine = await canonicalPublicAddress(viewKey, 0n);
    const log = await memoLog(mine.pub, { value: 100n, timelock: NOW });
    const scanner = new PublicMemoScanner(
      fakeContract([log], [], { timestamp: NOW - 1n }),
      viewKey,
    );

    expect((await scanner.scan(0))[0].matured).toBe(false);
  });

  it("skips a malformed event and still returns the sound ones", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const mine = await canonicalPublicAddress(viewKey, 0n);
    const good = await memoLog(mine.pub, { value: 100n, index: 3 });
    const badAsset = { ...good, asset: "0xnotanaddress", index: 1 };
    const badValue = { ...good, value: 0n, index: 2 };
    const overflowValue = { ...good, value: 1n << 128n, index: 4 };
    const overflowTimelock = { ...good, timelock: 1n << 64n, index: 5 };

    const scanner = new PublicMemoScanner(
      fakeContract(
        [badAsset, badValue, good, overflowValue, overflowTimelock],
        [],
        { rawLogs: [{ block: 9, index: 0 }] },
      ),
      viewKey,
    );

    const found = await scanner.scan(0);
    expect(found).toHaveLength(1);
    expect(found[0].value).toBe(100n);
    expect(warn).toHaveBeenCalled();
  });

  it("skips a malformed spend event without losing the memo", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const mine = await canonicalPublicAddress(viewKey, 0n);
    const log = await memoLog(mine.pub, { value: 100n });
    const scanner = new PublicMemoScanner(
      fakeContract([log], ["not-a-field-element"]),
      viewKey,
    );

    const memo = (await scanner.scan(0))[0];
    expect(memo.spent).toBe(false);
    expect(warn).toHaveBeenCalled();
  });

  it("extends the index window past a frontier match", async () => {
    const near = await canonicalPublicAddress(viewKey, 5n);
    const beyondWindow = await canonicalPublicAddress(viewKey, 24n);
    const first = await memoLog(near.pub, { value: 1n, index: 0 });
    const second = await memoLog(beyondWindow.pub, { value: 2n, index: 1 });

    const found = await new PublicMemoScanner(
      fakeContract([first, second]),
      viewKey,
    ).scan(0);

    expect(found.map((m) => m.ownerIndex)).toEqual([5n, 24n]);
  });

  it("leaves an index beyond the gap limit undiscovered", async () => {
    const unreachable = await canonicalPublicAddress(viewKey, 25n);
    const log = await memoLog(unreachable.pub, { value: 100n });

    expect(
      await new PublicMemoScanner(fakeContract([log]), viewKey).scan(0),
    ).toHaveLength(0);
    expect(
      await new PublicMemoScanner(fakeContract([log]), viewKey, 30).scan(0),
    ).toHaveLength(1);
  });

  it("returns memos in chain order", async () => {
    const a = await canonicalPublicAddress(viewKey, 0n);
    const b = await canonicalPublicAddress(viewKey, 1n);
    const first = await memoLog(a.pub, { value: 1n, block: 5, index: 2 });
    const second = await memoLog(b.pub, { value: 2n, block: 5, index: 7 });
    const third = await memoLog(a.pub, { value: 3n, block: 8, index: 0 });

    const scanner = new PublicMemoScanner(
      fakeContract([third, second, first]),
      viewKey,
    );

    const found = await scanner.scan(0);
    expect(found.map((m) => m.value)).toEqual([1n, 2n, 3n]);
  });

  it("rejects a non-positive index window", () => {
    expect(
      () => new PublicMemoScanner(fakeContract([]), new Fr(1n), 0),
    ).toThrow(PublicMemoScanError);
  });

  it("names the missing event when the ABI has none", async () => {
    const contract = { filters: {}, runner: {} } as unknown as Contract;
    await expect(
      new PublicMemoScanner(contract, viewKey).scan(0),
    ).rejects.toThrow(/NewPublicMemo/);
  });

  it("says how to fix a missing provider instead of guessing the clock", async () => {
    const mine = await canonicalPublicAddress(viewKey, 0n);
    const log = await memoLog(mine.pub, { value: 100n });
    const scanner = new PublicMemoScanner(
      fakeContract([log], [], { noProvider: true }),
      viewKey,
    );

    await expect(scanner.scan(0)).rejects.toThrow(/pass nowSeconds/);
  });
});
