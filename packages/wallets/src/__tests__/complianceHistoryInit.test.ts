/**
 * `vectors/darkpool-compliance-receipts.json` holds the raw receipts of a local Hardhat deployment of DarkPool
 * through `deployDarkPoolFixture` followed by two `rotateComplianceKey` calls: the proxy deployment receipt,
 * whose logs include the `ComplianceKeyRotated(0, 1, x, y)` that `initialize` emits, and one receipt per
 * rotation. The tests decode them exactly as a log reader would.
 */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AbiCoder, id } from "ethers";
import type { Point } from "@zk-kit/baby-jubjub";
import {
  ComplianceKeyError,
  ComplianceKeyRing,
  completeComplianceHistory,
  type ComplianceKeyRotation,
} from "../index.js";

interface RawLog {
  readonly address: string;
  readonly topics: readonly string[];
  readonly data: string;
}
interface RawReceipt {
  readonly blockNumber: number;
  readonly status: number;
  readonly logs: readonly RawLog[];
}
interface Capture {
  readonly pool: string;
  readonly genesisKey: readonly [string, string];
  readonly deployReceipt: RawReceipt;
  readonly rotationReceipts: readonly RawReceipt[];
  readonly complianceKey: { x: string; y: string; version: number };
}

const capture = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "vectors/darkpool-compliance-receipts.json",
    ),
    "utf8",
  ),
) as Capture;

const ROTATED_TOPIC = id(
  "ComplianceKeyRotated(uint256,uint256,uint256,uint256)",
);

function rotationsIn(receipt: RawReceipt): ComplianceKeyRotation[] {
  expect(receipt.status).toBe(1);
  return receipt.logs
    .filter(
      (log) =>
        log.address.toLowerCase() === capture.pool.toLowerCase() &&
        log.topics[0] === ROTATED_TOPIC,
    )
    .map((log) => {
      const [oldVersion, newVersion, newX, newY] =
        AbiCoder.defaultAbiCoder().decode(
          ["uint256", "uint256", "uint256", "uint256"],
          log.data,
        ) as unknown as [bigint, bigint, bigint, bigint];
      return {
        oldVersion: Number(oldVersion),
        newVersion: Number(newVersion),
        newX,
        newY,
        blockNumber: receipt.blockNumber,
      };
    });
}

const GENESIS: Point<bigint> = [
  BigInt(capture.genesisKey[0]),
  BigInt(capture.genesisKey[1]),
];
const CURRENT: Point<bigint> = [
  BigInt(capture.complianceKey.x),
  BigInt(capture.complianceKey.y),
];
const DEPLOY_BLOCK = capture.deployReceipt.blockNumber;
const LOG = [
  ...rotationsIn(capture.deployReceipt),
  ...capture.rotationReceipts.flatMap(rotationsIn),
];

function reasonOf(build: () => unknown): string | undefined {
  try {
    build();
  } catch (error) {
    if (error instanceof ComplianceKeyError) return error.reason;
    throw error;
  }
  return undefined;
}

describe("compliance history from a real deployment's ComplianceKeyRotated log", () => {
  it("the deployment receipt carries the initialization event with the genesis key", () => {
    const init = rotationsIn(capture.deployReceipt);
    expect(init).toHaveLength(1);
    expect(init[0]).toMatchObject({
      oldVersion: 0,
      newVersion: 1,
      newX: GENESIS[0],
      newY: GENESIS[1],
    });
    expect(LOG.map((r) => [r.oldVersion, r.newVersion])).toEqual([
      [0, 1],
      [1, 2],
      [2, 3],
    ]);
  });

  it("completeComplianceHistory accepts the full log and dates the genesis epoch at deployment", () => {
    const history = completeComplianceHistory({
      genesisPk: GENESIS,
      rotations: LOG,
      currentPk: CURRENT,
      currentVersion: capture.complianceKey.version,
    });
    expect(history.currentVersion).toBe(3);
    expect(
      history.ring.epochs.map((e) => [e.version, e.fromBlock, e.pk]),
    ).toEqual([
      [1, DEPLOY_BLOCK, GENESIS],
      [2, capture.rotationReceipts[0].blockNumber, [LOG[1].newX, LOG[1].newY]],
      [3, capture.rotationReceipts[1].blockNumber, CURRENT],
    ]);
    expect(history.ring.candidatesFor(DEPLOY_BLOCK)[0].version).toBe(1);
  });

  it("ComplianceKeyRing.fromRotations accepts the full log and agrees with the history", () => {
    const ring = ComplianceKeyRing.fromRotations(GENESIS, LOG);
    const history = completeComplianceHistory({
      genesisPk: GENESIS,
      rotations: LOG,
      currentPk: CURRENT,
      currentVersion: 3,
    });
    expect(ring.epochs).toEqual(history.ring.epochs);
    expect(
      ComplianceKeyRing.fromRotations(GENESIS, LOG, DEPLOY_BLOCK).epochs,
    ).toEqual(ring.epochs);
  });

  it("still accepts the log without the initialization event", () => {
    const rotationsOnly = LOG.slice(1);
    const history = completeComplianceHistory({
      genesisPk: GENESIS,
      rotations: rotationsOnly,
      currentPk: CURRENT,
      currentVersion: 3,
    });
    expect(history.ring.epochs.map((e) => e.version)).toEqual([1, 2, 3]);
    expect(history.ring.epochs[0].fromBlock).toBeUndefined();
    expect(
      ComplianceKeyRing.fromRotations(GENESIS, rotationsOnly).epochs.map(
        (e) => e.version,
      ),
    ).toEqual([1, 2, 3]);
  });

  describe("rejects every other version-0 event", () => {
    const [init, ...rest] = LOG;
    const cases: readonly [string, ComplianceKeyRotation[]][] = [
      [
        "an initialization event for a different key",
        [{ ...init, newX: CURRENT[0], newY: CURRENT[1] }, ...rest],
      ],
      [
        "an initialization event to version 2",
        [{ ...init, newVersion: 2 }, ...rest],
      ],
      ["an initialization event after a rotation", [rest[0], init, rest[1]]],
      ["a repeated initialization event", [init, init, ...rest]],
    ];

    it.each(cases)(
      "%s",
      (_label: string, rotations: ComplianceKeyRotation[]) => {
        expect(
          reasonOf(() =>
            completeComplianceHistory({
              genesisPk: GENESIS,
              rotations,
              currentPk: CURRENT,
              currentVersion: 3,
            }),
          ),
        ).toBe("INVALID_VERSION_SEQUENCE");
        expect(
          reasonOf(() => ComplianceKeyRing.fromRotations(GENESIS, rotations)),
        ).toBe("INVALID_VERSION_SEQUENCE");
      },
    );

    it("an initialization event at a block other than the given genesis block", () => {
      expect(
        reasonOf(() =>
          ComplianceKeyRing.fromRotations(GENESIS, LOG, DEPLOY_BLOCK + 1),
        ),
      ).toBe("INVALID_VERSION_SEQUENCE");
    });

    it.each([-1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1])(
      "an initialization event at block %s, which is not a block number",
      (blockNumber: number) => {
        const rotations = [{ ...init, blockNumber }, ...rest];
        expect(
          reasonOf(() => ComplianceKeyRing.fromRotations(GENESIS, rotations)),
        ).toBe("INVALID_VERSION_SEQUENCE");
        expect(() =>
          ComplianceKeyRing.fromRotations(GENESIS, rotations),
        ).toThrow(/initialization block .* is not a block number/);
        expect(
          reasonOf(() =>
            completeComplianceHistory({
              genesisPk: GENESIS,
              rotations,
              currentPk: CURRENT,
              currentVersion: 3,
            }),
          ),
        ).toBe("INVALID_VERSION_SEQUENCE");
      },
    );

    it("an initialization event dated after the first rotation", () => {
      expect(
        reasonOf(() =>
          completeComplianceHistory({
            genesisPk: GENESIS,
            rotations: [
              { ...init, blockNumber: rest[0].blockNumber! + 1 },
              ...rest,
            ],
            currentPk: CURRENT,
            currentVersion: 3,
          }),
        ),
      ).toBe("INVALID_VERSION_SEQUENCE");
    });
  });
});
