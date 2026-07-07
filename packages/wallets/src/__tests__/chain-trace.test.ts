import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import {
  forwardTrace,
  backwardTrace,
  ChainState,
  DecryptNote,
  LeafData,
  SpendGraph,
} from "../threshold/chainTrace.js";
import { BASE8, scalarMul, Point } from "../tss/bjj.js";
import { demEncrypt, demDecrypt } from "../crypto/dem.js";
import { toFr } from "../crypto/fields.js";
import { leaf, packParents } from "../note/note.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";

// A single-key holder stands in for the committee: cek = (c*eph_pub).x == the encryptor's (eph*C).x.
const COMPLIANCE_SECRET =
  0x2a3bce9f10475d8c17e4f0a2b6d5931e77c0aa4415e9b2d63f81047c9d2e5abfn;
const COMPLIANCE_PK: Point = scalarMul(COMPLIANCE_SECRET, BASE8);

const ASSET_ID = toFr("0x1234567890123456789012345678901234567890");
const OWNER = toFr(
  "0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27",
);

class MockChain {
  private readonly leaves = new Map<number, LeafData>();
  private readonly spent = new Map<string, number[]>();
  private maxIndex = -1;

  async addNote(
    leafIndex: number,
    ephScalar: bigint,
    value: bigint,
    parents: Fr,
  ): Promise<Fr> {
    const ephPub = scalarMul(ephScalar, BASE8);
    const cek = new Fr(scalarMul(ephScalar, COMPLIANCE_PK)[0]);
    const psi = await computePsi(cek);
    const plaintext = [
      toFr(1),
      ASSET_ID,
      toFr(0),
      toFr(0),
      new Fr(value),
      OWNER,
      parents,
    ];
    const ciphertext = await demEncrypt(cek, plaintext);
    const commitment = await leaf({
      noteVersion: toFr(1),
      assetId: ASSET_ID,
      noteType: toFr(0),
      conditionsHash: toFr(0),
      value,
      owner: OWNER,
      psi,
      parents,
    });
    this.leaves.set(leafIndex, { ephPub, ciphertext, leaf: commitment });
    if (leafIndex > this.maxIndex) this.maxIndex = leafIndex;
    return computeNullifier(psi, new Fr(BigInt(leafIndex)));
  }

  markSpent(nf: Fr, children: number[]): void {
    this.spent.set(nf.toString(), children);
  }

  state(): ChainState {
    return {
      getLeaf: (i) => this.leaves.get(i),
      nextLeafIndex: () => this.maxIndex + 1,
      isNullifierSpent: (nf) => this.spent.has(nf.toString()),
      childrenOfSpend: (nf) => this.spent.get(nf.toString()) ?? [],
    };
  }

  decryptHook(): DecryptNote {
    return async (ephPub, ciphertext) => {
      const cek = new Fr(scalarMul(COMPLIANCE_SECRET, ephPub)[0]);
      const fields = await demDecrypt(cek, ciphertext);
      return { fields, cek };
    };
  }
}

function single(inputIndex: number): Fr {
  return packParents([{ leafIndex: inputIndex }, { leafIndex: 0 }]);
}

function joined(indexA: number, indexB: number): Fr {
  return packParents([{ leafIndex: indexA }, { leafIndex: indexB }]);
}

// Leaf 0 is reserved: a lone leaf-0 single-input spend packs to 0 and would alias a deposit.
async function buildLifecycleChain(): Promise<MockChain> {
  const chain = new MockChain();

  const nfDeposit = await chain.addNote(1, 2n, 100n, toFr(0));
  const nfMemo1 = await chain.addNote(2, 3n, 60n, single(1));
  await chain.addNote(3, 4n, 40n, single(1));
  const nfMemo2 = await chain.addNote(4, 5n, 35n, single(2));
  await chain.addNote(5, 6n, 25n, single(2));
  const nfChange3 = await chain.addNote(6, 7n, 30n, single(4));
  const nfSplit1 = await chain.addNote(7, 8n, 18n, single(6));
  const nfSplit2 = await chain.addNote(8, 9n, 12n, single(6));
  await chain.addNote(9, 10n, 30n, joined(7, 8));

  chain.markSpent(nfDeposit, [2, 3]);
  chain.markSpent(nfMemo1, [4, 5]);
  chain.markSpent(nfMemo2, [6]);
  chain.markSpent(nfChange3, [7, 8]);
  chain.markSpent(nfSplit1, [9]);
  chain.markSpent(nfSplit2, [9]);

  return chain;
}

function expectGraph(actual: SpendGraph, expected: SpendGraph): void {
  expect(actual.nodes).toEqual(expected.nodes);
  expect(actual.edges).toEqual(expected.edges);
}

describe("chainTrace: spend-graph reconstruction over threshold-decryptable notes", () => {
  it("forwardTrace from the deposit reconstructs the full descendant graph", async () => {
    const chain = await buildLifecycleChain();
    const graph = await forwardTrace(1, chain.state(), chain.decryptHook());
    expectGraph(graph, {
      nodes: [1, 2, 3, 4, 5, 6, 7, 8, 9],
      edges: [
        [1, 2],
        [1, 3],
        [2, 4],
        [2, 5],
        [4, 6],
        [6, 7],
        [6, 8],
        [7, 9],
        [8, 9],
      ],
    });
  });

  it("backwardTrace from the join output reconstructs the ancestor lineage back to the deposit", async () => {
    const chain = await buildLifecycleChain();
    const graph = await backwardTrace(9, chain.state(), chain.decryptHook());
    expectGraph(graph, {
      nodes: [1, 2, 4, 6, 7, 8, 9],
      edges: [
        [1, 2],
        [2, 4],
        [4, 6],
        [6, 7],
        [6, 8],
        [7, 9],
        [8, 9],
      ],
    });
  });

  it("forwardTrace from a mid-chain note yields the descendant subgraph only", async () => {
    const chain = await buildLifecycleChain();
    const graph = await forwardTrace(6, chain.state(), chain.decryptHook());
    expectGraph(graph, {
      nodes: [6, 7, 8, 9],
      edges: [
        [6, 7],
        [6, 8],
        [7, 9],
        [8, 9],
      ],
    });
  });

  it("backwardTrace from an unspent change note stops at its single parent", async () => {
    const chain = await buildLifecycleChain();
    const graph = await backwardTrace(5, chain.state(), chain.decryptHook());
    expectGraph(graph, {
      nodes: [1, 2, 5],
      edges: [
        [1, 2],
        [2, 5],
      ],
    });
  });

  it("terminates on a cyclic spend graph via the visited-set", async () => {
    const chain = new MockChain();
    const nfA = await chain.addNote(1, 11n, 10n, toFr(0));
    const nfB = await chain.addNote(2, 12n, 10n, single(1));
    chain.markSpent(nfA, [2]);
    chain.markSpent(nfB, [1]); // adversarial cycle 1 -> 2 -> 1
    const graph = await forwardTrace(1, chain.state(), chain.decryptHook());
    expectGraph(graph, {
      nodes: [1, 2],
      edges: [
        [1, 2],
        [2, 1],
      ],
    });
  });

  it("rejects a start index beyond the tree frontier", async () => {
    const chain = await buildLifecycleChain();
    await expect(
      forwardTrace(99, chain.state(), chain.decryptHook()),
    ).rejects.toThrow(/out of range/);
  });
});
