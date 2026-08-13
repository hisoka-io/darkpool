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
import { demEncrypt, demDecrypt, DEM_FIELDS } from "../crypto/dem.js";
import { toFr } from "../crypto/fields.js";
import { leaf, packParents, PARENTS_HIDDEN } from "../note/note.js";
import { computePsi, computeNullifier } from "../note/nullifier.js";

const PARENTS_FIELD_INDEX_TEST = DEM_FIELDS - 1;

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

// Only the two fields the callers actually supply. `truncated` is asserted separately where it matters,
// so requiring it here would force every call site to restate a value it does not exercise.
function expectGraph(
  actual: SpendGraph,
  expected: Pick<SpendGraph, "nodes" | "edges">,
): void {
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
    chain.markSpent(nfB, [1]);
    const graph = await forwardTrace(1, chain.state(), chain.decryptHook());
    expectGraph(graph, {
      nodes: [1, 2],
      edges: [
        [1, 2],
        [2, 1],
      ],
    });
  });

  async function buildTransferChain(): Promise<{
    chain: MockChain;
    memoIndex: number;
  }> {
    const chain = new MockChain();
    const nfDeposit = await chain.addNote(1, 21n, 100n, toFr(0));
    await chain.addNote(2, 22n, 40n, PARENTS_HIDDEN);
    await chain.addNote(3, 23n, 60n, single(1));
    chain.markSpent(nfDeposit, [2, 3]);
    return { chain, memoIndex: 2 };
  }

  it("backwardTrace crosses a PARENTS_HIDDEN memo via the sender's co-output change note", async () => {
    const { chain, memoIndex } = await buildTransferChain();
    const graph = await backwardTrace(
      memoIndex,
      chain.state(),
      chain.decryptHook(),
    );
    expect(graph.nodes).toEqual([1, 2]);
    expect(graph.edges).toEqual([[1, 2]]);
    expect(graph.truncated).toEqual([]);
  });

  it("forwardTrace still reaches both outputs of that transfer", async () => {
    const { chain } = await buildTransferChain();
    const graph = await forwardTrace(1, chain.state(), chain.decryptHook());
    expect(graph.nodes).toEqual([1, 2, 3]);
    expect(graph.edges).toEqual([
      [1, 2],
      [1, 3],
    ]);
  });

  it("records a truncation when the hidden lineage cannot be recovered", async () => {
    const chain = new MockChain();
    await chain.addNote(1, 31n, 40n, PARENTS_HIDDEN);
    const graph = await backwardTrace(1, chain.state(), chain.decryptHook());
    expect(graph.nodes).toEqual([1]);
    expect(graph.edges).toEqual([]);
    expect(graph.truncated).toEqual([1]);
  });

  it("refuses an unverified bridge when the claimed parent's nullifier is unspent", async () => {
    const chain = new MockChain();
    await chain.addNote(1, 41n, 100n, toFr(0));
    await chain.addNote(2, 42n, 40n, PARENTS_HIDDEN);
    await chain.addNote(3, 43n, 60n, single(1));
    const graph = await backwardTrace(2, chain.state(), chain.decryptHook());
    expect(graph.nodes).toEqual([2]);
    expect(graph.truncated).toEqual([2]);
  });

  it("refuses plaintext that does not reproduce the committed leaf", async () => {
    const chain = await buildLifecycleChain();
    const honest = chain.decryptHook();
    const tampered: DecryptNote = async (ephPub, ciphertext) => {
      const out = await honest(ephPub, ciphertext);
      const fields = [...out.fields];
      fields[PARENTS_FIELD_INDEX_TEST] = single(1);
      return { fields, cek: out.cek };
    };
    const graph = await backwardTrace(6, chain.state(), tampered);
    expect(graph.edges).toEqual([]);
    expect(graph.truncated).toEqual([6]);
  });

  it("rejects a start index beyond the tree frontier", async () => {
    const chain = await buildLifecycleChain();
    await expect(
      forwardTrace(99, chain.state(), chain.decryptHook()),
    ).rejects.toThrow(/out of range/);
  });

  // The bridge adopts leaf m+1's parents, so it MUST prove m and m+1 are outputs of one spend. Here they are
  // not: leaf 4 belongs to a second transaction, and adopting its parent would attribute deposit B's funds to
  // a memo actually funded by deposit A.
  it("refuses the bridge when the adjacent leaf belongs to a different transaction", async () => {
    const chain = new MockChain();
    const nfDepositA = await chain.addNote(1, 51n, 100n, toFr(0));
    const nfDepositB = await chain.addNote(2, 52n, 50n, toFr(0));
    await chain.addNote(3, 53n, 40n, PARENTS_HIDDEN);
    await chain.addNote(4, 54n, 50n, single(2));
    chain.markSpent(nfDepositA, [3]);
    chain.markSpent(nfDepositB, [4]);

    const graph = await backwardTrace(3, chain.state(), chain.decryptHook());
    expect(graph.edges).toEqual([]);
    expect(graph.truncated).toEqual([3]);
  });

  // A tampered ciphertext decrypts to a uniform Fr, so the value field overflows u128 with probability ~1 and
  // the leaf rebuild would throw before the commitment check ever runs. The trace must degrade, not abort.
  it("truncates rather than throwing when a decrypted value exceeds u128", async () => {
    const chain = await buildLifecycleChain();
    const honest = chain.decryptHook();
    const tampered: DecryptNote = async (ephPub, ciphertext) => {
      const out = await honest(ephPub, ciphertext);
      const fields = [...out.fields];
      fields[4] = new Fr(1n << 128n);
      return { fields, cek: out.cek };
    };
    const graph = await backwardTrace(6, chain.state(), tampered);
    expect(graph.edges).toEqual([]);
    expect(graph.truncated).toEqual([6]);
  });

  // Committed, so it survives the leaf rebuild and reaches the unpack; only the range guard can stop it.
  it("truncates rather than throwing on a committed but unpackable parents field", async () => {
    const chain = new MockChain();
    await chain.addNote(1, 61n, 40n, new Fr(1n << 64n));
    const graph = await backwardTrace(1, chain.state(), chain.decryptHook());
    expect(graph.edges).toEqual([]);
    expect(graph.truncated).toEqual([1]);
  });

  it("truncates rather than throwing on a committed out-of-range parent index", async () => {
    const chain = new MockChain();
    await chain.addNote(1, 62n, 40n, single(99));
    const graph = await backwardTrace(1, chain.state(), chain.decryptHook());
    expect(graph.edges).toEqual([]);
    expect(graph.truncated).toEqual([1]);
  });
});
