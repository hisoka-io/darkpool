import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import { DarkAccount } from "../keys/DarkAccount";
import { KeyRepository } from "../state/KeyRepository";
import { InMemoryEphemeralCounterStore } from "../state/EphemeralCounterStore";
import { NoteProcessor } from "../sync/NoteProcessor";
import { UnprocessedEvent } from "../sync/types";
import {
  IKeyRepository,
  IncomingAddress,
  KeyRepoState,
  SelfEphemeral,
} from "../repositories";
import { deriveCek, unwrapCek, wrapCek } from "../crypto/kem";
import { demEncrypt } from "../crypto/dem";
import { computePsi } from "../note/nullifier";
import { leaf as computeLeaf } from "../note/note";
import { publicKey, pubkeyOwner, discoveryTag } from "../note/keys";

const MNEMONIC = "test test test test test test test test test test test junk";

const COMPLIANCE_PK: Point<bigint> = [
  0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111n,
  0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8n,
];

// A NoteProcessor-only key source that resolves the fixture discovery tags to their fixture scalars,
// so the decrypt lifecycle runs against gen_v2_fixtures.ts values rather than re-derived wallet keys.
class FixtureKeyRepo implements IKeyRepository {
  readonly selfScanIndex = 0;
  readonly incomingScanIndex = 0;

  constructor(
    private readonly selfTags: Map<string, { eph: Fr; index: number }>,
    private readonly incomingTags: Map<string, { inKey: Fr; index: number }>,
    private readonly selfSpend: Fr,
    private readonly selfSpendPub: Point<bigint>,
  ) {}

  public matchSelfTag(tag: bigint | string): { eph: Fr; index: number } | null {
    return this.selfTags.get(new Fr(BigInt(tag)).toString()) ?? null;
  }

  public matchIncomingTag(
    tag: bigint | string,
  ): { inKey: Fr; index: number } | null {
    return this.incomingTags.get(new Fr(BigInt(tag)).toString()) ?? null;
  }

  public async getSelfSpendScalar(): Promise<Fr> {
    return this.selfSpend;
  }
  public async getSelfSpendPub(): Promise<Point<bigint>> {
    return this.selfSpendPub;
  }

  public recordIncomingMatch(): void {}
  public async ensureSelfLookahead(): Promise<boolean> {
    return false;
  }
  public async ensureIncomingLookahead(): Promise<boolean> {
    return false;
  }
  public nextSelfEphemeral(): Promise<SelfEphemeral> {
    return Promise.reject(new Error("FixtureKeyRepo does not mint"));
  }
  public nextIncomingAddress(): Promise<IncomingAddress> {
    return Promise.reject(new Error("FixtureKeyRepo does not issue"));
  }
  public getState(): KeyRepoState {
    throw new Error("FixtureKeyRepo is not durable");
  }
  public async restore(): Promise<void> {}
}

describe("self-note lifecycle (deposit fixture round-trip)", () => {
  const DEPOSIT_TAG =
    0x1961ff2315812fd2f3e459a258f5ded2dde68cd35c79c8b9fb443e1860e1fbe4n;
  const DEPOSIT_EPH_Y =
    0x217d990737cc33efe8db5485973124fdd98c866783f0d81ffccfffe7102a9c6an;
  const DEPOSIT_LEAF =
    "0x09b087f618ba26b56f02ad1438a08cf9681445de37e85771c2e77f3058e0a551";
  const DEPOSIT_CEK = new Fr(
    0x0f55e80a890924a14c58cae89e59608fb8bb124578d548643e81fdaaa6c833f6n,
  );
  const OWNER_SELF = new Fr(
    0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785n,
  );
  const NULLIFIER_AT_0 = new Fr(
    0x2761654f0b4e9f47ac9bafe900c723ead042a888da718a34b6ecc8036850755en,
  );
  const SELF_SPEND = new Fr(789n);
  const DEPOSIT_CT = [
    "0x13e12fd48ec5eefe22cea1ccf4f29e16f8883011140afbe24dfe35a049b34f1d",
    "0x2de9323ad365a7a1d87313532c6fab1c5c28cc719199cc2d2fb7c11dacf2a320",
    "0x02555b86c4f79aeaf1d42a42d741ea9ad55b520a805749e51b7c6763e774fa53",
    "0x1ede7e0fe3a5480fe39c58d0d4f3943608d1f32317fc8b352d0837751abb1a56",
    "0x0315cb8108b04605532f5b3ebd9a6e03dce5b3f0506e76de29bd7bad5df93d33",
    "0x1f5a021db1636df508522b57770b1b7024e5e2ec2cb2927859b536cef6f1b09d",
    "0x0f0c848a687a5d761bda9b0043218db11eddbbdab55c4bec7d5dae04c89182cb",
  ];

  it("CEK = (eph*C).x reproduces the fixture content key", () => {
    expect(deriveCek(new Fr(5n), COMPLIANCE_PK).equals(DEPOSIT_CEK)).toBe(true);
  });

  it("decrypts the deposit ciphertext to value 100 / owner_self / fixture leaf and nullifier at index 0", async () => {
    const selfTags = new Map([
      [new Fr(DEPOSIT_TAG).toString(), { eph: new Fr(5n), index: 0 }],
    ]);
    const repo = new FixtureKeyRepo(
      selfTags,
      new Map(),
      SELF_SPEND,
      publicKey(SELF_SPEND),
    );
    const processor = new NoteProcessor(repo, COMPLIANCE_PK);

    const event: UnprocessedEvent = {
      type: "NEW_NOTE",
      blockNumber: 1,
      txHash: "0x00",
      args: {
        leafIndex: 0n,
        commitment: DEPOSIT_LEAF,
        ephemeralX: DEPOSIT_TAG,
        ephemeralY: DEPOSIT_EPH_Y,
        packedCiphertext: DEPOSIT_CT,
      },
    };

    const walletNote = await processor.process(event);
    expect(walletNote).not.toBeNull();
    expect(walletNote!.commitment.equals(new Fr(BigInt(DEPOSIT_LEAF)))).toBe(
      true,
    );
    expect(walletNote!.note.value).toBe(100n);
    expect(walletNote!.note.owner.equals(OWNER_SELF)).toBe(true);
    expect(walletNote!.nullifier.equals(NULLIFIER_AT_0)).toBe(true);
    expect(walletNote!.spendScalar.equals(SELF_SPEND)).toBe(true);
    expect(walletNote!.isIncoming).toBe(false);
  });
});

describe("incoming-memo lifecycle (transfer memo fixture round-trip)", () => {
  const MEMO_TAG =
    0x1b16e357953d68d73398c838aa883cc65ddae2aef75a4bc437e4232afdbe43c8n;
  const MEMO_EPH_X =
    0x25fbe8bb651983f4e6651fb47245f7f058afcda6958a3e468dc50e8d77af07e6n;
  const MEMO_EPH_Y =
    0x2fe08fd5f557d0326251711696f8bfb3cfd33fc3c15168019ac86c9e8af6f3a9n;
  const MEMO_LEAF =
    "0x192da44b73da0d163a65d76aac64fd3bc8ab96f2a1bee6ed64bc284e0ec4c6f2";
  const MEMO_CEK = new Fr(
    0x0e94d7f61c674a233b14b9b972d8fe81f5c14f1ef33e2568a2cb20be47ce2991n,
  );
  const MEMO_CEK_WRAP =
    0x1b67cde705ce9682a9d976006cff63dfcc524dedaf6f8d4bc31ac09bc3e084a6n;
  const OWNER_MEMO = new Fr(
    0x1113074e2fb269d979ad2b64e6fe70b1967c67b007b706600603b847306aefe3n,
  );
  const IN_KEY_J = new Fr(4n);
  const MEMO_CT = [
    "0x29bb025dd94ba3d39cfc290a2b868a66b8053f6d9a6ecbf6aad13eec3430c45f",
    "0x0cf24f6565c72b95af848758fd84320df5deba59a2d981ea80979c2b26c6aad1",
    "0x2608f23654db19cf478e1dafb0def1df1ea850f80ba8017ecfa54d2bd412ef16",
    "0x1c20829f07ff3709a9533be0681409540ddcb3571673e5deb1d70d95d6b70366",
    "0x17450b54d6f9f2f6d675df6859b38a80e06306db392cf0137154537e4de4e042",
    "0x2f8af6aee688f06521a50c621ff6d1b75c406013988d45016cfa8ab7b2dbc58d",
    "0x21b3dd8c5596bdde64eca0bbcd19e2b52e3a42d70a64d9d521a50cf06bc6a4ec",
  ];

  it("unwrapCek recovers the fixture CEK from in_key_j and eph_pub", async () => {
    const recovered = await unwrapCek(new Fr(MEMO_CEK_WRAP), IN_KEY_J, [
      MEMO_EPH_X,
      MEMO_EPH_Y,
    ]);
    expect(recovered.equals(MEMO_CEK)).toBe(true);
  });

  it("decrypts the transfer memo to value 40 / owner_memo / fixture leaf as an incoming note", async () => {
    const incomingTags = new Map([
      [new Fr(MEMO_TAG).toString(), { inKey: IN_KEY_J, index: 0 }],
    ]);
    const repo = new FixtureKeyRepo(
      new Map(),
      incomingTags,
      new Fr(0n),
      publicKey(new Fr(1n)),
    );
    const processor = new NoteProcessor(repo, COMPLIANCE_PK);

    const event: UnprocessedEvent = {
      type: "NEW_MEMO",
      blockNumber: 1,
      txHash: "0x00",
      args: {
        leafIndex: 0n,
        commitment: MEMO_LEAF,
        ephemeralX: MEMO_EPH_X,
        ephemeralY: MEMO_EPH_Y,
        packedCiphertext: MEMO_CT,
        tag: MEMO_TAG,
        cekWrap: MEMO_CEK_WRAP,
      },
    };

    const walletNote = await processor.process(event);
    expect(walletNote).not.toBeNull();
    expect(walletNote!.commitment.equals(new Fr(BigInt(MEMO_LEAF)))).toBe(true);
    expect(walletNote!.note.value).toBe(40n);
    expect(walletNote!.note.owner.equals(OWNER_MEMO)).toBe(true);
    expect(walletNote!.spendScalar.equals(IN_KEY_J)).toBe(true);
    expect(walletNote!.isIncoming).toBe(true);
  });
});

// WN-1 regression: an incoming memo whose leaf/CEK/tag all match but whose `owner` is NOT the recipient's must be
// DROPPED (a phantom, unspendable note = balance overstatement), not registered. Before the fix the incoming path
// skipped the owner check, so it registered. A valid memo (owner == recipient) still registers.
describe("WN-1: incoming note owner binding (phantom-note guard)", () => {
  const EPH = new Fr(7n);
  const IN_KEY = new Fr(4n);
  const ASSET = new Fr(0x1234n);
  const V1 = new Fr(1n);
  const ZERO = new Fr(0n);
  const hex = (f: Fr) => "0x" + f.toBigInt().toString(16).padStart(64, "0");

  async function memoEventFor(owner: Fr): Promise<UnprocessedEvent> {
    const inPub = publicKey(IN_KEY);
    const cek = deriveCek(EPH, COMPLIANCE_PK);
    const psi = await computePsi(cek);
    const commitment = await computeLeaf({
      noteVersion: V1,
      assetId: ASSET,
      noteType: ZERO,
      conditionsHash: ZERO,
      value: 40n,
      owner,
      psi,
      parents: ZERO,
    });
    const ct = await demEncrypt(cek, [
      V1,
      ASSET,
      ZERO,
      ZERO,
      new Fr(40n),
      owner,
      ZERO,
    ]);
    const cekWrap = await wrapCek(cek, EPH, inPub);
    const ephPub = publicKey(EPH);
    return {
      type: "NEW_MEMO",
      blockNumber: 1,
      txHash: "0x00",
      args: {
        leafIndex: 0n,
        commitment: hex(commitment),
        ephemeralX: ephPub[0],
        ephemeralY: ephPub[1],
        packedCiphertext: ct.map(hex),
        tag: discoveryTag(inPub).toBigInt(),
        cekWrap: cekWrap.toBigInt(),
      },
    } as UnprocessedEvent;
  }

  function repoFor(): FixtureKeyRepo {
    const tag = discoveryTag(publicKey(IN_KEY));
    return new FixtureKeyRepo(
      new Map(),
      new Map([
        [new Fr(tag.toBigInt()).toString(), { inKey: IN_KEY, index: 0 }],
      ]),
      new Fr(0n),
      publicKey(new Fr(1n)),
    );
  }

  it("registers a valid incoming note (owner == recipient)", async () => {
    const owner = await pubkeyOwner(publicKey(IN_KEY));
    const note = await new NoteProcessor(repoFor(), COMPLIANCE_PK).process(
      await memoEventFor(owner),
    );
    expect(note).not.toBeNull();
    expect(note!.note.owner.equals(owner)).toBe(true);
    expect(note!.isIncoming).toBe(true);
  });

  it("drops a mismatched incoming note (owner != recipient) as a phantom", async () => {
    const wrongOwner = await pubkeyOwner(publicKey(new Fr(999n)));
    const note = await new NoteProcessor(repoFor(), COMPLIANCE_PK).process(
      await memoEventFor(wrongOwner),
    );
    expect(note).toBeNull();
  });
});

describe("atomic self-ephemeral counter durability", () => {
  it("advances write-ahead, serializes concurrent mints, and never reuses an index across restart", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const repo = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );

    const first = await repo.nextSelfEphemeral();
    const second = await repo.nextSelfEphemeral();
    expect(second.index).toBeGreaterThan(first.index);
    expect(first.eph.equals(second.eph)).toBe(false);
    expect(repo.getState().selfMintCounter).toBe(second.index + 1);

    const [third, fourth] = await Promise.all([
      repo.nextSelfEphemeral(),
      repo.nextSelfEphemeral(),
    ]);
    expect(third.index).not.toBe(fourth.index);

    const priorIndices = [first, second, third, fourth];
    const priorMax = Math.max(...priorIndices.map((m) => m.index));

    const fresh = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    await fresh.restore(repo.getState());
    const resumed = await fresh.nextSelfEphemeral();

    expect(resumed.index).toBeGreaterThan(priorMax);
    expect(priorIndices.some((m) => m.eph.equals(resumed.eph))).toBe(false);
  });
});
