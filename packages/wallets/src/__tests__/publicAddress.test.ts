import { describe, it, expect, beforeAll } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Point } from "@zk-kit/baby-jubjub";
import {
  canonicalPublicAddress,
  deriveIncomingKey,
  derivePublicIncomingKey,
  deriveSelfEphemeral,
  deriveViewKey,
  isEvenY,
  publicKey,
} from "../note/keys";
import {
  encodeHisokaAddress,
  decodeHisokaAddress,
  encodeHisokaPublicAddress,
  decodeHisokaPublicAddress,
} from "../address";
import { calculatePublicMemoId } from "../crypto/index";

const frHex = (f: Fr): string => "0x" + f.toBuffer().toString("hex");

const SK_ROOT = new Fr(0x2an);

// Freezes the "hisoka.pubIn" label and the index binding: a change here silently renumbers every
// published receiving address and strands funds already escrowed to the old point.
const PUB_IN_KEY_J0 =
  "0x02d1f3210d3e4ffd352ae6ee805c3c3540a25af5d5443688bc8c9cc274b1fd1f";
const PUB_IN_J0_X =
  0x0cf7e2339362e6302ca5475848bb4e5e5b75d50297d396212cee4e643f3e80a2n;
const PUB_IN_J0_Y =
  0x0b5f723dfbea311c19e65ee804372a10337478c10fc2b8ae7786f04d7f08a1bfn;

const EVEN_Y_INDEX = 2n;
const ODD_Y_INDEX = 0n;

// Order-2 point (0, -1): on the curve, outside the prime-order subgroup, so no public_claim witness reaches it.
const ORDER_TWO_POINT: Point<bigint> = [
  0n,
  21888242871839275222246405745257275088548364400416034343698204186575808495616n,
];

describe("public receiving keys are a separate family from private incoming keys", () => {
  let sk_view: Fr;

  beforeAll(async () => {
    sk_view = await deriveViewKey(SK_ROOT);
  });

  it("pins the hisoka.pubIn derivation", async () => {
    const key = await derivePublicIncomingKey(sk_view, 0n);
    expect(frHex(key)).toBe(PUB_IN_KEY_J0);
    const pub = publicKey(key);
    expect(pub[0]).toBe(PUB_IN_J0_X);
    expect(pub[1]).toBe(PUB_IN_J0_Y);
  });

  it("produces a different point than the private families at the same index", async () => {
    for (let index = 0n; index < 4n; index++) {
      const pub = publicKey(await derivePublicIncomingKey(sk_view, index));
      const incoming = publicKey(await deriveIncomingKey(sk_view, index));
      const selfEph = publicKey(await deriveSelfEphemeral(sk_view, index));
      expect(
        pub[0],
        `index ${index} collides with the incoming family`,
      ).not.toBe(incoming[0]);
      expect(pub[0], `index ${index} collides with the self family`).not.toBe(
        selfEph[0],
      );
    }
  });

  it("keeps the requested index even when the point has odd y", async () => {
    const addr = await canonicalPublicAddress(sk_view, ODD_Y_INDEX);
    expect(isEvenY(addr.pub)).toBe(false);
    expect(addr.index).toBe(ODD_Y_INDEX);
    expect(addr.pub[0]).toBe(PUB_IN_J0_X);
    expect(addr.pub[1]).toBe(PUB_IN_J0_Y);
  });
});

describe("public address codec", () => {
  let sk_view: Fr;

  beforeAll(async () => {
    sk_view = await deriveViewKey(SK_ROOT);
  });

  it("round-trips both y parities without loss", async () => {
    for (const index of [ODD_Y_INDEX, EVEN_Y_INDEX]) {
      const addr = await canonicalPublicAddress(sk_view, index);
      const decoded = decodeHisokaPublicAddress(
        encodeHisokaPublicAddress({ ownerPub: addr.pub, index: addr.index }),
      );
      expect(decoded.ownerPub[0]).toBe(addr.pub[0]);
      expect(decoded.ownerPub[1]).toBe(addr.pub[1]);
      expect(decoded.index).toBe(index);
    }
  });

  it("uses the hisopub_ prefix", async () => {
    const addr = await canonicalPublicAddress(sk_view, EVEN_Y_INDEX);
    const encoded = encodeHisokaPublicAddress({
      ownerPub: addr.pub,
      index: addr.index,
    });
    expect(encoded.startsWith("hisopub_")).toBe(true);
    expect(encoded.startsWith("hiso_")).toBe(false);
  });

  it("rejects a private address, naming the decoder to use", async () => {
    const canonical = await canonicalPublicAddress(sk_view, EVEN_Y_INDEX);
    const privateAddress = encodeHisokaAddress({
      inPub: canonical.pub,
      index: canonical.index,
    });
    expect(() => decodeHisokaPublicAddress(privateAddress)).toThrow(
      /private payment address/,
    );
    expect(() => decodeHisokaPublicAddress(privateAddress)).toThrow(/hisopub_/);
  });

  it("rejects a public address in the private decoder", async () => {
    const addr = await canonicalPublicAddress(sk_view, EVEN_Y_INDEX);
    const publicAddress = encodeHisokaPublicAddress({
      ownerPub: addr.pub,
      index: addr.index,
    });
    expect(() => decodeHisokaAddress(publicAddress)).toThrow(
      /decodeHisokaPublicAddress/,
    );
  });

  it("rejects an unknown prefix", async () => {
    const addr = await canonicalPublicAddress(sk_view, EVEN_Y_INDEX);
    const tampered = encodeHisokaPublicAddress({
      ownerPub: addr.pub,
      index: addr.index,
    }).replace("hisopub_", "invalid_");
    expect(() => decodeHisokaPublicAddress(tampered)).toThrow(/prefix/);
  });

  it("rejects a corrupted checksum", async () => {
    const addr = await canonicalPublicAddress(sk_view, EVEN_Y_INDEX);
    const parts = encodeHisokaPublicAddress({
      ownerPub: addr.pub,
      index: addr.index,
    }).split("_");
    const last = parts[1].slice(-1);
    const flipped = last === "A" ? "B" : "A";
    expect(() =>
      decodeHisokaPublicAddress(
        `${parts[0]}_${parts[1].slice(0, -1)}${flipped}`,
      ),
    ).toThrow(/checksum/i);
  });

  it("rejects an off-curve owner point", () => {
    expect(() =>
      encodeHisokaPublicAddress({
        ownerPub: [1n, 2n] as Point<bigint>,
        index: 0n,
      }),
    ).toThrow(/curve/);
  });

  it("rejects an owner point outside the prime-order subgroup", () => {
    expect(() =>
      encodeHisokaPublicAddress({ ownerPub: ORDER_TWO_POINT, index: 0n }),
    ).toThrow(/subgroup/);
  });

  it("feeds the memo id that DarkPool.publicTransfer computes", async () => {
    const addr = await canonicalPublicAddress(sk_view, ODD_Y_INDEX);
    const decoded = decodeHisokaPublicAddress(
      encodeHisokaPublicAddress({ ownerPub: addr.pub, index: addr.index }),
    );
    const memoId = await calculatePublicMemoId(
      new Fr(100n),
      new Fr(0x1234567890123456789012345678901234567890n),
      new Fr(0n),
      new Fr(decoded.ownerPub[0]),
      new Fr(decoded.ownerPub[1]),
      new Fr(7n),
    );
    const direct = await calculatePublicMemoId(
      new Fr(100n),
      new Fr(0x1234567890123456789012345678901234567890n),
      new Fr(0n),
      new Fr(addr.pub[0]),
      new Fr(addr.pub[1]),
      new Fr(7n),
    );
    expect(memoId.equals(direct)).toBe(true);
  });
});
