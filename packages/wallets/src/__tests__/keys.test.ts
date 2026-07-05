import { describe, it, expect, beforeAll } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import {
  deriveViewKey,
  deriveIncomingKey,
  deriveSelfSpendKey,
  publicKey,
  pubkeyOwner,
  isEvenY,
  discoveryTag,
  canonicalIncomingAddress,
} from "../note/keys";

const frHex = (f: Fr): string => "0x" + f.toBuffer().toString("hex");

const SK_ROOT = new Fr(0x2an);

// KAT vector (checked in): TS output that the Noir even_y.nr #[test] mirrors on the same points.
const OWNER_INCOMING_J0 =
  "0x2aaf6cdf7a53712806c9b19173ad8682efbcea40760d3a01c9ebecd220714603";
const OWNER_SELF =
  "0x1e72d68a51bb74f76f9028fdff9f53c0a37468586d7b1b6a99a4115216730d54";

const IN_PUB_ODD_X =
  0x1f082615764661f46f203a3d3d4336d5d7273bf17a67d15bd485a7f329f47c93n;
const IN_PUB_ODD_Y =
  0x288d616819eb80b160bc2157bdbbd872bfe393957ee45a4aa222587e58a1bb47n;
const IN_PUB_EVEN_X =
  0x13bf364f3ed4490cd6a62bf0d6be4923b09ca23e761d654c7033321c381ba057n;
const IN_PUB_EVEN_Y =
  0x2071ecc0c290d14de1059e9e7594170da51ea08c071d2812bb047692e4e91338n;

const FIXTURE_IN_PUB_X =
  0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764n;
const FIXTURE_IN_PUB_Y =
  0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101n;

describe("Option-A key derivations + owner + even-y tags", () => {
  let sk_view: Fr;

  beforeAll(async () => {
    sk_view = await deriveViewKey(SK_ROOT);
  });

  it("derives the incoming-note owner (j=0)", async () => {
    const owner = await pubkeyOwner(
      publicKey(await deriveIncomingKey(sk_view, 0n)),
    );
    expect(frHex(owner)).toBe(OWNER_INCOMING_J0);
  });

  it("derives the self-note owner", async () => {
    const owner = await pubkeyOwner(
      publicKey(await deriveSelfSpendKey(sk_view)),
    );
    expect(frHex(owner)).toBe(OWNER_SELF);
  });

  it("agrees with the KAT points and their y-parity", async () => {
    const oddPub = publicKey(await deriveIncomingKey(sk_view, 1n));
    const evenPub = publicKey(await deriveIncomingKey(sk_view, 2n));
    expect(oddPub[0]).toBe(IN_PUB_ODD_X);
    expect(oddPub[1]).toBe(IN_PUB_ODD_Y);
    expect(evenPub[0]).toBe(IN_PUB_EVEN_X);
    expect(evenPub[1]).toBe(IN_PUB_EVEN_Y);
    expect(isEvenY(oddPub)).toBe(false);
    expect(isEvenY(evenPub)).toBe(true);
  });

  it("rolls an odd-y index to the next even-y index for the canonical tag", async () => {
    const canonical = await canonicalIncomingAddress(sk_view, 1n);
    expect(canonical.index).toBe(2n);
    expect(canonical.tag.toBigInt()).toBe(IN_PUB_EVEN_X);
    expect(discoveryTag(canonical.pub).toBigInt()).toBe(IN_PUB_EVEN_X);
    expect(isEvenY(canonical.pub)).toBe(true);
  });

  it("rejects the shared-fixture odd-y point (in_key_j = 789)", () => {
    const fixture = mulPointEscalar(Base8, 789n);
    expect(fixture[0]).toBe(FIXTURE_IN_PUB_X);
    expect(fixture[1]).toBe(FIXTURE_IN_PUB_Y);
    expect(isEvenY(fixture)).toBe(false);
  });

  it("owner of the fixture in_pub_j matches the Noir owner KAT and the DEM owner field", async () => {
    const owner = await pubkeyOwner(mulPointEscalar(Base8, 789n));
    expect(frHex(owner)).toBe(
      "0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785",
    );
  });
});
