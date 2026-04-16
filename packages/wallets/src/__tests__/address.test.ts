import { describe, it, expect, beforeAll } from "vitest";
import { generateDLEQProof } from "../crypto";
import { encodeHisokaAddress, decodeHisokaAddress } from "../address";
import { mulPointEscalar, Base8, Point } from "@zk-kit/baby-jubjub";

describe("Hisoka Address Encoding", () => {
  let mockAddressData: Awaited<ReturnType<typeof generateDLEQProof>>;

  beforeAll(async () => {
    const bob_sk = 123456789n;
    const carol_sk = 987654321n;
    const carol_pk: Point<bigint> = mulPointEscalar(Base8, carol_sk);
    mockAddressData = await generateDLEQProof(bob_sk, carol_pk);
  });

  it("should encode and decode symmetrically without data loss", () => {
    const { B, P, pi } = mockAddressData;
    const address = encodeHisokaAddress({ B, P, pi });
    const decodedData = decodeHisokaAddress(address);

    expect(decodedData.B[0]).toEqual(B[0]);
    expect(decodedData.B[1]).toEqual(B[1]);
    expect(decodedData.P[0]).toEqual(P[0]);
    expect(decodedData.P[1]).toEqual(P[1]);
    expect(decodedData.pi.U[0]).toEqual(pi.U[0]);
    expect(decodedData.pi.U[1]).toEqual(pi.U[1]);
    expect(decodedData.pi.V[0]).toEqual(pi.V[0]);
    expect(decodedData.pi.V[1]).toEqual(pi.V[1]);
    expect(decodedData.pi.z).toEqual(pi.z);
  });

  it("should start with the correct prefix", () => {
    const { B, P, pi } = mockAddressData;
    const address = encodeHisokaAddress({ B, P, pi });
    expect(address.startsWith("hiso_")).toBe(true);
  });

  it("should throw an error for an invalid prefix", () => {
    const { B, P, pi } = mockAddressData;
    const address = encodeHisokaAddress({ B, P, pi });
    const tamperedAddress = address.replace("hiso_", "invalid_");
    expect(() => decodeHisokaAddress(tamperedAddress)).toThrow(
      /Invalid Hisoka address format or prefix/,
    );
  });

  it("should throw an error for a corrupted payload (checksum failure)", () => {
    const { B, P, pi } = mockAddressData;
    const address = encodeHisokaAddress({ B, P, pi });

    // Tamper with a character in the payload, ensuring it actually changes
    const parts = address.split("_");
    const lastChar = parts[1].slice(-1);
    const flipped = lastChar === "A" ? "B" : "A";
    const corruptedPayload = parts[1].slice(0, -1) + flipped;
    const tamperedAddress = `${parts[0]}_${corruptedPayload}`;

    // bs58check will throw on a checksum mismatch
    expect(() => decodeHisokaAddress(tamperedAddress)).toThrow(
      /Invalid checksum/,
    );
  });
});
