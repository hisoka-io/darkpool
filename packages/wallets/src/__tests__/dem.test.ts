import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { demEncrypt, demDecrypt, DEM_FIELDS } from "../crypto/dem.js";

// Shared note-format KAT fixture (byte-identical to Noir shared/src/dem.nr dem_kat_encrypt_decrypt).
const CEK = new Fr(
  0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bdan,
);

// order k=0..6: [note_version, asset_id, note_type, conditions_hash, value, owner, parents]
const PLAINTEXT: Fr[] = [
  new Fr(1n),
  new Fr(0x1234567890123456789012345678901234567890n),
  new Fr(0n),
  new Fr(0n),
  new Fr(100n),
  new Fr(0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785n),
  new Fr(0n),
];

const EXPECTED_CT: Fr[] = [
  new Fr(0x2731638e2a7a9820452856622ce83bb4ed875a995d5f28e09a9e2813d1472f67n),
  new Fr(0x17537f0cfa734af08271f104fe3a6b59c655a70ef150119205af625ab451b413n),
  new Fr(0x214d78fb170e5a1de97ded5727a834f29b94f4ed0d3ca29b36aa98b597051302n),
  new Fr(0x109dbab21c201fdac2cd7e0f59efdc423f18de696a918357c9fedea65869ff8en),
  new Fr(0x2065a8ce6a9cdce89ca92cad5e9bc7a80f2413b893219f03e27365ebead75032n),
  new Fr(0x0124088cefa5b815b5213279cd8c7a7eef948183c37291e8740c9deccc202418n),
  new Fr(0x2971fe65daaac4e80629e73dfbd54bf6a38f9748d9728257ffefdc8b97686211n),
];

describe("zero-AES Poseidon2 stream DEM (parity)", () => {
  it("encrypt matches the checked-in ciphertext KAT", async () => {
    const ciphertext = await demEncrypt(CEK, PLAINTEXT);
    expect(ciphertext.length).toBe(DEM_FIELDS);
    for (let k = 0; k < DEM_FIELDS; k++) {
      expect(ciphertext[k].equals(EXPECTED_CT[k])).toBe(true);
    }
  });

  it("decrypt of the ciphertext KAT round-trips to the plaintext", async () => {
    const recovered = await demDecrypt(CEK, EXPECTED_CT);
    expect(recovered.length).toBe(DEM_FIELDS);
    for (let k = 0; k < DEM_FIELDS; k++) {
      expect(recovered[k].equals(PLAINTEXT[k])).toBe(true);
    }
  });

  it("encrypt then decrypt is the identity", async () => {
    const recovered = await demDecrypt(CEK, await demEncrypt(CEK, PLAINTEXT));
    for (let k = 0; k < DEM_FIELDS; k++) {
      expect(recovered[k].equals(PLAINTEXT[k])).toBe(true);
    }
  });

  it("rejects a field array of the wrong length", async () => {
    await expect(demEncrypt(CEK, PLAINTEXT.slice(0, 6))).rejects.toThrow();
    await expect(
      demDecrypt(CEK, EXPECTED_CT.concat(new Fr(0n))),
    ).rejects.toThrow();
  });
});
