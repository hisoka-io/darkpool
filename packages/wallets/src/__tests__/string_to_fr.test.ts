import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { stringToFr } from "../crypto/fields";

describe("stringToFr Cross-Language Compatibility", () => {
  it('should match the known Noir output for "hisoka.enc_key"', async () => {
    const expectedNoirOutput = new Fr(
      0x0281a8425bea84c419aa615997d24dd06616356a715c72dc95be25985fd32e8dn,
    );

    const tsOutput = await stringToFr("hisoka.enc_key");
    expect(tsOutput.equals(expectedNoirOutput)).toBe(true);
  });
});
