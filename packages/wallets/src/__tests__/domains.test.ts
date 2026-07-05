import { describe, it, expect } from "vitest";
import { keccak256, toUtf8Bytes } from "ethers";
import { ENC_DOMAIN, PSI_DOMAIN, DLEQ_DOMAIN } from "../crypto/constants.js";
import { stringToFr } from "../crypto/fields.js";

const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const domainOf = (label: string): bigint =>
  BigInt(keccak256(toUtf8Bytes(label))) % P;

describe("note-format domain tags (parity)", () => {
  it("match keccak256(label) % BN254_Fr", () => {
    expect(ENC_DOMAIN).toBe(domainOf("hisoka.enc.v1"));
    expect(PSI_DOMAIN).toBe(domainOf("hisoka.psi.v1"));
    expect(DLEQ_DOMAIN).toBe(domainOf("hisoka.dleq.v1"));
  });

  it("are pairwise distinct", () => {
    expect(ENC_DOMAIN).not.toBe(PSI_DOMAIN);
    expect(ENC_DOMAIN).not.toBe(DLEQ_DOMAIN);
    expect(PSI_DOMAIN).not.toBe(DLEQ_DOMAIN);
  });

  it("KAT: exact field values match the Noir ENC_DOMAIN/PSI_DOMAIN globals", () => {
    expect(ENC_DOMAIN).toBe(
      0x1a0ef2d9219ffd1fa6aaa00b33818a7f5503303777b95cfcc6bb7653189dfca3n,
    );
    expect(PSI_DOMAIN).toBe(
      0x138d495e7a5c1b3f504318dd6cfcf0a7cf7bb6d69cf9eadb049cc35d6831ef5bn,
    );
  });

  it("new KDF purpose-labels derive distinct field tags (key domain separation)", async () => {
    const labels = [
      "hisoka.view",
      "hisoka.inKey",
      "hisoka.selfEph",
      "hisoka.selfSpend",
    ];
    const frs = await Promise.all(labels.map((l) => stringToFr(l)));
    const distinct = new Set(frs.map((f) => f.toString()));
    expect(distinct.size).toBe(labels.length);
  });
});
