import { expect } from "chai";
import { ethers } from "ethers";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  SAFE_V141,
  loadOwnerKeys,
  multiSendCallOnly,
  validateSafeConfig,
} from "../../scripts/gov/safe";

// The public hardhat/anvil development mnemonic, accounts 1 and 2.
const DEV_MNEMONIC =
  "test test test test test test test test test test test junk";
const devWallet = (index: number) =>
  ethers.HDNodeWallet.fromPhrase(
    DEV_MNEMONIC,
    undefined,
    `m/44'/60'/0'/0/${index}`,
  );
const KEY_1 = devWallet(1).privateKey;
const KEY_2 = devWallet(2).privateKey;
const ADDRESS_1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const ADDRESS_2 = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

describe("governance Safe helpers", function () {
  let dir: string;

  beforeEach(function () {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "gov-safe-"));
  });

  afterEach(function () {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function writeKeys(content: string, mode: number): string {
    const file = path.join(dir, "keys.json");
    fs.writeFileSync(file, content, { mode });
    fs.chmodSync(file, mode);
    return file;
  }

  function errorOf(body: () => unknown): Error {
    try {
      body();
    } catch (e) {
      return e as Error;
    }
    throw new Error("expected a throw");
  }

  it("loads owner keys by derived address", function () {
    const file = writeKeys(
      JSON.stringify({
        owners: [
          { address: ADDRESS_1, privateKey: KEY_1 },
          { privateKey: KEY_2 },
        ],
      }),
      0o600,
    );
    const keys = loadOwnerKeys(file);
    expect([...keys.keys()]).to.deep.equal([ADDRESS_1, ADDRESS_2]);
  });

  it("refuses a keys file readable by group or others", function () {
    const file = writeKeys(
      JSON.stringify({ owners: [{ privateKey: KEY_1 }] }),
      0o644,
    );
    expect(errorOf(() => loadOwnerKeys(file)).message).to.contain("chmod 600");
  });

  it("never echoes key material in its errors", function () {
    const broken = writeKeys(`{"owners": [{"privateKey": "${KEY_1}"`, 0o600);
    const parseError = errorOf(() => loadOwnerKeys(broken));
    expect(parseError.message).to.contain("is not valid JSON");
    expect(parseError.message).to.not.contain(KEY_1.slice(2, 20));

    const mismatched = writeKeys(
      JSON.stringify({ owners: [{ address: ADDRESS_2, privateKey: KEY_1 }] }),
      0o600,
    );
    const mismatch = errorOf(() => loadOwnerKeys(mismatched));
    expect(mismatch.message).to.contain("does not match its privateKey");
    expect(mismatch.message).to.not.contain(KEY_1.slice(2, 20));

    const short = writeKeys(
      JSON.stringify({ owners: [{ privateKey: KEY_1.slice(0, 40) }] }),
      0o600,
    );
    const shortError = errorOf(() => loadOwnerKeys(short));
    expect(shortError.message).to.contain("32-byte hex");
    expect(shortError.message).to.not.contain(KEY_1.slice(2, 20));
  });

  it("refuses a repeated owner", function () {
    const file = writeKeys(
      JSON.stringify({
        owners: [{ privateKey: KEY_1 }, { privateKey: KEY_1 }],
      }),
      0o600,
    );
    expect(errorOf(() => loadOwnerKeys(file)).message).to.contain(
      `repeats owner ${ADDRESS_1}`,
    );
  });

  it("validates Safe owner sets and thresholds", function () {
    expect(() =>
      validateSafeConfig({ owners: [ADDRESS_1, ADDRESS_2], threshold: 2 }, "t"),
    ).to.not.throw();
    expect(() =>
      validateSafeConfig({ owners: [ADDRESS_1, ADDRESS_1], threshold: 1 }, "t"),
    ).to.throw("listed twice");
    expect(() =>
      validateSafeConfig({ owners: [ADDRESS_1], threshold: 0 }, "t"),
    ).to.throw("threshold 0");
    expect(() =>
      validateSafeConfig({ owners: [ADDRESS_1], threshold: 2 }, "t"),
    ).to.throw("threshold 2");
    expect(() =>
      validateSafeConfig({ owners: [ethers.ZeroAddress], threshold: 1 }, "t"),
    ).to.throw("must be non-zero");
  });

  it("packs MultiSendCallOnly calls as (operation, to, value, length, data)", function () {
    const calls = [
      { to: ADDRESS_1, value: 0n, data: "0x12345678" },
      { to: ADDRESS_2, value: 5n, data: "0x" },
    ];
    const batch = multiSendCallOnly(calls);
    expect(batch.to).to.equal(SAFE_V141.multiSendCallOnly.address);
    expect(batch.value).to.equal(0n);
    const [packed] = new ethers.Interface([
      "function multiSend(bytes transactions)",
    ]).decodeFunctionData("multiSend", batch.data);
    const expected = ethers.concat([
      "0x00",
      ADDRESS_1,
      ethers.toBeHex(0, 32),
      ethers.toBeHex(4, 32),
      "0x12345678",
      "0x00",
      ADDRESS_2,
      ethers.toBeHex(5, 32),
      ethers.toBeHex(0, 32),
    ]);
    expect((packed as string).toLowerCase()).to.equal(expected.toLowerCase());
  });
});
