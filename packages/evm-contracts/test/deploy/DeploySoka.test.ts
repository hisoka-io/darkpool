import { expect } from "chai";
import { ethers } from "hardhat";
import * as fs from "fs";
import { deploySoka } from "../../scripts/deploy-soka";

async function withEnv<T>(
  env: Record<string, string>,
  body: () => Promise<T>,
): Promise<T> {
  const saved: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === "") delete process.env[k];
    else process.env[k] = v;
  }
  const realLog = console.log;
  console.log = () => undefined;
  try {
    return await body();
  } finally {
    console.log = realLog;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

describe("deploy-soka script", function () {
  it("deploys SOKA with the configured treasury, supply and owner, and records it", async function () {
    const [, treasury, owner] = await ethers.getSigners();
    const { record, latestFile, reused } = await withEnv(
      {
        SOKA_TREASURY: treasury.address,
        SOKA_SUPPLY: "250000000",
        SOKA_OWNER: owner.address,
      },
      deploySoka,
    );
    expect(reused).to.equal(false);

    const token = await ethers.getContractAt("SokaToken", record.token.address);
    const supply = ethers.parseEther("250000000");
    expect(await token.balanceOf(treasury.address)).to.equal(supply);
    expect(await token.totalSupply()).to.equal(supply);
    expect(await token.owner()).to.equal(owner.address);
    expect(record.token.totalSupply).to.equal(supply.toString());
    expect(record.constructorArgs).to.deep.equal([
      treasury.address,
      supply.toString(),
      owner.address,
    ]);
    expect(record.codeHash).to.equal(
      ethers.keccak256(await ethers.provider.getCode(record.token.address)),
    );
    expect(JSON.parse(fs.readFileSync(latestFile, "utf8"))).to.deep.equal(
      JSON.parse(JSON.stringify(record)),
    );
  });

  it("defaults the owner to the treasury", async function () {
    const [, treasury] = await ethers.getSigners();
    const { record } = await withEnv(
      { SOKA_TREASURY: treasury.address, SOKA_SUPPLY: "1", SOKA_OWNER: "" },
      deploySoka,
    );
    expect(record.token.owner).to.equal(treasury.address);
  });

  it("rejects a malformed supply and treasury before deploying anything", async function () {
    const [deployer] = await ethers.getSigners();
    const nonceBefore = await ethers.provider.getTransactionCount(
      deployer.address,
    );
    for (const [env, message] of [
      [{ SOKA_SUPPLY: "lots", SOKA_TREASURY: "" }, "SOKA_SUPPLY=lots"],
      [{ SOKA_SUPPLY: "0", SOKA_TREASURY: "" }, "must be positive"],
      [{ SOKA_SUPPLY: "1", SOKA_TREASURY: "0x1234" }, "not a valid address"],
      [
        { SOKA_SUPPLY: "1", SOKA_TREASURY: ethers.ZeroAddress },
        "must be non-zero",
      ],
    ] as const) {
      let error: unknown = null;
      try {
        await withEnv({ ...env }, deploySoka);
      } catch (e) {
        error = e;
      }
      expect(error, message).to.be.instanceOf(Error);
      expect((error as Error).message).to.contain(message);
    }
    expect(
      await ethers.provider.getTransactionCount(deployer.address),
    ).to.equal(nonceBefore);
  });
});
