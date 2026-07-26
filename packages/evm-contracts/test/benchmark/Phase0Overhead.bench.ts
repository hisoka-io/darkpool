import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import { BytesLike } from "ethers";
import {
  deployDarkPoolFixture,
  mintSelfNote,
  evenYEphemeral,
  userSpendScalar,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { addressToFr } from "@hisoka/wallets";
import { proveDeposit } from "@hisoka/prover";

// PHASE0=1 npx hardhat test test/benchmark/Phase0Overhead.bench.ts
// Verify-vs-overhead gas split: the first deposit into a fresh tree, run once against the real verifier and once
// against the no-op StubVerifier, so identical tree state gives a clean delta.
const run = process.env.PHASE0 ? describe : describe.skip;

async function firstDepositGas(useStub: boolean): Promise<bigint> {
  const { darkPool, token, alice, deployer } = await loadFixture(
    deployDarkPoolFixture,
  );
  const assetFr = addressToFr(await token.getAddress());
  const spendScalar = await userSpendScalar(alice.address);
  const eph = evenYEphemeral(101n);
  const built = await mintSelfNote(eph, 100n, spendScalar, assetFr);
  const proof = await proveDeposit({
    compliancePk: COMPLIANCE_PK,
    note: built.note,
    eph,
  });

  let proofBytes: BytesLike = proof.proof;
  if (useStub) {
    const stub = await (
      await ethers.getContractFactory("StubVerifier")
    ).deploy();
    // CIRCUIT_DEPOSIT = 0; deployer holds UPGRADER_ROLE from initialize.
    await darkPool.connect(deployer).setVerifier(0, await stub.getAddress());
    proofBytes = "0x";
  }

  await token.connect(alice).approve(await darkPool.getAddress(), 100n);
  const rc = await (
    await darkPool.connect(alice).deposit(proofBytes, proof.publicInputs)
  ).wait();
  return rc!.gasUsed;
}

run("Phase 0: verify vs overhead (mock no-op verifier)", function () {
  this.timeout(600_000);

  it("deposit split", async function () {
    const full = await firstDepositGas(false);
    const overhead = await firstDepositGas(true);
    const verify = full - overhead;
    const pct = (n: bigint) =>
      `${((100 * Number(n)) / Number(full)).toFixed(1)}%`;
    console.log(`\n=== Phase 0: deposit verify vs overhead (cancun) ===`);
    console.log(`  FULL action (real verifier) = ${full}`);
    console.log(
      `  OVERHEAD (stub verify)      = ${overhead}   ${pct(overhead)}`,
    );
    console.log(`  in-context VERIFY           = ${verify}   ${pct(verify)}`);
  });
});
