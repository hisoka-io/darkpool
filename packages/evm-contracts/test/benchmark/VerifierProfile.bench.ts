import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { ethers } from "hardhat";
import {
  deployDarkPoolFixture,
  makeDeposit,
  mintSelfNote,
  evenYEphemeral,
  userSpendScalar,
  newSeededTree,
  COMPLIANCE_PK,
} from "../helpers/fixtures";
import { addressToFr, packParents } from "@hisoka/wallets";
import { proveDeposit, proveSplit } from "@hisoka/prover";
import { writeFileSync } from "fs";
import { HonkVerifier__factory } from "../../typechain-types/factories/contracts/verifiers/DepositVerifier.sol";
import { HonkVerifier__factory as KageVerifier__factory } from "../../typechain-types/factories/contracts/verifiers/KageVerifier.sol";
import { KAGE_PROOF, KAGE_PUBLIC_INPUTS } from "../integration/kageGolden";

// PROFILE=1 npx hardhat test test/benchmark/VerifierProfile.bench.ts
const run = process.env.PROFILE ? describe : describe.skip;

function calldataGas(hexData: string): number {
  const b = hexData.startsWith("0x") ? hexData.slice(2) : hexData;
  let g = 0;
  for (let i = 0; i < b.length; i += 2)
    g += b.slice(i, i + 2) === "00" ? 4 : 16;
  return g;
}

async function isolatedDepositVerifier() {
  const [deployer] = await ethers.getSigners();
  return new HonkVerifier__factory(deployer).deploy();
}

function report(
  op: string,
  full: bigint,
  verifyEst: bigint,
  cdVerify: number,
  cdFull: number,
  proofBytes: number,
  pubCount: number,
) {
  const INTRINSIC = 21000;
  const verifyInternal = Number(verifyEst) - INTRINSIC - cdVerify;
  const overhead = Number(full) - INTRINSIC - cdFull - verifyInternal;
  const f = Number(full);
  const pct = (n: number) => `${((100 * n) / f).toFixed(1)}%`;
  console.log(`\n=== ${op} gas split ===`);
  console.log(
    `proof=${proofBytes}B, publicInputs=${pubCount}, full=${f}, verifyEst=${verifyEst}`,
  );
  console.log(
    `  intrinsic        ${INTRINSIC.toString().padStart(9)}  ${pct(INTRINSIC)}`,
  );
  console.log(
    `  calldata         ${cdFull.toString().padStart(9)}  ${pct(cdFull)}`,
  );
  console.log(
    `  VERIFY internal  ${verifyInternal.toString().padStart(9)}  ${pct(verifyInternal)}`,
  );
  console.log(
    `  OVERHEAD (ours)  ${overhead.toString().padStart(9)}  ${pct(overhead)}`,
  );
}

run("Verifier profile: verify vs overhead", function () {
  this.timeout(1_800_000);

  it("deposit / withdraw / split split", async function () {
    const verifier = await isolatedDepositVerifier();

    // deposit: 1 insert + ERC20 pull
    {
      const { darkPool, token, alice } = await loadFixture(
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
      const proofDump = process.env["PROOF_DUMP"];
      if (proofDump) {
        writeFileSync(
          proofDump,
          JSON.stringify({
            proof: proof.proof,
            publicInputs: proof.publicInputs,
          }),
        );
      }
      const verifyEst = await verifier.verify.estimateGas(
        proof.proof,
        proof.publicInputs,
      );
      const cdV = calldataGas(
        (
          await verifier.verify.populateTransaction(
            proof.proof,
            proof.publicInputs,
          )
        ).data!,
      );
      await token.connect(alice).approve(await darkPool.getAddress(), 100n);
      const pop = await darkPool
        .connect(alice)
        .deposit.populateTransaction(proof.proof, proof.publicInputs);
      const rc = await (
        await darkPool.connect(alice).deposit(proof.proof, proof.publicInputs)
      ).wait();
      report(
        "deposit",
        rc!.gasUsed,
        verifyEst,
        cdV,
        calldataGas(pop.data!),
        (proof.proof.length - 2) / 2,
        proof.publicInputs.length,
      );
    }

    // split: 2 inserts, no ERC20
    {
      const { darkPool, token, alice } = await loadFixture(
        deployDarkPoolFixture,
      );
      const assetFr = addressToFr(await token.getAddress());
      const dep = await makeDeposit(darkPool, token, alice, 100n);
      const tree = await newSeededTree();
      await tree.insert(dep.commitment);
      const outParents = packParents([{ leafIndex: 1 }, { leafIndex: 0 }]);
      const out1 = await mintSelfNote(
        evenYEphemeral(111n),
        40n,
        dep.spendScalar,
        assetFr,
        outParents,
      );
      const out2 = await mintSelfNote(
        evenYEphemeral(222n),
        60n,
        dep.spendScalar,
        assetFr,
        outParents,
      );
      const proof = await proveSplit({
        compliancePk: COMPLIANCE_PK,
        noteIn: dep.built.note,
        spendScalar: dep.spendScalar,
        indexIn: 1,
        pathIn: tree.getMerklePath(1),
        noteOut1: out1.note,
        eph1: out1.eph,
        noteOut2: out2.note,
        eph2: out2.eph,
      });
      // split verifier differs; reuse deposit verifier only for calldata shape (verify gas is close across circuits)
      const pop = await darkPool
        .connect(alice)
        .split.populateTransaction(proof.proof, proof.publicInputs);
      const rc = await (
        await darkPool.connect(alice).split(proof.proof, proof.publicInputs)
      ).wait();
      console.log(
        `\n=== split full=${rc!.gasUsed} proof=${(proof.proof.length - 2) / 2}B pub=${proof.publicInputs.length} calldata=${calldataGas(pop.data!)} ===`,
      );
      console.log(
        "  (split has 2 inserts vs deposit's 1: full(split) - full(deposit) ~= 1 extra insert + 1 extra mint)",
      );
    }
  });

  // Isolated verify() gas of the deployed optimized 5.0.0 KageVerifier against the real native-bb swap_settle
  // golden proof. Measurement only (no assertion): re-measures the recorded Kage verify figure after the 5.0.0
  // --optimized regen. verifyInternal strips intrinsic + calldata so it is comparable across verifiers.
  it("kage swap_settle verify gas (optimized 5.0.0 KageVerifier)", async function () {
    const [deployer] = await ethers.getSigners();
    const verifier = await new KageVerifier__factory(deployer).deploy();
    const verifyEst = await verifier.verify.estimateGas(
      KAGE_PROOF,
      KAGE_PUBLIC_INPUTS,
    );
    const cdV = calldataGas(
      (
        await verifier.verify.populateTransaction(
          KAGE_PROOF,
          KAGE_PUBLIC_INPUTS,
        )
      ).data!,
    );
    const INTRINSIC = 21000;
    const verifyInternal = Number(verifyEst) - INTRINSIC - cdV;
    console.log(`\n=== kage swap_settle verify gas (optimized 5.0.0) ===`);
    console.log(
      `proof=${(KAGE_PROOF.length - 2) / 2}B, publicInputs=${KAGE_PUBLIC_INPUTS.length}`,
    );
    console.log(
      `  verify estimateGas ${Number(verifyEst).toString().padStart(9)}`,
    );
    console.log(`  calldata           ${cdV.toString().padStart(9)}`);
    console.log(
      `  VERIFY internal    ${verifyInternal.toString().padStart(9)}`,
    );
  });
});
