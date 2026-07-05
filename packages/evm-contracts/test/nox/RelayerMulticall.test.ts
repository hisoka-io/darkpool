import { expect } from "chai";
import { ethers } from "hardhat";
import {
  RelayerMulticall,
  MockTarget,
  RelayerMulticall__factory,
  MockTarget__factory,
} from "../../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("RelayerMulticall", function () {
  let multicall: RelayerMulticall;
  let mockTarget: MockTarget;
  let owner: SignerWithAddress;

  beforeEach(async function () {
    [owner] = await ethers.getSigners();

    const RelayerMulticallFactory = (await ethers.getContractFactory(
      "RelayerMulticall",
    )) as unknown as RelayerMulticall__factory;
    multicall = await RelayerMulticallFactory.deploy();

    const MockTargetFactory = (await ethers.getContractFactory(
      "MockTarget",
    )) as unknown as MockTarget__factory;
    mockTarget = await MockTargetFactory.deploy();
  });

  it("should execute a single successful call", async function () {
    const message = "Hello";
    const callData = mockTarget.interface.encodeFunctionData("successFn", [
      message,
    ]);

    const calls = [
      {
        target: await mockTarget.getAddress(),
        data: callData,
        value: 0,
        requireSuccess: true,
      },
    ];

    await expect(multicall.multicall(calls))
      .to.emit(multicall, "CallExecuted")
      .withArgs(0, true, (hexString: string) => {
        const decoded = ethers.AbiCoder.defaultAbiCoder().decode(
          ["string"],
          hexString,
        );
        return decoded[0] === message;
      });
  });

  it("should revert if a requireSuccess call fails (Atomic Fail)", async function () {
    const message = "Boom";
    const failData = mockTarget.interface.encodeFunctionData("failFn", [
      message,
    ]);

    const calls = [
      {
        target: await mockTarget.getAddress(),
        data: failData,
        value: 0,
        requireSuccess: true,
      },
    ];

    await expect(multicall.multicall(calls)).to.be.revertedWith(message);
  });

  it("should NOT revert if a requireSuccess=false call fails (partial success)", async function () {
    const successMsg = "I worked";
    const failMsg = "I failed";

    const successData = mockTarget.interface.encodeFunctionData("successFn", [
      successMsg,
    ]);
    const failData = mockTarget.interface.encodeFunctionData("failFn", [
      failMsg,
    ]);

    const calls = [
      {
        target: await mockTarget.getAddress(),
        data: successData,
        value: 0,
        requireSuccess: true, // critical
      },
      {
        target: await mockTarget.getAddress(),
        data: failData,
        value: 0,
        requireSuccess: false, // non-critical
      },
    ];

    const tx = await multicall.multicall(calls);
    await tx.wait();

    // Expect CallExecuted(0, true), CallFailed(1), CallExecuted(1, false)
    await expect(tx)
      .to.emit(multicall, "CallExecuted")
      .withArgs(0, true, (_d: string) => true);
    await expect(tx).to.emit(multicall, "CallFailed");
  });

  it("should forward value correctly", async function () {
    const value = ethers.parseEther("1.0");
    const successData = mockTarget.interface.encodeFunctionData("successFn", [
      "ValueTest",
    ]);

    const calls = [
      {
        target: await mockTarget.getAddress(),
        data: successData,
        value: value,
        requireSuccess: true,
      },
    ];

    await expect(
      multicall.multicall(calls, { value: value }),
    ).to.changeEtherBalances([owner, mockTarget], [-value, value]);
  });

  it("should revert if msg.value does not equal the sum of call values", async function () {
    const successData = mockTarget.interface.encodeFunctionData("successFn", [
      "MismatchTest",
    ]);

    const calls = [
      {
        target: await mockTarget.getAddress(),
        data: successData,
        value: ethers.parseEther("1.0"),
        requireSuccess: true,
      },
    ];

    await expect(
      multicall.multicall(calls, { value: ethers.parseEther("0.5") }),
    ).to.be.revertedWithCustomError(multicall, "ValueMismatch");
  });

  it("should revert if requireSuccess=true call fails with no reason", async function () {
    const failData = mockTarget.interface.encodeFunctionData("failNoReason");

    const calls = [
      {
        target: await mockTarget.getAddress(),
        data: failData,
        value: 0,
        requireSuccess: true,
      },
    ];

    await expect(multicall.multicall(calls)).to.be.revertedWithCustomError(
      multicall,
      "CriticalCallFailed",
    );
  });

  describe("Edge Cases", function () {
    it("should handle large payload size (100KB)", async function () {
      const largeString = "a".repeat(100 * 1024);
      const callData = mockTarget.interface.encodeFunctionData("successFn", [
        largeString,
      ]);

      const calls = [
        {
          target: await mockTarget.getAddress(),
          data: callData,
          value: 0,
          requireSuccess: true,
        },
      ];

      await expect(multicall.multicall(calls))
        .to.emit(multicall, "CallExecuted")
        .withArgs(0, true, (_hexString: string) => {
          // Skip full decode (heavy); emission alone proves no revert
          return true;
        });
    });

    it("should recover from first call failure and execute second call", async function () {
      const failMsg = "First Fail";
      const successMsg = "Second Success";

      const failData = mockTarget.interface.encodeFunctionData("failFn", [
        failMsg,
      ]);
      const successData = mockTarget.interface.encodeFunctionData("successFn", [
        successMsg,
      ]);

      const calls = [
        {
          target: await mockTarget.getAddress(),
          data: failData,
          value: 0,
          requireSuccess: false, // Critical: MUST be false to continue
        },
        {
          target: await mockTarget.getAddress(),
          data: successData,
          value: 0,
          requireSuccess: true,
        },
      ];

      const tx = await multicall.multicall(calls);

      // Verify events: 0->Fail, 1->Success
      await expect(tx).to.emit(multicall, "CallFailed");
      await expect(tx)
        .to.emit(multicall, "CallExecuted")
        .withArgs(1, true, (_d: string) => true);
    });

    it("should handle calls to invalid targets (destructed or EOA)", async function () {
      // Calling a random address (EOA) succeeds with no return data
      const randomAddr = ethers.Wallet.createRandom().address;
      const calls = [
        {
          target: randomAddr,
          data: "0x1234",
          value: 0,
          requireSuccess: true,
        },
      ];

      const tx = await multicall.multicall(calls);
      await expect(tx)
        .to.emit(multicall, "CallExecuted")
        .withArgs(0, true, "0x");
    });
  });
});
