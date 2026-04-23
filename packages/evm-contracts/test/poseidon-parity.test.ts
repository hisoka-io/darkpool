import { expect } from "chai";
import { ethers } from "hardhat";
import { Poseidon as TsPoseidon, toFr } from "@hisoka/wallets";
import {
    Poseidon2,
    Poseidon2__factory,
    Poseidon2Harness,
    Poseidon2Harness__factory,
} from "../typechain-types";

// parity between TS `@aztec/foundation/crypto` and the Solidity Yul sponge.
const KNOWN_HASH_2_1_2 =
    "0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383";

describe("Poseidon2 parity (Yul-backed) vs TypeScript reference", () => {
    let lib: Poseidon2;
    let harness: Poseidon2Harness;

    before(async () => {
        const Factory = (await ethers.getContractFactory(
            "Poseidon2"
        )) as unknown as Poseidon2__factory;
        lib = await Factory.deploy();
        const HarnessFactory = (await ethers.getContractFactory(
            "Poseidon2Harness"
        )) as unknown as Poseidon2Harness__factory;
        harness = await HarnessFactory.deploy();
    });

    it("hash_2(1,2) matches the published test vector", async () => {
        const got = await lib.hash_2(1n, 2n);
        expect(ethers.toBeHex(got, 32)).to.equal(KNOWN_HASH_2_1_2);
    });

    it("hash_1 matches TS Poseidon.hash([x])", async () => {
        for (const x of [1n, 2n, 42n, 1n << 200n]) {
            const ts = (await TsPoseidon.hash([toFr(x)])).toBigInt();
            const sol = await lib.hash_1(x);
            expect(sol).to.equal(ts, `hash_1(${x})`);
        }
    });

    it("hash_2 matches TS Poseidon.hash([x,y])", async () => {
        for (const [x, y] of [
            [0n, 0n],
            [1n, 2n],
            [3n, 4n],
            [12345n, 67890n],
        ] as [bigint, bigint][]) {
            const ts = (await TsPoseidon.hash([toFr(x), toFr(y)])).toBigInt();
            const sol = await lib.hash_2(x, y);
            expect(sol).to.equal(ts, `hash_2(${x},${y})`);
        }
    });

    it("hash_3 matches TS Poseidon.hash([x,y,z])", async () => {
        for (const [x, y, z] of [
            [1n, 2n, 3n],
            [0n, 0n, 0n],
            [11n, 22n, 33n],
        ] as [bigint, bigint, bigint][]) {
            const ts = (
                await TsPoseidon.hash([toFr(x), toFr(y), toFr(z)])
            ).toBigInt();
            const sol = await lib.hash_3(x, y, z);
            expect(sol).to.equal(ts, `hash_3(${x},${y},${z})`);
        }
    });

    it("variable-length hash matches TS reference for lengths 1..10", async () => {
        for (let n = 1; n <= 10; n++) {
            const inputs = Array.from({ length: n }, (_, i) => BigInt(i + 1));
            const ts = (
                await TsPoseidon.hash(inputs.map((v) => toFr(v)))
            ).toBigInt();
            const sol = await lib["hash(uint256[])"](inputs);
            expect(sol).to.equal(ts, `hash(len=${n})`);
        }
    });

    it("variable-length hash matches via the Poseidon2Lib internal path", async () => {
        for (const inputs of [
            [1n],
            [1n, 2n, 3n, 4n, 5n, 6n, 7n],
            [9n, 8n, 7n, 6n, 5n, 4n],
            Array.from({ length: 8 }, (_, i) => BigInt(100 + i)),
        ]) {
            const ts = (
                await TsPoseidon.hash(inputs.map((v) => toFr(v)))
            ).toBigInt();
            const sol = await harness.hashArray(inputs);
            expect(sol).to.equal(ts, `harness.hashArray(len=${inputs.length})`);
        }
    });

    it("is_variable_length=true appends the `1` domain separator", async () => {
        const inputs = [1n, 2n, 3n];
        const fixed = await harness.hashFixed(inputs);
        const variable = await harness.hashVariable(inputs);
        expect(fixed).to.not.equal(variable);
    });
});
