#!/usr/bin/env node
// Manual prove-time profiler (not in CI): median witness+prove ms per entrypoint as a markdown table.
// Run: `pnpm --filter @hisoka/prover benchmark` [out-file|BENCH_OUT]. Env: BB_THREADS, BENCH_ITERS.

import { UltraHonkBackend, Barretenberg } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { performance } from "perf_hooks";

import { Fr } from "@aztec/foundation/fields";
import { subOrder } from "@zk-kit/baby-jubjub";
import {
  leaf,
  computePsi,
  computeNullifier,
  deriveCek,
  publicKey,
  pubkeyOwner,
  isEvenY,
  packParents,
  LeanIMT,
} from "@hisoka/wallets";
import * as frost from "@hisoka/wallets/frost";
import { frostAccountDkg } from "@hisoka/wallets/unsafe-sim";

const __dirname = dirname(fileURLToPath(import.meta.url));
const TARGET_DIR = resolve(__dirname, "../../circuits/target");
const OUT_FILE = process.argv[2] ?? process.env.BENCH_OUT ?? null;
const THREADS = parseInt(process.env.BB_THREADS ?? "16", 10) || 16;
const ITERS = parseInt(process.env.BENCH_ITERS ?? "3", 10) || 3;

const ASSET_HEX = "0x1234567890123456789012345678901234567890";
const ASSET_BIG = 0x1234567890123456789012345678901234567890n;
const ASSET_FR = new Fr(ASSET_BIG);
const CX = "0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111";
const CY = "0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8";
const CPK = [BigInt(CX), BigInt(CY)];
const OWNER_2874 =
  "0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785";
const ZERO_PATH = Array.from({ length: 32 }, () => "0");
const ACCOUNT_CTX = 0x484f574cn;

function randSubgroupScalar() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  const s = acc % subOrder;
  return s === 0n ? 1n : s;
}

function evenYKeypair() {
  for (let i = 0; i < 256; i++) {
    const scalar = new Fr(randSubgroupScalar());
    const pub = publicKey(scalar);
    if (isEvenY(pub)) return { scalar, pub };
  }
  throw new Error("no even-y keypair sampled");
}

function pointHex(p) {
  return { x: "0x" + p[0].toString(16), y: "0x" + p[1].toString(16) };
}

function leafOf(n) {
  return leaf({
    noteVersion: new Fr(1n),
    assetId: ASSET_FR,
    noteType: new Fr(n.noteType),
    conditionsHash: new Fr(0n),
    value: n.value,
    owner: n.owner,
    psi: n.psi,
    parents: new Fr(n.parents),
  });
}

function marshalNote(n) {
  return {
    note_version: "1",
    asset_id: ASSET_HEX,
    note_type: n.noteType.toString(),
    conditions_hash: "0",
    value: n.value.toString(),
    owner: n.owner.toString(),
    psi: n.psi.toString(),
    parents: n.parents.toString(),
  };
}

async function frostSign(gpk, shares, signerIds, m) {
  const cs = frost.bjjCiphersuite;
  const msg = frost.encodeMessage(m);
  const nonceById = new Map();
  const commitments = [];
  for (const id of signerIds) {
    const secret = shares.get(id);
    const { nonces, commitment } = await frost.commit(
      cs,
      id,
      secret,
      crypto.getRandomValues(new Uint8Array(32)),
      crypto.getRandomValues(new Uint8Array(32)),
    );
    nonceById.set(id, nonces);
    commitments.push(commitment);
  }
  const rhos = await frost.bindingFactors(cs, gpk, msg, commitments);
  const R = frost.groupCommitment(cs, commitments, rhos);
  const zShares = [];
  for (const id of signerIds) {
    zShares.push(
      await frost.signShare(
        cs,
        id,
        nonceById.get(id),
        shares.get(id),
        gpk,
        msg,
        commitments,
      ),
    );
  }
  const sig = frost.aggregate(cs, R, zShares);
  if (!(await frost.verify(cs, gpk, msg, sig)))
    throw new Error("frostSign: signature failed to verify");
  return { R: sig.R, z: sig.z };
}

async function selfPsi(v, member, startJ) {
  const tag = await frost.canonicalMultisigSelfTag(v, member, startJ);
  const psi = await computePsi(deriveCek(tag.eph, CPK));
  return { eph: tag.eph, j: tag.j, psi };
}

// Standard-op inputs, byte-identical to the circuit KAT fixtures.

const stdInputs = {
  deposit: () => ({
    compliance_pubkey_x: CX,
    compliance_pubkey_y: CY,
    note: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "100",
      owner: OWNER_2874,
      psi: "0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731",
      parents: "0",
    },
    eph: "5",
  }),
  withdraw: () => ({
    withdraw_value: "40",
    _recipient: ASSET_HEX,
    _intent_hash: "0",
    compliance_pubkey_x: CX,
    compliance_pubkey_y: CY,
    old_note: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "100",
      owner: OWNER_2874,
      psi: "0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731",
      parents: "0",
    },
    spend_scalar: "789",
    old_note_index: "0",
    old_note_path: ZERO_PATH,
    change_note: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "60",
      owner: OWNER_2874,
      psi: "0x094cb623c946044df25c471166b70569c57b22e5b6af36baeb1349c48a4ba160",
      parents: "0",
    },
    change_eph: "8",
  }),
  transfer: () => {
    const inPub = {
      x: "0x1b16e357953d68d73398c838aa883cc65ddae2aef75a4bc437e4232afdbe43c8",
      y: "0x02d7ee0be055310d2895c5ed5090a8aa1c700e73c64294f1e817ec77f46b4fdc",
    };
    return {
      compliance_pubkey_x: CX,
      compliance_pubkey_y: CY,
      recipient_in_pub: inPub,
      old_note: {
        note_version: "1",
        asset_id: ASSET_HEX,
        note_type: "0",
        conditions_hash: "0",
        value: "100",
        owner: OWNER_2874,
        psi: "0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731",
        parents: "0",
      },
      spend_scalar: "789",
      old_note_index: "0",
      old_note_path: ZERO_PATH,
      memo_note: {
        note_version: "1",
        asset_id: ASSET_HEX,
        note_type: "0",
        conditions_hash: "0",
        value: "40",
        owner:
          "0x1113074e2fb269d979ad2b64e6fe70b1967c67b007b706600603b847306aefe3",
        psi: "0x2ae9db6316c6ee380fa8c43bed4df9818e3207ff00b3cfb15a5ee1ef925f456d",
        parents: "0",
      },
      memo_eph: "0x378",
      change_note: {
        note_version: "1",
        asset_id: ASSET_HEX,
        note_type: "0",
        conditions_hash: "0",
        value: "60",
        owner: OWNER_2874,
        psi: "0x0b78b93ec011fe550e1f125af7f7fa286a69a839cca56d248fa04abfe9312f7b",
        parents: "0",
      },
      change_eph: "9",
    };
  },
  split: () => ({
    compliance_pubkey_x: CX,
    compliance_pubkey_y: CY,
    note_in: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "100",
      owner: OWNER_2874,
      psi: "0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731",
      parents: "0",
    },
    spend_scalar: "789",
    index_in: "0",
    path_in: ZERO_PATH,
    note_out_1: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "40",
      owner: OWNER_2874,
      psi: "0x017131231dbfc29f6bdfb775d6e859c148b7379acc2844380ff9f824fa7073ad",
      parents: "0",
    },
    eph_1: "15",
    note_out_2: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "60",
      owner: OWNER_2874,
      psi: "0x1fc1420fa8dd294ee9feaa5067000d40945bdc796e47ce5dfbfa4cbb4210ef8d",
      parents: "0",
    },
    eph_2: "20",
  }),
  join: () => ({
    compliance_pubkey_x: CX,
    compliance_pubkey_y: CY,
    note_a: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "100",
      owner: OWNER_2874,
      psi: "0x271c8cc2341079e393fa781a5e7b4664b27b649d4f0277a53110b7937ed9fada",
      parents: "0",
    },
    spend_scalar_a: "789",
    index_a: "0",
    path_a: [
      "0x2065744fd5ee65c5747ac8277513f27eadda10f02f9b5bb58d28131ec808b102",
      ...Array.from({ length: 31 }, () => "0"),
    ],
    note_b: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "50",
      owner: OWNER_2874,
      psi: "0x22c2ddd73188e4c766c528228312ae28595623aba1a5c5341a8f7154943842d3",
      parents: "0",
    },
    spend_scalar_b: "789",
    index_b: "1",
    path_b: [
      "0x1a6b6e47769e1f5de94e5ce9f3094b49cc9967d5ba3ef90df6af6598ca26d41b",
      ...Array.from({ length: 31 }, () => "0"),
    ],
    note_out: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "150",
      owner: OWNER_2874,
      psi: "0x09fb1bde9d635c97fa5a0884a8a38d961cec75db95e76629aabec8b63baec84a",
      parents: "0x100000000",
    },
    eph_out: "28",
  }),
  public_claim: () => ({
    memo_id:
      "0x0731300919ae74d1507ab3b22cac576da8c86deb8ddc11f24317b861f17f6f93",
    compliance_pubkey_x: CX,
    compliance_pubkey_y: CY,
    current_timestamp: "0",
    val: "100",
    asset_id: ASSET_HEX,
    timelock: "0",
    owner_x:
      "0x2a39f6a9afe8c569977ec299af985e30142d18ee451008ffd13fc0a2a36cf54e",
    owner_y:
      "0x1d5a43dc73fe0493cce521cc92a4d34d4837214ce47871c587c567d2d0c72c8f",
    salt: "0x004996117eaf098d97b6a42a8ec9c27b5ec30cdca90ffbdb6792eb4733c982d4",
    recipient_sk: "0x3039",
    note_out: {
      note_version: "1",
      asset_id: ASSET_HEX,
      note_type: "0",
      conditions_hash: "0",
      value: "100",
      owner: OWNER_2874,
      psi: "0x2b15d2a7e6a394714f0489affd8fcb29292b35d148d26453116782a6672edd12",
      parents: "0",
    },
    eph: "31",
  }),
};

// Multisig-op inputs: real FROST-signed witnesses.

async function withdrawMultisigInputs() {
  const acct = await frostAccountDkg(5, 3, ACCOUNT_CTX);
  const v = new Fr(acct.viewKey);
  const member = acct.qual[0];
  const inPsi = await computePsi(deriveCek(new Fr(randSubgroupScalar()), CPK));
  const oldNote = {
    noteType: 1n,
    value: 1000n,
    owner: acct.owner,
    psi: inPsi,
    parents: 0n,
  };
  const root = await leafOf(oldNote);
  const nf = await computeNullifier(inPsi, new Fr(0n));
  const ch = await selfPsi(v, member, 0n);
  const chNote = {
    noteType: 1n,
    value: 700n,
    owner: acct.owner,
    psi: ch.psi,
    parents: 0n,
  };
  const chLeaf = await leafOf(chNote);
  const recipient = new Fr(0x00c0ffee00c0ffee00c0ffee00c0ffee00c0ffeen);
  const m = await frost.msgWithdraw({
    root: root.toBigInt(),
    nullifier: nf.toBigInt(),
    changeLeaf: chLeaf.toBigInt(),
    publicOut: 300n,
    asset: ASSET_BIG,
    recipient: recipient.toBigInt(),
    intentHash: 0n,
  });
  const sig = await frostSign(acct.gpk, acct.shares, acct.qual.slice(0, 3), m);
  return {
    withdraw_value: "300",
    recipient: recipient.toString(),
    intent_hash: "0",
    compliance_pubkey_x: CX,
    compliance_pubkey_y: CY,
    gpk: pointHex(acct.gpk),
    frost_r: pointHex(sig.R),
    frost_z: sig.z.toString(),
    old_note: marshalNote(oldNote),
    old_note_index: "0",
    old_note_path: ZERO_PATH,
    change_note: marshalNote(chNote),
    change_eph: ch.eph.toString(),
  };
}

async function transferMultisigInputs() {
  const acct = await frostAccountDkg(5, 3, ACCOUNT_CTX);
  const v = new Fr(acct.viewKey);
  const member = acct.qual[0];
  const inPsi = await computePsi(deriveCek(new Fr(randSubgroupScalar()), CPK));
  const oldNote = {
    noteType: 1n,
    value: 100n,
    owner: acct.owner,
    psi: inPsi,
    parents: 0n,
  };
  const root = await leafOf(oldNote);
  const nf = await computeNullifier(inPsi, new Fr(0n));
  const recip = evenYKeypair();
  const memoEph = new Fr(randSubgroupScalar());
  const memoPsi = await computePsi(deriveCek(memoEph, CPK));
  const memoNote = {
    noteType: 0n,
    value: 40n,
    owner: await pubkeyOwner(recip.pub),
    psi: memoPsi,
    parents: 0n,
  };
  const memoLeaf = await leafOf(memoNote);
  const ch = await selfPsi(v, member, 0n);
  const chNote = {
    noteType: 1n,
    value: 60n,
    owner: acct.owner,
    psi: ch.psi,
    parents: 0n,
  };
  const chLeaf = await leafOf(chNote);
  const m = await frost.msgTransfer({
    root: root.toBigInt(),
    nullifier: nf.toBigInt(),
    memoLeaf: memoLeaf.toBigInt(),
    changeLeaf: chLeaf.toBigInt(),
    asset: ASSET_BIG,
  });
  const sig = await frostSign(acct.gpk, acct.shares, acct.qual.slice(0, 3), m);
  return {
    compliance_pubkey_x: CX,
    compliance_pubkey_y: CY,
    gpk: pointHex(acct.gpk),
    frost_r: pointHex(sig.R),
    frost_z: sig.z.toString(),
    recipient_in_pub: pointHex(recip.pub),
    old_note: marshalNote(oldNote),
    old_note_index: "0",
    old_note_path: ZERO_PATH,
    memo_note: marshalNote(memoNote),
    memo_eph: memoEph.toString(),
    change_note: marshalNote(chNote),
    change_eph: ch.eph.toString(),
  };
}

async function splitMultisigInputs() {
  const acct = await frostAccountDkg(5, 3, ACCOUNT_CTX);
  const v = new Fr(acct.viewKey);
  const member = acct.qual[0];
  const inPsi = await computePsi(deriveCek(new Fr(randSubgroupScalar()), CPK));
  const inNote = {
    noteType: 1n,
    value: 100n,
    owner: acct.owner,
    psi: inPsi,
    parents: 0n,
  };
  const root = await leafOf(inNote);
  const nf = await computeNullifier(inPsi, new Fr(0n));
  const a = await selfPsi(v, member, 0n);
  const b = await selfPsi(v, member, a.j + 1n);
  const o1 = {
    noteType: 1n,
    value: 40n,
    owner: acct.owner,
    psi: a.psi,
    parents: 0n,
  };
  const o2 = {
    noteType: 1n,
    value: 60n,
    owner: acct.owner,
    psi: b.psi,
    parents: 0n,
  };
  const l1 = await leafOf(o1);
  const l2 = await leafOf(o2);
  const m = await frost.msgSplit({
    root: root.toBigInt(),
    nullifier: nf.toBigInt(),
    out1Leaf: l1.toBigInt(),
    out2Leaf: l2.toBigInt(),
    asset: ASSET_BIG,
  });
  const sig = await frostSign(acct.gpk, acct.shares, acct.qual.slice(0, 3), m);
  return {
    compliance_pubkey_x: CX,
    compliance_pubkey_y: CY,
    gpk: pointHex(acct.gpk),
    frost_r: pointHex(sig.R),
    frost_z: sig.z.toString(),
    note_in: marshalNote(inNote),
    index_in: "0",
    path_in: ZERO_PATH,
    note_out_1: marshalNote(o1),
    eph_1: a.eph.toString(),
    note_out_2: marshalNote(o2),
    eph_2: b.eph.toString(),
  };
}

async function joinMultisigInputs() {
  const acct = await frostAccountDkg(5, 3, ACCOUNT_CTX);
  const v = new Fr(acct.viewKey);
  const member = acct.qual[0];
  const a = await selfPsi(v, member, 0n);
  const b = await selfPsi(v, member, a.j + 1n);
  const noteA = {
    noteType: 1n,
    value: 100n,
    owner: acct.owner,
    psi: a.psi,
    parents: 0n,
  };
  const noteB = {
    noteType: 1n,
    value: 50n,
    owner: acct.owner,
    psi: b.psi,
    parents: 0n,
  };
  const tree = new LeanIMT(32);
  await tree.insert(await leafOf(noteA));
  await tree.insert(await leafOf(noteB));
  const root = tree.getRoot();
  const pathA = tree.getMerklePath(0).map((f) => f.toString());
  const pathB = tree.getMerklePath(1).map((f) => f.toString());
  const nfA = await computeNullifier(a.psi, new Fr(0n));
  const nfB = await computeNullifier(b.psi, new Fr(1n));
  const out = await selfPsi(v, member, b.j + 1n);
  const outNote = {
    noteType: 1n,
    value: 150n,
    owner: acct.owner,
    psi: out.psi,
    parents: packParents([{ leafIndex: 0 }, { leafIndex: 1 }]).toBigInt(),
  };
  const outLeaf = await leafOf(outNote);
  const m = await frost.msgJoin({
    root: root.toBigInt(),
    nullifierA: nfA.toBigInt(),
    nullifierB: nfB.toBigInt(),
    outLeaf: outLeaf.toBigInt(),
    asset: ASSET_BIG,
  });
  const sigA = await frostSign(acct.gpk, acct.shares, acct.qual.slice(0, 3), m);
  const sigB = await frostSign(acct.gpk, acct.shares, acct.qual.slice(0, 3), m);
  return {
    compliance_pubkey_x: CX,
    compliance_pubkey_y: CY,
    gpk_a: pointHex(acct.gpk),
    frost_r_a: pointHex(sigA.R),
    frost_z_a: sigA.z.toString(),
    note_a: marshalNote(noteA),
    index_a: "0",
    path_a: pathA,
    gpk_b: pointHex(acct.gpk),
    frost_r_b: pointHex(sigB.R),
    frost_z_b: sigB.z.toString(),
    note_b: marshalNote(noteB),
    index_b: "1",
    path_b: pathB,
    note_out: marshalNote(outNote),
    eph_out: out.eph.toString(),
  };
}

const OPS = [
  {
    name: "deposit",
    circuit: "deposit",
    build: async () => stdInputs.deposit(),
  },
  {
    name: "withdraw",
    circuit: "withdraw",
    build: async () => stdInputs.withdraw(),
  },
  {
    name: "transfer",
    circuit: "transfer",
    build: async () => stdInputs.transfer(),
  },
  { name: "split", circuit: "split", build: async () => stdInputs.split() },
  { name: "join", circuit: "join", build: async () => stdInputs.join() },
  {
    name: "public_claim",
    circuit: "public_claim",
    build: async () => stdInputs.public_claim(),
  },
  {
    name: "withdraw_multisig",
    circuit: "withdraw_multisig",
    build: withdrawMultisigInputs,
  },
  {
    name: "transfer_multisig",
    circuit: "transfer_multisig",
    build: transferMultisigInputs,
  },
  {
    name: "split_multisig",
    circuit: "split_multisig",
    build: splitMultisigInputs,
  },
  {
    name: "join_multisig",
    circuit: "join_multisig",
    build: joinMultisigInputs,
  },
];

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

async function main() {
  const api = await Barretenberg.new({ threads: THREADS });
  const rows = [];
  for (const op of OPS) {
    const artifact = resolve(TARGET_DIR, `${op.circuit}.json`);
    if (!existsSync(artifact)) {
      throw new Error(
        `missing circuit artifact ${artifact} (run the build first)`,
      );
    }
    const circuitJson = JSON.parse(readFileSync(artifact, "utf8"));
    const noir = new Noir(circuitJson);
    const backend = new UltraHonkBackend(circuitJson.bytecode, api);
    const inputs = await op.build();

    const witnessMs = [];
    const proveMs = [];
    let publicCount = 0;
    for (let i = 0; i < ITERS; i++) {
      const t0 = performance.now();
      const { witness } = await noir.execute(inputs);
      const t1 = performance.now();
      const { publicInputs } = await backend.generateProof(witness, {
        verifierTarget: "evm",
      });
      const t2 = performance.now();
      witnessMs.push(t1 - t0);
      proveMs.push(t2 - t1);
      publicCount = publicInputs.length;
    }
    const w = Math.round(median(witnessMs));
    const p = Math.round(median(proveMs));
    rows.push({
      name: op.name,
      witness: w,
      prove: p,
      total: w + p,
      publicCount,
    });
    process.stderr.write(
      `${op.name.padEnd(18)} witness ${w} ms | prove ${p} ms | total ${w + p} ms | ${publicCount} public inputs\n`,
    );
  }
  await api.destroy();

  const header =
    "## Per-op prove time (Part D)\n\n" +
    `bb.js UltraHonk (verifierTarget evm), BB_THREADS=${THREADS}, median of ${ITERS} iterations. ` +
    "witness = noir.execute; prove = backend.generateProof.\n\n" +
    "| op | witness (ms) | prove (ms) | total (ms) | public inputs |\n" +
    "|----|-------------:|-----------:|-----------:|--------------:|\n" +
    rows
      .map(
        (r) =>
          `| ${r.name} | ${r.witness} | ${r.prove} | ${r.total} | ${r.publicCount} |`,
      )
      .join("\n") +
    "\n";

  if (!OUT_FILE) {
    process.stdout.write("\n" + header);
    return;
  }
  const marker = "\n## Per-op prove time";
  let doc = existsSync(OUT_FILE) ? readFileSync(OUT_FILE, "utf8") : "";
  const cut = doc.indexOf(marker);
  if (cut !== -1) doc = doc.slice(0, cut).replace(/\s+$/, "") + "\n";
  const body = doc ? doc.replace(/\s+$/, "") + "\n\n" + header : header;
  writeFileSync(OUT_FILE, body);
  process.stderr.write(`\nWrote Per-op prove time table to ${OUT_FILE}\n`);
}

main().catch((e) => {
  process.stderr.write(`benchmark failed: ${e?.stack ?? e}\n`);
  process.exit(1);
});
