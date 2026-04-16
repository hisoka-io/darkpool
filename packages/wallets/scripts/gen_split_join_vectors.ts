import {
  NotePlaintext,
  encryptNoteDeposit,
  toFr,
  addressToFr,
  deriveSharedSecret,
  Poseidon,
  LeanIMT,
  Kdf,
} from "../src";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { Fr } from "@aztec/foundation/fields";
import { packToNoir, fmt } from "./lib/helpers.js";

async function main() {
  console.log("--- GENERATING SPLIT & JOIN VECTORS ---\n");
  const COMPLIANCE_PK = mulPointEscalar(Base8, 987654321n);
  const ASSET_ID = addressToFr("0x1234567890123456789012345678901234567890");

  const tree = new LeanIMT(32);

  async function setupNote(val: bigint, nonceVal: bigint, index: number) {
    const note: NotePlaintext = {
      value: toFr(val),
      asset_id: ASSET_ID,
      secret: toFr(1000n + nonceVal),
      nullifier: toFr(2000n + nonceVal),
      timelock: toFr(0n),
      hashlock: toFr(0n),
    };
    const nonce = toFr(nonceVal);
    const skView = toFr(555n);

    const res = await encryptNoteDeposit(skView, nonce, note, COMPLIANCE_PK);

    const packedFrs = [];
    let idx = 0;
    for (let p = 0; p < 7; p++) {
      let val = 0n;
      const bytes = p < 6 ? 31 : 22;
      let power = 1n;
      for (let i = 0; i < bytes; i++) {
        val += BigInt(res.ciphertext[idx]) * power;
        power *= 256n;
        idx++;
      }
      packedFrs.push(new Fr(val));
    }
    const commitment = await Poseidon.hash(packedFrs);

    await tree.insert(commitment);

    const ephemeralSk = await Kdf.derive("hisoka.ephemeral", skView, nonce);
    const sharedSecret = await deriveSharedSecret(ephemeralSk, COMPLIANCE_PK);
    const nullifier = await Poseidon.hashScalar(note.nullifier);

    return { note, sharedSecret, index, commitment, nullifier };
  }

  // ======================================================
  // SCENARIO 1: JOIN (Note A + Note B -> Note Out)
  // ======================================================
  console.log("[Setup] Creating Note A...");
  const noteA = await setupNote(100n, 10n, 0);
  console.log("[Setup] Creating Note B...");
  const noteB = await setupNote(50n, 11n, 1);

  const rootJoin = tree.getRoot();

  const pathA = Array(32).fill(new Fr(0n));
  pathA[0] = noteB.commitment;

  const pathB = Array(32).fill(new Fr(0n));
  pathB[0] = noteA.commitment;

  const noteOutJoin: NotePlaintext = {
    value: toFr(150n),
    asset_id: ASSET_ID,
    secret: toFr(999n),
    nullifier: toFr(888n),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };

  const resJoinOut = await encryptNoteDeposit(
    toFr(111n),
    toFr(1n),
    noteOutJoin,
    COMPLIANCE_PK,
  );

  const skOutJoin = resJoinOut.ephemeral_sk_used;

  console.log("// [JOIN] COPY INTO packages/circuits/join/src/main.nr");
  console.log(`
    let merkle_root = ${fmt(rootJoin)};
    let current_timestamp = 0;
    let compliance_pubkey_x = ${fmt(COMPLIANCE_PK[0])};
    let compliance_pubkey_y = ${fmt(COMPLIANCE_PK[1])};

    let note_a = Note {
        asset_id: ${fmt(noteA.note.asset_id)}, value: ${fmt(noteA.note.value)},
        secret: ${fmt(noteA.note.secret)}, nullifier: ${fmt(noteA.note.nullifier)},
        timelock: 0, hashlock: 0
    };
    let secret_a = ${fmt(noteA.sharedSecret)};
    let index_a = 0;
    let path_a = [${pathA.map((p) => p.toString()).join(", ")}];
    let preimage_a = 0;

    let note_b = Note {
        asset_id: ${fmt(noteB.note.asset_id)}, value: ${fmt(noteB.note.value)},
        secret: ${fmt(noteB.note.secret)}, nullifier: ${fmt(noteB.note.nullifier)},
        timelock: 0, hashlock: 0
    };
    let secret_b = ${fmt(noteB.sharedSecret)};
    let index_b = 1;
    let path_b = [${pathB.map((p) => p.toString()).join(", ")}];
    let preimage_b = 0;

    let note_out = Note {
        asset_id: ${fmt(noteOutJoin.asset_id)}, value: ${fmt(noteOutJoin.value)},
        secret: ${fmt(noteOutJoin.secret)}, nullifier: ${fmt(noteOutJoin.nullifier)},
        timelock: 0, hashlock: 0
    };
    let sk_out = ${fmt(skOutJoin)}; // Matches enc

    let exp_nf_a = ${fmt(noteA.nullifier)};
    let exp_nf_b = ${fmt(noteB.nullifier)};
    let exp_ct = ${packToNoir(resJoinOut.ciphertext)};

    let (nf_a, nf_b, _, _, ct, _) = main(
        merkle_root, current_timestamp, compliance_pubkey_x, compliance_pubkey_y,
        note_a, secret_a, index_a, path_a, preimage_a,
        note_b, secret_b, index_b, path_b, preimage_b,
        note_out, sk_out
    );

    assert(nf_a == exp_nf_a);
    assert(nf_b == exp_nf_b);
    assert(ct == exp_ct);
    `);

  // ======================================================
  // SCENARIO 2: SPLIT
  // ======================================================
  console.log("[Setup] Creating Note C...");
  const noteC = await setupNote(100n, 12n, 2);
  const rootSplit = tree.getRoot();

  const hashAB = await Poseidon.hash([noteA.commitment, noteB.commitment]);
  const pathC = Array(32).fill(new Fr(0n));
  pathC[0] = new Fr(0n);
  pathC[1] = hashAB;

  const out1: NotePlaintext = {
    ...noteOutJoin,
    value: toFr(40n),
    nullifier: toFr(111n),
  };
  const out2: NotePlaintext = {
    ...noteOutJoin,
    value: toFr(60n),
    nullifier: toFr(222n),
  };

  const res1 = await encryptNoteDeposit(
    toFr(1n),
    toFr(1n),
    out1,
    COMPLIANCE_PK,
  );
  const res2 = await encryptNoteDeposit(
    toFr(1n),
    toFr(2n),
    out2,
    COMPLIANCE_PK,
  );

  const sk1 = res1.ephemeral_sk_used;
  const sk2 = res2.ephemeral_sk_used;

  console.log("// [SPLIT] COPY INTO packages/circuits/split/src/main.nr");
  console.log(`
    let merkle_root = ${fmt(rootSplit)};
    let current_timestamp = 0;
    let compliance_pubkey_x = ${fmt(COMPLIANCE_PK[0])};
    let compliance_pubkey_y = ${fmt(COMPLIANCE_PK[1])};

    let note_in = Note {
        asset_id: ${fmt(noteC.note.asset_id)}, value: ${fmt(noteC.note.value)},
        secret: ${fmt(noteC.note.secret)}, nullifier: ${fmt(noteC.note.nullifier)},
        timelock: 0, hashlock: 0
    };
    let secret_in = ${fmt(noteC.sharedSecret)};
    let index_in = 2;
    let path_in = [${pathC.map((p) => p.toString()).join(", ")}];
    let preimage_in = 0;

    let note_out_1 = Note {
        asset_id: ${fmt(out1.asset_id)}, value: ${fmt(out1.value)},
        secret: ${fmt(out1.secret)}, nullifier: ${fmt(out1.nullifier)},
        timelock: 0, hashlock: 0
    };
    let sk_out_1 = ${fmt(sk1)};

    let note_out_2 = Note {
        asset_id: ${fmt(out2.asset_id)}, value: ${fmt(out2.value)},
        secret: ${fmt(out2.secret)}, nullifier: ${fmt(out2.nullifier)},
        timelock: 0, hashlock: 0
    };
    let sk_out_2 = ${fmt(sk2)};

    let exp_nf = ${fmt(noteC.nullifier)};
    let exp_ct1 = ${packToNoir(res1.ciphertext)};
    let exp_ct2 = ${packToNoir(res2.ciphertext)};

    let (nf, _, _, ct1, _, _, ct2, _) = main(
        merkle_root, current_timestamp, compliance_pubkey_x, compliance_pubkey_y,
        note_in, secret_in, index_in, path_in, preimage_in,
        note_out_1, sk_out_1,
        note_out_2, sk_out_2
    );

    assert(nf == exp_nf);
    assert(ct1 == exp_ct1);
    assert(ct2 == exp_ct2);
    `);
}

main().catch((err) => { console.error(err); process.exit(1); });
