import {
  NotePlaintext,
  encryptNoteDeposit,
  toFr,
  addressToFr,
  deriveSharedSecret,
  Poseidon,
  LeanIMT,
  packNotePlaintext,
  aes128Encrypt,
  kdfToAesKeyIV,
} from "../src";
import { generateDLEQProof } from "../src/crypto/dleq";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { Fr } from "@aztec/foundation/fields";
import { packToNoir, fmt, fmtPt } from "./lib/helpers.js";

async function main() {
  console.log("--- TRANSFER VECTORS ---");
  const COMPLIANCE_PK = mulPointEscalar(Base8, 987654321n);

  const oldNote: NotePlaintext = {
    value: toFr(100n),
    asset_id: addressToFr("0x1234567890123456789012345678901234567890"),
    secret: toFr(100n),
    nullifier: toFr(200n),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };
  const oldNonce = toFr(10n);
  const oldRes = await encryptNoteDeposit(
    toFr(555n),
    oldNonce,
    oldNote,
    COMPLIANCE_PK,
  );

  const packedFrs = [];
  let idx = 0;
  for (let p = 0; p < 7; p++) {
    let val = 0n;
    const bytes = p < 6 ? 31 : 22;
    let power = 1n;
    for (let i = 0; i < bytes; i++) {
      val += BigInt(oldRes.ciphertext[idx]) * power;
      power *= 256n;
      idx++;
    }
    packedFrs.push(new Fr(val));
  }
  const commitment = await Poseidon.hash(packedFrs);
  const tree = new LeanIMT(32);
  await tree.insert(commitment);
  const root = tree.getRoot();

  const bob_sk = 11111n;
  const bob_dleq = await generateDLEQProof(bob_sk, COMPLIANCE_PK);

  const memoValue = 40n;
  const memoNote: NotePlaintext = {
    ...oldNote,
    value: toFr(memoValue),
    secret: toFr(0n),
    nullifier: toFr(0n),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };
  const memoEphSk = toFr(888n);

  // 3-party encryption: S = a * P
  const S_point = mulPointEscalar(bob_dleq.P, memoEphSk.toBigInt());
  const S = new Fr(S_point[0]);
  const { key: mKey, iv: mIv } = await kdfToAesKeyIV(S);
  const mPlain = packNotePlaintext(memoNote);
  const mCt = await aes128Encrypt(mPlain, mKey, mIv);

  const intBob = mulPointEscalar(COMPLIANCE_PK, memoEphSk.toBigInt());
  const intCarol = mulPointEscalar(bob_dleq.B, memoEphSk.toBigInt());

  const changeValue = 60n;
  const changeNote: NotePlaintext = {
    ...oldNote,
    value: toFr(changeValue),
    secret: toFr(300n),
    nullifier: toFr(400n),
  };
  const changeRes = await encryptNoteDeposit(
    toFr(555n),
    toFr(99n),
    changeNote,
    COMPLIANCE_PK,
  );

  const oldSharedSecret = await deriveSharedSecret(
    oldRes.ephemeral_sk_used,
    COMPLIANCE_PK,
  );

  const nullifierHash = await Poseidon.hashScalar(oldNote.nullifier);

  console.log(`
    let merkle_root = ${fmt(root)};
    let current_timestamp = 0;
    let compliance_pubkey_x = ${fmt(COMPLIANCE_PK[0])};
    let compliance_pubkey_y = ${fmt(COMPLIANCE_PK[1])};

    let recipient_B = ${fmtPt(bob_dleq.B)};
    let recipient_P = ${fmtPt(bob_dleq.P)};
    let recipient_proof = DLEQProof {
        U: ${fmtPt(bob_dleq.pi.U)},
        V: ${fmtPt(bob_dleq.pi.V)},
        z: ${fmt(bob_dleq.pi.z)}
    };

    let old_note = Note {
        asset_id: ${fmt(oldNote.asset_id)},
        value: ${fmt(oldNote.value)},
        secret: ${fmt(oldNote.secret)},
        nullifier: ${fmt(oldNote.nullifier)},
        timelock: ${fmt(oldNote.timelock)},
        hashlock: ${fmt(oldNote.hashlock)}
    };
    let old_shared_secret = ${fmt(oldSharedSecret)};
    let old_note_index = 0;
    let old_note_path = [${Array(32).fill("0").join(", ")}];
    let hashlock_preimage = 0;

    let memo_note = Note {
        asset_id: ${fmt(memoNote.asset_id)},
        value: ${fmt(memoNote.value)},
        secret: ${fmt(memoNote.secret)},
        nullifier: ${fmt(memoNote.nullifier)},
        timelock: ${fmt(memoNote.timelock)},
        hashlock: ${fmt(memoNote.hashlock)}
    };
    let memo_ephemeral_sk = ${fmt(memoEphSk)};

    let change_note = Note {
        asset_id: ${fmt(changeNote.asset_id)},
        value: ${fmt(changeNote.value)},
        secret: ${fmt(changeNote.secret)},
        nullifier: ${fmt(changeNote.nullifier)},
        timelock: ${fmt(changeNote.timelock)},
        hashlock: ${fmt(changeNote.hashlock)}
    };
    let change_ephemeral_sk = ${fmt(changeRes.ephemeral_sk_used)};

    // EXPECTED OUTPUTS
    let exp_nf = ${fmt(nullifierHash)};
    let exp_m_ct = ${packToNoir(mCt)};
    let exp_ib = ${fmtPt(intBob)};
    let exp_ic = ${fmtPt(intCarol)};

    let (nf, _, _, m_ct, ib, ic, _, _, _) = main(
        merkle_root, current_timestamp, compliance_pubkey_x, compliance_pubkey_y,
        recipient_B, recipient_P, recipient_proof,
        old_note, old_shared_secret, old_note_index, old_note_path, hashlock_preimage,
        memo_note, memo_ephemeral_sk,
        change_note, change_ephemeral_sk
    );

    assert(nf == exp_nf);
    assert(m_ct == exp_m_ct);
    assert(ib == exp_ib);
    assert(ic == exp_ic);
    `);
}

main().catch((err) => { console.error(err); process.exit(1); });
