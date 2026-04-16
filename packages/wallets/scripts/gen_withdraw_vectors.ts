import {
  NotePlaintext,
  encryptNoteDeposit,
  toFr,
  addressToFr,
  deriveSharedSecret,
  Poseidon,
  LeanIMT,
} from "../src";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { packToNoir, fmt } from "./lib/helpers.js";

async function main() {
  console.log("--- WITHDRAW VECTORS (With Intent) ---");
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

  const withdrawVal = 40n;
  const changeNote: NotePlaintext = {
    ...oldNote,
    value: toFr(60n),
    nullifier: toFr(300n),
    secret: toFr(400n),
  };
  const changeNonce = toFr(20n);
  const changeRes = await encryptNoteDeposit(
    toFr(555n),
    changeNonce,
    changeNote,
    COMPLIANCE_PK,
  );

  const oldEphSk = oldRes.ephemeral_sk_used;
  const oldSS = await deriveSharedSecret(oldEphSk, COMPLIANCE_PK);

  const nullifier = await Poseidon.hashScalar(oldNote.nullifier);

  // 0 = standard withdraw (no swap intent)
  const intentHash = 0;

  console.log(`
    let withdraw_value = ${fmt(withdrawVal)};
    let recipient = 0x1234567890123456789012345678901234567890; 
    let merkle_root = ${fmt(root)};
    let current_timestamp = 0;
    let intent_hash = ${fmt(intentHash)}; 
    let compliance_pubkey_x = ${fmt(COMPLIANCE_PK[0])};
    let compliance_pubkey_y = ${fmt(COMPLIANCE_PK[1])};

    let old_note = Note {
        asset_id: ${fmt(oldNote.asset_id)},
        value: ${fmt(oldNote.value)},
        secret: ${fmt(oldNote.secret)},
        nullifier: ${fmt(oldNote.nullifier)},
        timelock: ${fmt(oldNote.timelock)},
        hashlock: ${fmt(oldNote.hashlock)}
    };
    let old_shared_secret = ${fmt(oldSS)};
    let old_note_index = 0;
    let old_note_path = [${Array(32).fill("0").join(", ")}];
    let hashlock_preimage = 0;

    let change_note = Note {
        asset_id: ${fmt(changeNote.asset_id)},
        value: ${fmt(changeNote.value)},
        secret: ${fmt(changeNote.secret)},
        nullifier: ${fmt(changeNote.nullifier)},
        timelock: ${fmt(changeNote.timelock)},
        hashlock: ${fmt(changeNote.hashlock)}
    };
    let change_ephemeral_sk = ${fmt(changeRes.ephemeral_sk_used)};

    let exp_nf = ${fmt(nullifier)};
    let exp_ct = ${packToNoir(changeRes.ciphertext)};

    let (nf, _, _, ct, _) = main(
        withdraw_value, recipient, merkle_root, current_timestamp,
        intent_hash, 
        compliance_pubkey_x, compliance_pubkey_y,
        old_note, old_shared_secret, old_note_index, old_note_path, hashlock_preimage,
        change_note, change_ephemeral_sk
    );

    assert(nf == exp_nf);
    assert(ct == exp_ct);
    `);
}

main().catch((err) => { console.error(err); process.exit(1); });
