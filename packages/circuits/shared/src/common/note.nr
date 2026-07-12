use crate::domains::PSI_DOMAIN;
use poseidon::poseidon2::Poseidon2;

pub global TWO_POW_32: Field = 4294967296;

pub global NOTE_VERSION: Field = 1;
pub global NOTE_TYPE_STANDARD: Field = 0;
pub global NOTE_TYPE_MULTISIG: Field = 1;
pub global NOTE_TYPE_CONDITIONAL: Field = 2;

// A note_type outside the enabled set commits to a leaf no circuit consumes (silent burn).
pub fn assert_valid_note_type(note_type: Field) {
    assert(
        (note_type == NOTE_TYPE_STANDARD) | (note_type == NOTE_TYPE_MULTISIG),
        "note_type not in {STANDARD, MULTISIG}",
    );
}

pub fn assert_asset_id(asset_id: Field) {
    let _: [u8; 20] = asset_id.to_be_bytes();
}

pub struct Parent {
    pub leaf_index: u32,
}

// Ordered stable-first so a spend hashing both consumed and created leaves shares the sponge prefix.
pub struct Note {
    pub note_version: Field,
    pub asset_id: Field,
    pub note_type: Field,
    pub conditions_hash: Field,
    pub value: u128,
    pub owner: Field,
    pub psi: Field,
    pub parents: Field,
}

impl Note {
    // Plaintext-commit leaf over all 8 fields; byte-identical to the TS `leaf`.
    pub fn leaf(self) -> Field {
        Poseidon2::hash(
            [
                self.note_version,
                self.asset_id,
                self.note_type,
                self.conditions_hash,
                self.value as Field,
                self.owner,
                self.psi,
                self.parents,
            ],
            8,
        )
    }
}

pub fn pack_parents(parents: [Parent; 2]) -> Field {
    (parents[0].leaf_index as Field) + (parents[1].leaf_index as Field) * TWO_POW_32
}

pub fn unpack_parents(packed: Field) -> [Parent; 2] {
    let bytes: [u8; 32] = packed.to_le_bytes();
    for i in 8..32 {
        assert(bytes[i] == 0, "packed parents exceeds 2^64");
    }
    [Parent { leaf_index: u32_from_le(bytes, 0) }, Parent { leaf_index: u32_from_le(bytes, 4) }]
}

// indexes MUST be the same witnesses verify_spend feeds the nullifier/membership proof, else parents forge.
pub fn assert_parents_bound(note: Note, indexes: [Field; 2]) {
    let expected = pack_parents([
        Parent { leaf_index: indexes[0] as u32 },
        Parent { leaf_index: indexes[1] as u32 },
    ]);
    assert(note.parents == expected, "output parents not bound to consumed inputs");
}

fn u32_from_le(bytes: [u8; 32], offset: u32) -> u32 {
    (bytes[offset] as u32)
        + (bytes[offset + 1] as u32) * 256
        + (bytes[offset + 2] as u32) * 65536
        + (bytes[offset + 3] as u32) * 16777216
}

#[test]
fn kat_leaf_fully_populated() {
    let cek = 0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bda;
    let note_psi = Poseidon2::hash([cek, PSI_DOMAIN], 2);
    let note = Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 100,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        psi: note_psi,
        parents: 0,
    };
    assert(note.leaf() == 0x1bcd07739b701ccbd05dfb11bb4aaa428b200b37a7cbdc49d575b281b88930cc);
}

#[test]
fn kat_pack_unpack_parents() {
    let parents = [Parent { leaf_index: 2 }, Parent { leaf_index: 4 }];
    let packed = pack_parents(parents);
    assert(packed == 0x400000002);

    let unpacked = unpack_parents(packed);
    assert(unpacked[0].leaf_index == 2);
    assert(unpacked[1].leaf_index == 4);
}

#[test]
fn kat_deposit_parents_zero() {
    let parents = [Parent { leaf_index: 0 }, Parent { leaf_index: 0 }];
    assert(pack_parents(parents) == 0);

    let unpacked = unpack_parents(0);
    assert(unpacked[0].leaf_index == 0);
    assert(unpacked[1].leaf_index == 0);
}

#[test]
fn kat_max_u32_boundary() {
    let parents = [Parent { leaf_index: 0xffffffff }, Parent { leaf_index: 0xffffffff }];
    let packed = pack_parents(parents);
    assert(packed == 0xffffffffffffffff);
    let unpacked = unpack_parents(packed);
    assert(unpacked[0].leaf_index == 0xffffffff);
    assert(unpacked[1].leaf_index == 0xffffffff);
}

// A packed value with any bit above 2^64 (here byte 8 set) is not two u32 leaf indices and must be rejected.
#[test(should_fail_with = "packed parents exceeds 2^64")]
fn audit_unpack_parents_overflow() {
    let _ = unpack_parents(0x10000000000000000);
}
