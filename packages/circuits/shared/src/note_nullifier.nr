use crate::domains::PSI_DOMAIN;
use poseidon::poseidon2::Poseidon2;

// psi = Poseidon2(CEK, PSI_DOMAIN): leaf blinder + nullifier key, re-derived from CEK, never transmitted.
pub fn psi(cek: Field) -> Field {
    Poseidon2::hash([cek, PSI_DOMAIN], 2)
}

// nullifier = Poseidon2(psi, leaf_index). 2-input arity; the DEM keystream is 3-input Poseidon2 -> the two
// preimages cannot alias.
pub fn nullifier(note_psi: Field, leaf_index: Field) -> Field {
    Poseidon2::hash([note_psi, leaf_index], 2)
}

#[test]
fn kat_psi_nullifier() {
    let cek = 0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bda;
    let note_psi = psi(cek);
    assert(note_psi == 0x0441d9b1006cd55062a6458b5dd1db14869f1a5c8fbc66f73032208c2b109956);

    let nf = nullifier(note_psi, 3);
    assert(nf == 0x0ced8160f191dfff5c3432bc36f182188226143b294192021ea754f282075897);

    // A 2-arity Poseidon2 of CEK differs from CEK: psi is a non-trivial hidden preimage of the commitment.
    assert(note_psi != cek);
}
