//! Cipher domain-separation tags: keccak256(label) % BN254_Fr, the DLEQ_DOMAIN precedent. ENC separates
//! the note-cipher keystream; PSI separates the leaf blinder. Two tags are the minimal sufficient set
//! (the nullifier and cek_wrap key off values provably distinct from CEK, so no NULL/WRAP tag is needed).

use crate::DLEQ_DOMAIN;

// keccak256("hisoka.enc.v1") % BN254_Fr
pub global ENC_DOMAIN: Field = 0x1a0ef2d9219ffd1fa6aaa00b33818a7f5503303777b95cfcc6bb7653189dfca3;
// keccak256("hisoka.psi.v1") % BN254_Fr
pub global PSI_DOMAIN: Field = 0x138d495e7a5c1b3f504318dd6cfcf0a7cf7bb6d69cf9eadb049cc35d6831ef5b;

// Pairwise distinctness is load-bearing: equal tags would let one primitive's Poseidon2 preimage alias
// another's.
#[test]
fn audit_domains_pairwise_distinct() {
    assert(ENC_DOMAIN != PSI_DOMAIN);
    assert(ENC_DOMAIN != DLEQ_DOMAIN);
    assert(PSI_DOMAIN != DLEQ_DOMAIN);
}
