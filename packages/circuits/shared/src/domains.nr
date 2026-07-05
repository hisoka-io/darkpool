//! Domain-separation tags, keccak256(label) % BN254_Fr. ENC separates the note-cipher keystream, PSI the
//! leaf blinder; the nullifier and cek_wrap key off values provably distinct from CEK so need no tag.

// keccak256("hisoka.enc.v1") % BN254_Fr
pub global ENC_DOMAIN: Field = 0x1a0ef2d9219ffd1fa6aaa00b33818a7f5503303777b95cfcc6bb7653189dfca3;
// keccak256("hisoka.psi.v1") % BN254_Fr
pub global PSI_DOMAIN: Field = 0x138d495e7a5c1b3f504318dd6cfcf0a7cf7bb6d69cf9eadb049cc35d6831ef5b;

// Equal tags would let the keystream preimage alias the blinder preimage.
#[test]
fn audit_domains_pairwise_distinct() {
    assert(ENC_DOMAIN != PSI_DOMAIN);
}
