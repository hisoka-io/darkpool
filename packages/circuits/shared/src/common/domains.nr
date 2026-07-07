// keccak256("hisoka.enc.v1") % BN254_Fr
pub global ENC_DOMAIN: Field = 0x1a0ef2d9219ffd1fa6aaa00b33818a7f5503303777b95cfcc6bb7653189dfca3;
// keccak256("hisoka.psi.v1") % BN254_Fr
pub global PSI_DOMAIN: Field = 0x138d495e7a5c1b3f504318dd6cfcf0a7cf7bb6d69cf9eadb049cc35d6831ef5b;

// keccak256("hisoka.frost.v1") % BN254_Fr
pub global SCHNORR_DOMAIN: Field =
    0x2107179dff41b3dd7a3f1dafc51478ba9cf2daee14867e12f614e781f5aeba85;

// keccak256("hisoka.frost.action.<op>.v1") % BN254_Fr
pub global ACTION_WITHDRAW: Field =
    0x10bdf6418845f80562b4936e9fc0f64de27bc95b7c96f2c0898fd9511d751d47;
pub global ACTION_TRANSFER: Field =
    0x2ff0294e5ed0c2a9655cc6709bc96e34b62c677397e3dd0416c299b945c63314;
pub global ACTION_SPLIT: Field = 0x10ab6394a1de647bbaa0f2e7b6316e2a73e63b8afa79018783d2a22202083d08;
pub global ACTION_JOIN: Field = 0x1bc4c29e7730275b30fd38d913559fc7f15eb4fabc3e1aed2295e2d0ef006617;

#[test]
fn audit_domains_pairwise_distinct() {
    let tags = [
        ENC_DOMAIN,
        PSI_DOMAIN,
        SCHNORR_DOMAIN,
        ACTION_WITHDRAW,
        ACTION_TRANSFER,
        ACTION_SPLIT,
        ACTION_JOIN,
    ];
    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert(tags[i] != tags[j], "domain tags must be pairwise distinct");
        }
    }
}
