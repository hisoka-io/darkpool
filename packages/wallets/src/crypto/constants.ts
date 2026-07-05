/** Baby Jubjub subgroup order. */
export const BJJ_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

/** Note-cipher keystream domain tag (keccak256("hisoka.enc.v1") % BN254_Fr). Must match Noir `ENC_DOMAIN`. */
export const ENC_DOMAIN =
  0x1a0ef2d9219ffd1fa6aaa00b33818a7f5503303777b95cfcc6bb7653189dfca3n;

/** Leaf-blinder (psi) domain tag (keccak256("hisoka.psi.v1") % BN254_Fr). Must match Noir `PSI_DOMAIN`. */
export const PSI_DOMAIN =
  0x138d495e7a5c1b3f504318dd6cfcf0a7cf7bb6d69cf9eadb049cc35d6831ef5bn;
