/** Baby Jubjub subgroup order. */
export const BJJ_SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

/** DLEQ challenge domain-separation tag (keccak256("hisoka.dleq.v1") % BN254_Fr). Must match the Noir
 * `DLEQ_DOMAIN` global; prepended to the DLEQ challenge to prevent cross-protocol proof replay. */
export const DLEQ_DOMAIN =
  0x1570eff8f2295a2eb1f2cf6cea827909fd713f0446dcbd7f1647496d89273366n;
