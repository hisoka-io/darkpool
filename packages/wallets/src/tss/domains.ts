// Field-element domain-separation tags for the (t,n)-over-BabyJubJub primitives, computed as
// keccak256(label) % BN254_Fr -- byte-identical to the Noir `shared/src/common/domains.nr` tags so TS and the
// circuit hash the same preimage. A shared tag would let one transcript alias another.

/** In-circuit FROST challenge tag (keccak256("hisoka.frost.v1")). Matches Noir SCHNORR_DOMAIN. */
export const SCHNORR_DOMAIN =
  0x2107179dff41b3dd7a3f1dafc51478ba9cf2daee14867e12f614e781f5aeba85n;

/** FROST binding-factor tag H1 (keccak256("hisoka.frost.rho.v1")). */
export const FROST_RHO_DOMAIN =
  0x0d165433f845e27e4b30d0d9097fde347a6fd27804b4e389df364c1075646cban;

/** FROST hedged-nonce tag H3 (keccak256("hisoka.frost.nonce.v1")). */
export const FROST_NONCE_DOMAIN =
  0x2a1ecc8a540d78f36e1f3de459fcea07f1275548922c2d41beec0a880eb0251dn;

/** FROST message pre-hash tag H4 (keccak256("hisoka.frost.msg.v1")). */
export const FROST_MSG_DOMAIN =
  0x239107747b96e6644d2f852367e078cc61864912ff638afd5efc0c65b943f5dcn;

/** FROST commitment-list pre-hash tag H5 (keccak256("hisoka.frost.com.v1")). */
export const FROST_COM_DOMAIN =
  0x1b3a889f80a6fdbbbfc54e00ae8c37bb92a4272459993cb546f912cec7017c1fn;

/** PedPoP proof-of-possession challenge tag (keccak256("hisoka.frost.pop.v1")). */
export const FROST_POP_DOMAIN =
  0x2be00580ace52d222adfc972534e93b8039645dc99ee9551792ac1fee8dcb3e1n;

/** Chaum-Pedersen DLEQ challenge tag (keccak256("hisoka.cp.v1")). */
export const CP_DOMAIN =
  0x28d8e60be83dbb247f779aa54f139872474d3205293b0ef0298ad0cbc2d54e5en;

/** Per-operation ACTION tag (first element of the FROST message m); a distinct tag per op stops
 *  cross-op signature replay. keccak256("hisoka.frost.action.<op>.v1"). */
export const ACTION_WITHDRAW =
  0x10bdf6418845f80562b4936e9fc0f64de27bc95b7c96f2c0898fd9511d751d47n;
export const ACTION_TRANSFER =
  0x2ff0294e5ed0c2a9655cc6709bc96e34b62c677397e3dd0416c299b945c63314n;
export const ACTION_SPLIT =
  0x10ab6394a1de647bbaa0f2e7b6316e2a73e63b8afa79018783d2a22202083d08n;
export const ACTION_JOIN =
  0x1bc4c29e7730275b30fd38d913559fc7f15eb4fabc3e1aed2295e2d0ef006617n;
