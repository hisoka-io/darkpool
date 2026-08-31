export const PSS_SCHEMA_VERSION = 2;

export const STATE_KEY_BYTES = 32;
export const DERIVED_KEY_BYTES = 32;
export const ACCOUNT_ID_BYTES = 32;
export const ED25519_SEED_BYTES = 32;
export const ED25519_PUBLIC_KEY_BYTES = 32;
export const ED25519_SIGNATURE_BYTES = 64;
export const SHA256_BYTES = 32;
export const GCM_NONCE_BYTES = 12;
export const GCM_TAG_BYTES = 16;

export const HKDF_INFO_AUTH = "auth-v1";
export const HKDF_INFO_CELL_STATE = "cell-state-v1";
export const HKDF_INFO_CELL_LABELS = "cell-labels-v1";

export const PREIMAGE_PUT_PREFIX = "pss-v1:put";
export const PREIMAGE_DELETE_PREFIX = "pss-v1:del";

// Protocol-fixed and uniform for every client. A user-tunable padding size or cadence collapses to the
// cheapest setting under rational choice and fingerprints whoever did not turn it down, so these are
// frozen here rather than exposed as configuration (Seres/Pejo/Burcsi, FC 2022, appendix D).
export const PAD_TIERS: readonly number[] = [16_384, 131_072, 1_048_576];
export const MAX_PLAINTEXT_BYTES = 1_048_576;
export const MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + 64;

// Slack above the tightest legal envelope, so a client whose JSON serialiser inserts whitespace is not
// refused. Uniform across deployments for the same reason the tiers are: a server that set its own
// tolerance would accept bodies its neighbours reject, and the client could tell which one it reached.
export const BODY_HEADROOM_BYTES = 4096;

export const TIMESTAMP_SKEW_SECONDS = 300;
export const WRITES_PER_HOUR = 60;
export const WRITE_BURST = 10;

export const INSTALL_ID_BYTES = 16;
export const INVITE_CODE_MAX_CHARS = 128;
export const PLATFORM_MAX_CHARS = 64;
