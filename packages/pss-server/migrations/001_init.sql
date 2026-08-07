CREATE TABLE IF NOT EXISTS slots (
  account_id   BLOB    NOT NULL,
  collection   TEXT    NOT NULL CHECK (collection IN ('state', 'labels')),
  version      INTEGER NOT NULL CHECK (version >= 0),
  prev_version INTEGER NOT NULL CHECK (prev_version >= 0),
  nonce        BLOB    NOT NULL,
  ciphertext   BLOB    NOT NULL,
  updated_on   TEXT    NOT NULL CHECK (updated_on LIKE '____-__-__'),
  PRIMARY KEY (account_id, collection)
);

CREATE INDEX IF NOT EXISTS slots_updated_on ON slots (updated_on);

-- No account_id column, deliberately. Recording which account spent which code would build the exact
-- correlation table the invite gate is a placeholder for removing, and it would survive in backups.
-- Set membership is the whole contract, so the pairing is not representable rather than merely unwritten.
CREATE TABLE IF NOT EXISTS invites (
  code_hash BLOB    PRIMARY KEY,
  spent     INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0, 1))
);
