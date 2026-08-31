DROP INDEX IF EXISTS slots_updated_on;

CREATE TABLE slots_without_retention (
  account_id   BLOB    NOT NULL,
  collection   TEXT    NOT NULL CHECK (collection IN ('state', 'labels')),
  version      INTEGER NOT NULL CHECK (version >= 0),
  prev_version INTEGER NOT NULL CHECK (prev_version >= 0),
  nonce        BLOB    NOT NULL,
  ciphertext   BLOB    NOT NULL,
  PRIMARY KEY (account_id, collection)
);

INSERT INTO slots_without_retention
  (account_id, collection, version, prev_version, nonce, ciphertext)
SELECT account_id, collection, version, prev_version, nonce, ciphertext
FROM slots;

DROP TABLE slots;
ALTER TABLE slots_without_retention RENAME TO slots;
