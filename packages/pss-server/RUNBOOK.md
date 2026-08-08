# PSS server operator runbook

The private state store holds one encrypted blob per account per collection. It never reads the chain,
never holds a decryption key, and is advisory: if it is down, stale or lost, wallets resync from the
chain and keep working. Operate it accordingly.

---

## 1. Logging discipline

**No log line may contain an account identifier together with a timestamp.**

That pair is the correlation data this design exists not to produce. An access log that records
`(accountId, time)` reconstructs, for anyone who later reads it, exactly when each account was active,
which is correlatable against on-chain events. It survives in backups and in log shipping.

- Record coarse bucketed counters only: requests per route, per status class, per interval.
- Never log an `accountId`, an invite code, a ciphertext, a nonce or a signature.
- If a reverse proxy sits in front, turn its access log off or strip the path. The `accountId` is a
  path segment.
- The process emits a counter snapshot on shutdown and nothing per request. Keep it that way.

## 2. Invite issuance

Account creation is invite gated. The gate's entire strength is the entropy of the code, and **the
server cannot enforce it**: the wire format accepts any `[A-Za-z0-9_-]` string up to 128 characters, so
a one-character code parses and works.

- **Issue codes from a CSPRNG, at least 128 bits, which is 22 base64url characters.**
- Issuance is manual and out of band. There is no issuance endpoint and there should not be one.
- To issue, insert the digest directly. WAL mode permits this while the server is running:
  ```sql
  INSERT INTO invites (code_hash, spent) VALUES (?, 0);
  ```
  The parameter is **SHA-256 over the UTF-8 bytes of the code string**, not over the decoded entropy.
  Hand the code itself to the user and keep no record of who received which one beyond what you need.
- The server stores only `SHA256(code)` and records that a code was spent, never which account spent
  it. That set-membership property is the reason the whole `invites` table can be dropped later without
  breaking a single account.

There is no per-code rate limit and adding a global one would be worse than the problem: the only
throttle is keyed on an account identifier the caller mints for free, so a shared bucket becomes a
trivial global signup denial. Code entropy is the control.

A correct guess buys one storage slot for an account the guesser already controls. It grants no read,
no write and no reach into any other account.

## 3. Storage, WAL and backups

The database is SQLite in WAL mode with `synchronous = NORMAL`.

**WAL frames leak more than the main database does.** The invite spend and the first slot row commit in
one transaction, which is required: without it a rejected invite would leave a created account behind.
The consequence is that the live `-wal` transiently groups an account identifier with the code hash it
spent. That pairing does not survive a checkpoint and the `-wal` is removed on a clean shutdown, so the
durable main database carries no such pairing.

- **Run `PRAGMA wal_checkpoint(TRUNCATE)` before any file-level backup.**
- **If you adopt WAL-shipping replication (Litestream or similar), understand that it ships those
  frames.** Replication retains what a file copy would not. Decide that deliberately.
- Deletion is not a secure erase. `secure_delete` is off, so `DELETE FROM slots` unlinks pages and
  leaves the bytes. Contents stay AES-256-GCM under a key this server never holds, but the account
  identifier, the coarse tier size and the ciphertext remain recoverable from the file and from any
  already-shipped WAL segment. The API contract of "no tombstone, no recovery" is about semantics, not
  media sanitisation.
- Row storage order leaks insertion order. Page offsets do this regardless of table options, so it is
  accepted rather than mitigated.

## 4. Node version and the native module

**The server requires Node 20.x or 22.x.**

`better-sqlite3` is a native module compiled against a specific Node ABI, and there is no upstream
prebuild for Node 20, so installing builds from source and needs a working node-gyp toolchain. This is
the only dependency in the repo that fails hard rather than warning, and its failure reads like a code
defect: dozens of `ERR_DLOPEN_FAILED`, `NODE_MODULE_VERSION` mismatch and `Module did not self-register`
errors.

`engines` is advisory and package managers only warn, so run `bash scripts/check-node.sh` first. It
fails loudly with the fix.

After a Node major upgrade, rebuild rather than debug: `rm -rf node_modules && pnpm install --frozen-lockfile`.

## 5. Configuration

`PSS_HOST`, `PSS_PORT`, `PSS_DATABASE_PATH`. Everything else, including every protocol limit, comes
from the wire contract and is deliberately not configurable: a deployment that could widen its own
padding tiers or skew window would be distinguishable from every other deployment.

**`PSS_DATABASE_PATH` must be set, and must be absolute.** The built-in default is anchored inside the
install directory, which is wrong for a mounted volume or a read-only image. A relative path resolves
against the working directory, so launching from elsewhere silently opens a different, empty database
while the migrations still resolve. That looks like a healthy server that has lost every account.

## 6. Retention

Blobs expire 400 days after their last write, anchored on a date rather than a timestamp so the store
never holds an exact per-account activity time. The sweep runs once at boot and then daily.

Nothing reports sweep counts, so a silently dead sweep is invisible. To check, query the oldest
`updated_on` in `slots` and confirm it is inside the retention window.

An expired account is not an error. The wallet resyncs from the chain, which is slower and is a
supported path.

## 6a. Noticing a failure

There is no health route and every 500 is a bare status by design, so failures are silent on the wire.
Two things to watch:

- **Counters.** `startServer()` returns a `RunningServer` whose `counters.snapshot()` is readable live.
  Scrape it from the supervisor that starts the server. `blob_put.5xx` is what increments when the disk
  fills, which is the most likely real failure.
- **Free disk on the `PSS_DATABASE_PATH` volume.** SQLite returning `SQLITE_FULL` surfaces only as 5xx
  counters and refused writes.

**Sweep liveness**, per section 6:

```sh
sqlite3 "$PSS_DATABASE_PATH" 'SELECT MIN(updated_on) FROM slots;'
```

**Client clock skew.** A client seeing persistent 401s on PUT with a key that is otherwise fine has a
device clock off by 300 seconds or more. It is not a key problem and needs no server action: it clears
itself on the first correctly-clocked write.

## 7. Restore, and what it cannot recover

1. Stop the server.
2. Restore the main database file plus any `-wal` and `-shm` alongside it.
3. Run `bash scripts/check-node.sh`, then start. Migrations are idempotent and run at boot.

**What a restore cannot recover:** any write acknowledged after the backup point. At
`synchronous = NORMAL` a power loss can also lose transactions the server already answered 200 to.

This is safe by construction but not invisible. A client's version floor only ever moves up, and it now
rises on the client's own accepted write as well as on a read, so a server that has gone backwards will
have its older versions refused as rollbacks by any client that wrote since the backup point. **That
client stays refused until it resyncs; honest service alone does not clear it**, which is the intended
trade for detecting the loss at all.

**A client that reinstalled after the backup point has no such memory and cannot detect the rollback.**
It falls back to rechecking the chain before it spends, which is where the money-path guarantee actually
lives. Do not tell users the backup protects them across a reinstall.

Do not attempt to reconcile versions on the server, and never restore a backup over a newer database in
the hope of merging them.

## 8. What this server is not

It never reads the chain. It cannot decrypt a blob. It cannot forge one, because every write is signed
by a key derived from the account owner's wallet root and the account identifier is the hash of that
signing key. It cannot roll a client back without being detected. If you find yourself adding chain
access or a decryption key to this service, the design has drifted.
