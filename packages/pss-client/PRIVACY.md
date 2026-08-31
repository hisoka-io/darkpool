# What state sync does and does not hide

Your wallet can back up its own state to a server so it does not have to rebuild everything from
scratch every time you open it. The backup is encrypted on your device. This page says plainly what
that server can and cannot see, so you can decide whether to use it.

## What the server cannot do

- **It cannot read anything you store.** Your state is encrypted on your device with a key derived from
  your recovery phrase. The server never has that key.
- **It cannot create readable state.** Any ciphertext tampering is detected when your wallet opens the
  backup. The server can still discard writes, replay older backups, or show devices different histories.
- **It cannot roll you back while your device keeps its local data.** Your wallet remembers the newest
  version it has written or read and refuses anything older. After a reinstall that memory is gone and
  the wallet cannot tell an old backup from a current one, so it reconstructs owned notes through Raven
  before it spends. Raven v1 is trusted to return fresh and correct discovery results.
- **It cannot serve one part of your state in place of another.**
- **Nobody else can write to your account.** Writes are signed with a key only your recovery phrase can
  produce.

## What the server can see

- **A stable identifier for your account, and it links every write to it.** It is not your name or your
  wallet address, but it is the same identifier every time.
- **When you are active.** The server sees the timing of your writes, and that timing can be compared
  against public blockchain activity. **This is the real cost of using state sync and it is not
  slight.** Today it is reduced only by the fact that we run the server and put network-level
  protection in front of it. That is acceptable for this version and it will not be acceptable
  indefinitely.
- **Roughly how much state you have**, as one of three size bands. Not the contents, not the number of
  items.
- **That an invite code was used to create an account.** Codes are handed out by us, so a code links
  account creation to whoever we gave it to. The server records that a code was spent but never which
  account spent it, and the whole invite system can be removed later without breaking any account.

## Limits you should know about

- **You cannot use two devices at the same time.** You can move between them. One device is the writer;
  another device is read-only until you explicitly take over. Every self-mint counter reservation checks
  the remote writer through compare-and-swap before returning, so a former writer is demoted before it can
  release another index when the server serializes that operation honestly. Ordinary background state learns
  the handover on its next pull.
- **Deleting is permanent and gets you nothing back.** It erases everything stored for your account,
  with no recovery. Creating the account again needs a new invite code.
- **Stored state does not expire.** The server retains state and labels until you send an authenticated
  deletion. This protects the self-ephemeral counter from being lost during a long absence and means
  server storage grows until users delete accounts.

## If the server is down, gone, or lying

State sync is not the source of ownership. A wallet can reconstruct owned notes from its recovery phrase
and Raven's indexed chain data when PSS is unavailable. This version trusts Raven to answer every lookup
freshly and correctly; it does not provide authenticated absence, provider quorum, retries, or failover.
The real Raven Howl adapter is still external to this package. Existing local state remains readable, but a
deposit, claim, or spend that needs a fresh self output waits or fails closed because counter allocation
requires PSS.

This version trusts the server to serialize compare-and-swap writes honestly. A malicious server can show two
devices separate histories or acknowledge both counter writes without storing either one. Both devices can then
receive the same self-mint index. Do not use two devices simultaneously. Byzantine fork protection requires
independent witnesses or a quorum and is deferred to a later version.
