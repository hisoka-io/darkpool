# What state sync does and does not hide

Your wallet can back up its own state to a server so it does not have to rebuild everything from
scratch every time you open it. The backup is encrypted on your device. This page says plainly what
that server can and cannot see, so you can decide whether to use it.

## What the server cannot do

- **It cannot read anything you store.** Your state is encrypted on your device with a key derived from
  your recovery phrase. The server never has that key.
- **It cannot change your state.** Any tampering is detected when your wallet opens the backup, and the
  wallet refuses it.
- **It cannot roll you back while your device keeps its local data.** Your wallet remembers the newest
  version it has written or read and refuses anything older. After a reinstall that memory is gone and
  the wallet cannot tell an old backup from a current one, so it rechecks the blockchain before it
  spends. That recheck, not the backup, is what protects your money.
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
  another device is read-only until you explicitly take over, and taking over makes the first one
  read-only. This is deliberate: two devices writing at once can produce a key collision that would let
  one person read another's transfer.
- **Deleting is permanent and gets you nothing back.** It erases everything stored for your account,
  with no recovery. Creating the account again needs a new invite code.
- **Going quiet for more than 400 days deletes your stored state.** Your wallet still works. It rebuilds
  from the blockchain, which is slower.

## If the server is down, gone, or lying

**Your wallet still works.** State sync is a cache, never the source of truth. Your money lives on the
blockchain and your wallet can always rebuild from it using your recovery phrase alone. That rebuild is
slower, and it is a supported way to use the wallet, not an error.
