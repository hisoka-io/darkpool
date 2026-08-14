# @hisoka/howl-e2e

Test-only. The single place allowed to import the wallet SDK, PSS and a discovery source together, so the
flow that actually differentiates Howl from a trial-decrypt pool has somewhere to be exercised.

Howl's claim is single-shot discovery: a wallet computes its own tag locally and fetches only its own rows
in a bounded number of round trips. `ScanEngine` downloads every note event and filters locally, which is
O(pool) bandwidth. It is kept here as a differential ORACLE and is never the path under test.

`MockRaven` is a key-value store with XOR-masked cells standing in for the real PIR. It is faithful about
the things that break integrations (record bytes, the two-round-trip shape, one tag mapping to many notes,
a probe returning a row on a miss) and honest about the thing it does not do (it provides no query privacy,
so it counts and exposes every query instead, and the tests assert the COUNT is bounded).
