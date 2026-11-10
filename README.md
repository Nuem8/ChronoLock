# NueM8 ChronoLock

A small secret-sharing tool. The secret is encrypted in the browser. ChronoLock stores only the ciphertext. The link dies after one reveal, or when its time runs out.

This is a standalone program. It can be linked from nuem8.com later. It does not send anything to NueM8.

## What the server can see

The page generates a random key and encrypts the secret with AES-GCM before the upload. The key is placed after `#` in the link. Browsers do not send that part to the server, so ChronoLock cannot read the secret, and neither can a database copy.

Opening the link does not burn it. Link previews only receive the page. The secret is fetched when the recipient presses Reveal. If “Delete after one reveal” is on, that press deletes the ciphertext. Either way, the row is deleted when its lifetime ends.

Memory storage dies with the process. SQLite storage keeps unexpired secrets across a restart, still without the key.

## Run

```
cargo run --release -- --listen 127.0.0.1:8787 --store sqlite --data chronolock.db
```

Memory mode:

```
cargo run --release -- --listen 127.0.0.1:8787 --store memory
```

ChronoLock listens on localhost until you put it behind HTTPS. WebCrypto will not encrypt on a public `http://` page. A reverse proxy should forward to this address. Pass `--trust-proxy` only when the proxy connects from loopback, so the rate limit sees the visitor address. That address is kept in memory for the limit. It is not written to the database.

The longest lifetime is 7 days unless you set `--max-ttl` in seconds.

## Limits

One secret can be 64KB. There is no account, no log of the secret, and no log of the link id. This is a dead drop for a password or a key, not a password manager.
