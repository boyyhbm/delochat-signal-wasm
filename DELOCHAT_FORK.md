# DeloChat fork notes

This repository is an AGPL-3.0-only fork of
[`getmaapp/signal-wasm`](https://github.com/getmaapp/signal-wasm), pinned to
upstream commit `0952a017e83c19e9cad31769803fb119f895c01e` (upstream v0.5.0).
It remains a separate project and is not affiliated with Signal Messenger.

## Why this fork exists

The upstream in-memory identity store did not expose its remote identity map.
That makes it possible to persist ratchet sessions while losing the identity
trust state after a browser restart. DeloChat needs the state to survive in its
encrypted local vault, and it must never accept a changed identity silently.

## Added API

`WasmInMemIdentityKeyStore` now offers three asynchronous methods:

- `pinnedRemoteIdentity(address): Uint8Array | undefined` returns the public
  Signal identity key pinned for the address.
- `pinRemoteIdentity(address, identityKey): boolean` atomically stores a key
  when absent, returns `true` for that first pin and `false` for an identical
  existing key. Passing a different key fails with code
  `PinnedIdentityMismatch`.
- `assertPinnedRemoteIdentity(address, identityKey): void` fails with
  `PinnedIdentityMissing` or `PinnedIdentityMismatch` unless an exact pin is
  already present.

The API deliberately provides no replace operation. A product that permits
identity rotation must make that an explicit, user-confirmed process and discard
the old session before creating a new store.

## Integration invariant

Before processing a received prekey message, a consumer must verify the
application's signed identity binding, call `pinRemoteIdentity` with that
expected Signal identity, then decrypt. The store's normal libsignal trust
check then rejects a ciphertext carrying a different identity. The application
must export the returned public pins with its encrypted ratchet state and import
them before any encryption or decryption after restart.

This fork does not itself constitute a cryptographic audit or a promise that a
product implements Signal's protocol correctly.
