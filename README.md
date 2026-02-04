# xHD-Wallet-API-rs

Rust implementation for BIP32 ED25519 derivation. Forked from [typed-io/rust-ed25519-bip32](github.com/typed-io/rust-ed25519-bip32). This fork has two supported derivation schemes:

- `V2`, which is the scheme defined by Khovratovich and Law in [BIP32-Ed25519: Hierarchical Deterministic Keys over a Non-linear Keyspace](https://ieeexplore.ieee.org/document/7966967)
- `Peikert`, which is [Chris Peikert's adendum](https://github.com/algorandfoundation/bip32-ed25519-addendum/) to the Khovratovich and Law scheme that results in more entropy to derived keys.

## Current Status

This library is currently a work-in-progress. It is intended to be used to create packages in other languages, such as Python, via FFI bindings.
