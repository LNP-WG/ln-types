# Common Rust Lightning Network types

**Warning: while in a good state, this is still considered a preview version!**
There are some planned changes.

This library aims to provide Rust-idiomatic, ergonomic, and reasonably performant
implementation of primitives used in applications interacting with Lightning Network.
That means, they are not *just* types used to implement LN itself, they are supposed to be
useful to any application that e.g. communicates with an LN implementation. Of course,
they should still be useful for an LN implementation itself.

## Important types

The most important types currently available:

* `Amount` - similar to `bitcoin::Amount` but with millisatoshi precision
* `P2PAddress` - address of a node usually represented in text as `node_id_hex@host:port`
* `NodeId` - the byte representation of node's public key (no crypto operations)
* `NodePubkey` - newtype around `secp256k1::PublicKey` to distinguish node public key from
                   other keys. Requires `secp256k1` feature.

Note: invoice is not here and isn't planned because it already exists in a separate crate.

## Integrations

The crate aims to be interoperable with other crates via optional dependencies.
Currently available integrations (activate using features of the same name):

* `bitcoin` - converting between types
* `serde` - serialization and deserialization of types
* `postgres-types` - storing and retrieving from SQL
* `parse_arg` - parsing arguments into types in this crate
* `secp256k1` - provides `NodePubkey`
* `slog` - provides `slog::Value` and (where relevant) `slog::KV` implementations for the types

Feel free to contribute your own!

**Disclaimer**: Inclusion of any crate here is neither endorsment nor guarantee of it
being secure, honest, non-backdoored or functioning! You're required to do your own review of
any external crate.

The rules around adding a new integration are lax: the dependency must be optional, must
**not** be obviously broken or surprising, and must **not** interact with other implementations
in surprising ways.

## MSRV

The minimum supported Rust version is 1.48 but it's possible that it'll be decreased further.
Generally, the intention is to support at least the latest Debian stable.

Note that external libraries may have higher MSRV - this is not considered a breakage.

## License

MITNFA
