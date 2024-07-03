//! # Common types related to Lightning Network
//!
//! **Warning: while in a good state, this is still considered a preview version!**
//! There are some planned changes.
//!
//! This library aims to provide Rust-idiomatic, ergonomic, and reasonably performant
//! implementation of primitives used in applications interacting with Lightning Network.
//! That means, they are not *just* types used to implement LN itself, they are supposed to be
//! useful to any application that e.g. communicates with an LN implementation. Of course,
//! they should still be useful for an LN implementation itself.
//!
//! ## Important types
//!
//! The most important types currently available:
//!
//! * [`Amount`] - similar to [`bitcoin_units::Amount`] but with millisatoshi precision
//! * [`P2PAddress`] - address of a node usually represented in text as `node_id_hex@host:port`
//! * [`NodeId`] - the byte representation of node's public key (no crypto operations)
//! * [`NodePubkey`] - newtype around [`secp256k1::PublicKey`] to distinguish node public key from
//!                    other keys. Requires `secp256k1` feature.
//!
//! Note: invoice is not here and isn't planned because it already exists in a separate crate.
//!
//! ## Integrations
//!
//! The crate aims to be interoperable with other crates via optional dependencies.
//!
//! ### Supported external crates
//!
//! Ativate using features of the same name.
//!
//! * `std` - enables [`P2PAddress`] and implements [`std::error::Error`] for error types.
//!           Enabled by default, implies `alloc.
//! * `alloc` - enables conversions from/to heap-allocated types as well as additional error
//!             information.
//! * [`bitcoin-units`] - converting between types
//! * [`serde`] - serialization and deserialization of types
//! * [`postgres-types`](postgres_types) - storing and retrieving from SQL
//! * [`parse_arg`] - parsing arguments into types in this crate
//! * [`secp256k1`] - provides `NodePubkey`
//! * [`slog`] - provides `slog::Value` and (where relevant) `slog::KV` implementations for the types
//!
//! **Important: some combinations may benefit from additional features!**
//! See below.
//!
//! ### Additional features
//!
//! * `node_pubkey_verify` - convenience function for verifying messages signed with
//!                          [`NodePubkey`], implies `secp256k1/bitcoin_hashes`
//! * `node_pubkey_recovery` - convenience function for verifying lightning messages
//!                            signed with [`NodePubkey`], implies `node_pubkey_verify` and
//!                            `secp256k1/recovery`
//! * `secp256k1_std` - required for [`node_pubkey::ParseError`] to return `secp256k1::Error` from
//!                     `source()` method of [`std::error::Error`]
//! * `serde_alloc` - required for specialization of `serde::de::Visitor::visit_string` method to
//!                   avoid allocation
//! * `slog_std` - required for error types to use [`slog::Serializer::emit_error`] for logging
//!
//! Feel free to contribute your own!
//!
//! **Disclaimer**: Inclusion of any crate here is neither endorsment nor guarantee of it
//! being secure, honest, non-backdoored or functioning! You're required to do your own review of
//! any external crate.
//!
//! The rules around adding a new integration are lax: the dependency must be optional, must
//! **not** be obviously broken or surprising, and must **not** interact with other implementations
//! in surprising ways.
//!
//! ### `no_std` support
//!
//! This crate works without `std` or `alloc` with these limitations/differences:
//!
//! * [`P2PAddress`] is unavailable without `std` on Rust versions older than 1.77
//! * Resolving a socket address requires `std`
//! * Without `std` all error types display all sources delimited by `: `, with `std` they are
//!   returned from the [`source()`](std::error::Error::source) method instead.
//!
//! ## Versioning
//!
//! This crate uses standard Rust Semver with one special exception:
//! **Matching on fully private structs is not allowed and so changing an
//! all-private struct to an enum is considered non-breaking change even
//! though the consumer code matching on it would break!**
//!
//! See [Rust internals discussion](https://internals.rust-lang.org/t/disallow-matching-on-all-private-structs/15993) to learn more.
//!
//! ## MSRV
//!
//! The minimum supported Rust version is 1.48 but it's possible that it'll be decreased further.
//! Generally, the intention is to support at least the latest Debian stable.
//!
//! Note that external libraries may have higher MSRV - this is not considered a breakage.
//! 
//! ## License
//! 
//! MIT

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs)]

#![no_std]

#[cfg(any(feature = "std", test))]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub extern crate std;

#[cfg(any(feature = "alloc", test))]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub extern crate alloc;

#[cfg(feature = "bitcoin-units")]
#[cfg_attr(docsrs, doc(cfg(feature = "bitcoin")))]
pub extern crate bitcoin_units;

#[cfg(feature = "parse_arg")]
#[cfg_attr(docsrs, doc(cfg(feature = "parse_arg")))]
pub extern crate parse_arg;

#[cfg(feature = "postgres-types")]
#[cfg_attr(docsrs, doc(cfg(feature = "postgres-types")))]
pub extern crate postgres_types_real as postgres_types;

#[cfg(feature = "secp256k1")]
#[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
pub extern crate secp256k1;

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub extern crate serde;

#[cfg(feature = "slog")]
#[cfg_attr(docsrs, doc(cfg(feature = "slog")))]
pub extern crate slog;

#[macro_use]
mod macros;
#[macro_use]
pub(crate) mod err_fmt;

pub mod node_id;
#[cfg(any(feature = "std", rust_v_1_77))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "std", version("1.77.0")))))]
pub mod p2p_address;
pub mod amount;
#[cfg(feature = "secp256k1")]
pub mod node_pubkey;

pub use node_id::NodeId;
#[cfg(any(feature = "std", rust_v_1_77))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "std", version("1.77.0")))))]
pub use p2p_address::P2PAddress;
pub use amount::Amount;
#[cfg(feature = "secp256k1")]
#[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
pub use node_pubkey::NodePubkey;
