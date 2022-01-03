//! Newtype over `PublicKey` and corresponding error types.
//!
//! This module makes working with node public key easier by providing `NodePubkey` newtype.
//! This makes it less likely that the node public key will be mistaken for other public key.
//! Further, it provides convenient parsing, serialization and signature verification methods
//! along with strong error types.

#![cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]

use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use std::fmt;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use crate::NodeId;

/// Newtype over `secp256k1::PublicKey` representing a deserialized key identifying an LN node.
///
/// This can be considered similar to `NodeId` with these differences:
///
/// * `NodeId` is more performant for non-cryptographic operations.
/// * `NodeId` can not perform any cryptographic operations itself.
/// * `NodePubkey`, despite its field being public, maintains more invariants.
///    *In this library*, a valid `NodeId` is **not** guaranteed to be a valid `NodePubkey`
#[derive(Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct NodePubkey(
    /// The underlying public key used for cryptographic operations.
    pub PublicKey
);

impl NodePubkey {
    /// Verify a message signed by this key.
    ///
    /// This is a convenience method that simply uses slices.
    /// While this could be seen as regression from strongly-typed [`secp256k1`] library, it should
    /// be a good tradeoff here. The reason is we know that LN signatures are **not** DER-encoded
    /// and there shouldn't be a reason to need to keep message hash around.
    ///
    /// If you need anything advanced, you can still use the raw [`secp256k1::PublicKey`].
    #[cfg(feature = "secp256k1/bitcoin_hashes")]
    #[cfg_attr(docsrs, doc(cfg(feature = "secp256k1/bitcoin_hashes")))]
    pub fn verify<C: secp256k1::Verification>(&self, secp: &Secp256k1<C>, message: &[u8], signature: &[u8]) -> Result<(), secp256k1::Error> {
        use secp256k1::{Signature, Message};

        let signature = Signature::from_compact(signature)?;
        let message = Message::from_hashed_data(message);

        secp.verify(&message, &signature, &self.0)
    }

    /// Generic wrapper for parsing that is used to implement parsing from multiple types.
    fn internal_parse<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, ParseError> {
        match NodeId::parse_raw(s.as_ref()) {
            Ok(node_id) => {
                node_id.try_into()
                    .map_err(|error| ParseError {
                        input: s.into(),
                        reason: ParseErrorInner::Pubkey(error),
                    })
            },
            Err(error) => {
                Err(ParseError {
                    input: s.into(),
                    reason: ParseErrorInner::NodeId(error),
                })
            }
        }
    }

    /// Convenience conversion method.
    ///
    /// This is more readable and less prone to inference problems than `Into::into`.
    pub fn to_node_id(&self) -> NodeId {
        NodeId::from_raw_bytes(self.0.serialize())
    }

    /// Computes public key from a secret key and stores it as `NodePubkey`.
    pub fn from_secret_key<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: &SecretKey) -> Self {
        NodePubkey(PublicKey::from_secret_key(secp, sk))
    }
}

/// Shows `NodePubkey` as hex
impl fmt::Display for NodePubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.to_node_id(), f)
    }
}

impl fmt::Debug for NodePubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.to_node_id(), f)
    }
}

impl fmt::LowerHex for NodePubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.to_node_id(), f)
    }
}

impl fmt::UpperHex for NodePubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.to_node_id(), f)
    }
}

impl TryFrom<NodeId> for NodePubkey {
    type Error = secp256k1::Error;

    fn try_from(value: NodeId) -> Result<Self, Self::Error> {
        Ok(NodePubkey(PublicKey::from_slice(value.as_ref())?))
    }
}

impl From<NodePubkey> for NodeId {
    fn from(value: NodePubkey) -> Self {
        value.to_node_id()
    }
}

impl<'a> From<&'a NodePubkey> for NodeId {
    fn from(value: &'a NodePubkey) -> Self {
        value.to_node_id()
    }
}

impl AsRef<PublicKey> for NodePubkey {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

impl AsMut<PublicKey> for NodePubkey {
    fn as_mut(&mut self) -> &mut PublicKey {
        &mut self.0
    }
}

impl std::borrow::Borrow<PublicKey> for NodePubkey {
    fn borrow(&self) -> &PublicKey {
        &self.0
    }
}

impl std::borrow::BorrowMut<PublicKey> for NodePubkey {
    fn borrow_mut(&mut self) -> &mut PublicKey {
        &mut self.0
    }
}

/// Expects hex representation
impl FromStr for NodePubkey {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::internal_parse(s)
    }
}

/// Expects hex representation
impl<'a> TryFrom<&'a str> for NodePubkey {
    type Error = ParseError;

    #[inline]
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

/// Expects hex representation
impl TryFrom<String> for NodePubkey {
    type Error = ParseError;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

/// Expects hex representation
impl TryFrom<Box<str>> for NodePubkey {
    type Error = ParseError;

    #[inline]
    fn try_from(s: Box<str>) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

impl<'a> TryFrom<&'a [u8]> for NodePubkey {
    type Error = secp256k1::Error;

    #[inline]
    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(NodePubkey(PublicKey::from_slice(slice)?))
    }
}

impl TryFrom<Vec<u8>> for NodePubkey {
    type Error = secp256k1::Error;

    #[inline]
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        (*vec).try_into()
    }
}

impl TryFrom<Box<[u8]>> for NodePubkey {
    type Error = secp256k1::Error;

    #[inline]
    fn try_from(slice: Box<[u8]>) -> Result<Self, Self::Error> {
        (*slice).try_into()
    }
}

impl From<NodePubkey> for [u8; 33] {
    fn from(value: NodePubkey) -> Self {
        value.to_node_id().into()
    }
}

/// Error returned when parsing text representation fails.
#[derive(Debug, Clone)]
pub struct ParseError {
    /// The string that was attempted to be parsed
    input: String,
    /// Information about what exactly went wrong
    reason: ParseErrorInner,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "failed to parse '{}' as Lightning Network node public key", self.input)
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.reason {
            ParseErrorInner::NodeId(error) => error.source(),
            ParseErrorInner::Pubkey(error) => error.source(),
        }
    }
}

/// Details about the error.
///
/// This is private to avoid committing to a representation.
#[derive(Debug, Clone)]
enum ParseErrorInner {
    /// Length != 66 chars
    NodeId(crate::node_id::ParseErrorInner),
    Pubkey(secp256k1::Error),
}

/// Implementation of `parse_arg::ParseArg` trait
#[cfg(feature = "parse_arg")]
mod parse_arg_impl {
    use std::fmt;
    use super::NodePubkey;

    #[cfg_attr(docsrs, doc(cfg(feature = "parse_arg")))]
    impl parse_arg::ParseArgFromStr for NodePubkey {
        fn describe_type<W: fmt::Write>(mut writer: W) -> fmt::Result {
            writer.write_str("a hex-encoded LN node ID (66 hex digits/33 bytes)")
        }
    }
}

#[cfg(all(feature = "serde", feature = "secp256k1/serde"))]
mod serde_impls {
    use serde::{Serialize, Deserialize, Serializer, Deserializer};
    use super::NodePubkey;
    use secp256k1::PublicKey;

    /// `NodePubkey` is transparently serialized `secp256k1::PublicKey`
    #[cfg_attr(all(feature = "serde", feature = "secp256k1/serde"))]
    impl Serialize for NodePubkey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
            Seialize::serialize(&self.0, serializer)
        }
    }

    /// `NodePubkey` is transparently deserialized `secp256k1::PublicKey`
    #[cfg_attr(all(feature = "serde", feature = "secp256k1/serde"))]
    impl<'de> Deserialize<'de> for NodePubkey {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
            Ok(PublicKey::deserialize(deserializer)?)
        }
    }
}

/// Implementations of `postgres-types` traits
#[cfg(feature = "postgres-types")]
mod postgres_impl {
    use super::NodePubkey;
    use crate::NodeId;
    use postgres_types::{ToSql, FromSql, IsNull, Type};
    use bytes::BytesMut;
    use std::error::Error;
    use std::convert::TryInto;

    /// Supports `BYTEA`, `TEXT`, and `VARCHAR`.
    ///
    /// Stored as bytes if `BYTEA` is used, as hex string otherwise.
    #[cfg_attr(docsrs, doc(cfg(feature = "postgres-types")))]
    impl ToSql for NodePubkey {
        fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Send + Sync + 'static>> {
            self.to_node_id().to_sql(ty, out)
        }

        fn accepts(ty: &Type) -> bool {
            <NodeId as ToSql>::accepts(ty)
        }

        postgres_types::to_sql_checked!();
    }

    /// Supports `BYTEA`, `TEXT`, and `VARCHAR`.
    ///
    /// Decoded as bytes if `BYTEA` is used, as hex string otherwise.
    #[cfg_attr(docsrs, doc(cfg(feature = "postgres-types")))]
    impl<'a> FromSql<'a> for NodePubkey {
        fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
            NodeId::from_sql(ty, raw)?.try_into().map_err(|error| Box::new(error) as _)
        }

        fn accepts(ty: &Type) -> bool {
            <NodeId as FromSql>::accepts(ty)
        }
    }
}

/// Implementations of `slog` traits
#[cfg(feature = "slog")]
mod slog_impl {
    use super::NodePubkey;
    use slog::{Key, Value, Record, Serializer};

    /// Currently uses `Display` but may use `emit_bytes` if/when it's implemented.
    #[cfg_attr(docsrs, doc(cfg(feature = "slog")))]
    impl Value for NodePubkey {
        fn serialize(&self, _rec: &Record, key: Key, serializer: &mut dyn Serializer) -> slog::Result {
            serializer.emit_arguments(key, &format_args!("{}", self))
        }
    }

    impl_error_value!(super::ParseError);
}