//! Newtype over `PublicKey` and corresponding error types.
//!
//! This module makes working with node public key easier by providing `NodePubkey` newtype.
//! This makes it less likely that the node public key will be mistaken for other public key.
//! Further, it provides convenient parsing, serialization and signature verification methods
//! along with strong error types.

#![cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]

use core::convert::{TryFrom, TryInto};
use core::str::FromStr;
use core::fmt;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use crate::NodeId;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

/// Newtype over `secp256k1::PublicKey` representing a deserialized key identifying an LN node.
///
/// This can be considered similar to `NodeId` with these differences:
///
/// * `NodeId` is more performant for non-cryptographic operations.
/// * `NodeId` can not perform any cryptographic operations itself.
/// * `NodePubkey`, despite its field being public, maintains more invariants.
///    *In this library*, a valid `NodeId` is **not** guaranteed to be a valid `NodePubkey`
///
/// ## Example
///
/// ```
/// let marvin_str = "029ef8ee0ba895e2807ac1df1987a7888116c468e70f42e7b089e06811b0e45482";
/// let marvin = marvin_str.parse::<ln_types::NodePubkey>().unwrap();
/// assert_eq!(marvin.to_string(), marvin_str);
/// ```
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
    ///
    /// ## Example
    ///
    /// ```
    /// use ln_types::secp256k1::hashes::{sha256d, Hash};
    ///
    /// let marvin_str = "029ef8ee0ba895e2807ac1df1987a7888116c468e70f42e7b089e06811b0e45482";
    /// let marvin = marvin_str.parse::<ln_types::NodePubkey>().unwrap();
    /// let message = "Lightning Signed Message:I am the author of `ln-types` Rust crate.";
    /// let signature = &[0x29, 0x79, 0x4d, 0x9a, 0x6a, 0x48, 0x68, 0x0f, 0x9b, 0x8d, 0x60, 0x97, 0xa6, 0xd8, 0xef, 0x1d, 0x5c, 0xf9, 0xdc, 0x27, 0xcd, 0x76, 0x9a, 0x86, 0x58, 0xd6, 0x94, 0x00, 0x1c, 0x12, 0xb8, 0xdd, 0x49, 0xaf, 0x2b, 0xca, 0x0a, 0x24, 0xd8, 0xf4, 0x5a, 0x3b, 0x3c, 0xc7, 0x87, 0xf0, 0x48, 0x60, 0x63, 0x23, 0xf4, 0x24, 0xba, 0xa8, 0x0f, 0x5e, 0xe6, 0x05, 0x79, 0x81, 0xe2, 0x29, 0x6f, 0x0d];
    /// let secp = ln_types::secp256k1::Secp256k1::verification_only();
    /// let message = sha256d::Hash::hash(message.as_bytes());
    /// let message = secp256k1::Message::from_digest(message.to_byte_array());
    ///
    /// marvin.verify(&secp, message, signature).unwrap();
    /// ```
    #[cfg(feature = "node_pubkey_verify")]
    #[cfg_attr(docsrs, doc(cfg(feature = "node_pubkey_verify")))]
    pub fn verify<M: Into<secp256k1::Message>, C: secp256k1::Verification>(&self, secp: &Secp256k1<C>, message: M, signature: &[u8]) -> Result<(), secp256k1::Error> {
        use secp256k1::ecdsa::Signature;

        let signature = Signature::from_compact(signature)?;
        let message = message.into();

        secp.verify_ecdsa(&message, &signature, &self.0)
    }

    /// Verifies a message signed by `signmessage` Eclair/LND RPC.
    ///
    /// The signatures of messages returned by node RPCs are not so simple.
    /// They prefix messages with `Lightning Signed Message:`, use double sha256 and recovery.
    /// It is the reason why this function requires the `recovery` feature of [`secp256k1`].
    ///
    /// This function takes care of all that complexity for you so that you can verify the messages
    /// conveniently.
    ///
    /// ## Example
    ///
    /// ```
    /// let marvin_str = "029ef8ee0ba895e2807ac1df1987a7888116c468e70f42e7b089e06811b0e45482";
    /// let marvin = marvin_str.parse::<ln_types::NodePubkey>().unwrap();
    /// let message = "I am the author of `ln-types` Rust crate.";
    /// let signature = &[0x1f, 0x29, 0x79, 0x4d, 0x9a, 0x6a, 0x48, 0x68, 0x0f, 0x9b, 0x8d, 0x60, 0x97, 0xa6, 0xd8, 0xef, 0x1d, 0x5c, 0xf9, 0xdc, 0x27, 0xcd, 0x76, 0x9a, 0x86, 0x58, 0xd6, 0x94, 0x00, 0x1c, 0x12, 0xb8, 0xdd, 0x49, 0xaf, 0x2b, 0xca, 0x0a, 0x24, 0xd8, 0xf4, 0x5a, 0x3b, 0x3c, 0xc7, 0x87, 0xf0, 0x48, 0x60, 0x63, 0x23, 0xf4, 0x24, 0xba, 0xa8, 0x0f, 0x5e, 0xe6, 0x05, 0x79, 0x81, 0xe2, 0x29, 0x6f, 0x0d];
    /// let secp = ln_types::secp256k1::Secp256k1::verification_only();
    ///
    /// marvin.verify_lightning_message(&secp, message.as_bytes(), signature).unwrap();
    /// ```
    #[cfg(feature = "node_pubkey_recovery")]
    #[cfg_attr(docsrs, doc(cfg(feature = "node_pubkey_recovery")))]
    pub fn verify_lightning_message<C: secp256k1::Verification>(&self, secp: &Secp256k1<C>, message: &[u8], signature: &[u8]) -> Result<(), secp256k1::Error> {
        use secp256k1::Message;
        use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
        use secp256k1::hashes::{sha256, sha256d, HashEngine, Hash};

        let (recovery_id, signature) = signature
            .split_first()
            .ok_or(secp256k1::Error::InvalidSignature)?;

        let recovery_id = recovery_id
            .checked_sub(0x1f)
            .ok_or(secp256k1::Error::InvalidSignature)?;

        let recovery_id = RecoveryId::from_i32(recovery_id.into())?;
        let signature = RecoverableSignature::from_compact(signature, recovery_id)?;
        let mut hasher = sha256::HashEngine::default();
        hasher.input(b"Lightning Signed Message:");
        hasher.input(message);
        let hash = sha256d::Hash::from_engine(hasher);
        let message = Message::from_digest(hash.to_byte_array());

        let pubkey = secp.recover_ecdsa(&message, &signature)?;
        if pubkey == self.0 {
            Ok(())
        } else {
            Err(secp256k1::Error::IncorrectSignature)
        }
    }

    /// Generic wrapper for parsing that is used to implement parsing from multiple types.
    #[cfg(feature = "alloc")]
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

    /// Generic wrapper for parsing that is used to implement parsing from multiple types.
    #[cfg(not(feature = "alloc"))]
    fn internal_parse<S: AsRef<str>>(s: S) -> Result<Self, ParseError> {
        match NodeId::parse_raw(s.as_ref()) {
            Ok(node_id) => {
                node_id.try_into()
                    .map_err(|error| ParseError {
                        reason: ParseErrorInner::Pubkey(error),
                    })
            },
            Err(error) => {
                Err(ParseError {
                    reason: ParseErrorInner::NodeId(error),
                })
            }
        }
    }

    /// Convenience conversion method.
    ///
    /// This is more readable and less prone to inference problems than `Into::into`.
    pub fn to_node_id(&self) -> NodeId {
        NodeId::from_raw_bytes(self.0.serialize()).expect("secp256k1 always creates correct node ID")
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

impl core::borrow::Borrow<PublicKey> for NodePubkey {
    fn borrow(&self) -> &PublicKey {
        &self.0
    }
}

impl core::borrow::BorrowMut<PublicKey> for NodePubkey {
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
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl TryFrom<String> for NodePubkey {
    type Error = ParseError;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

/// Expects hex representation
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
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

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
impl TryFrom<Vec<u8>> for NodePubkey {
    type Error = secp256k1::Error;

    #[inline]
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        (*vec).try_into()
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
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
///
/// **Important: consumer code MUST NOT match on this using `ParseError { .. }` syntax.
#[derive(Debug, Clone)]
pub struct ParseError {
    /// The string that was attempted to be parsed
    #[cfg(feature = "alloc")]
    input: String,
    /// Information about what exactly went wrong
    reason: ParseErrorInner,
}

/// **Behaves strangely if `std` is enabled without `secp256k1_std`!**
///
/// Specifically pubkey error is displayed inline instead of as a source.
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "failed to parse{} Lightning Network node public key", opt_fmt!("alloc", format_args!(" '{}' as", &self.input)); &self.reason)
    }
}

/// **Behaves strangely if `std` is enabled without `secp256k1_std`!**
///
/// Specifically pubkey error is displayed inline instead of as a source.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
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

impl fmt::Display for ParseErrorInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseErrorInner::NodeId(error) => write_err!(f, "invalid node ID"; error),
            ParseErrorInner::Pubkey(error) => write_err_ext!("secp256k1_std", f, "invalid public key"; error),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for ParseErrorInner {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            ParseErrorInner::NodeId(error) => Some(error),
            #[cfg(feature = "secp256k1_std")]
            ParseErrorInner::Pubkey(error) => Some(error),
            #[cfg(not(feature = "secp256k1_std"))]
            ParseErrorInner::Pubkey(_) => None,
        }
    }
}

/// Implementation of `parse_arg::ParseArg` trait
#[cfg(feature = "parse_arg")]
mod parse_arg_impl {
    use core::fmt;
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
    use alloc::boxed::Box;
    use super::NodePubkey;
    use crate::NodeId;
    use postgres_types::{ToSql, FromSql, IsNull, Type};
    use bytes::BytesMut;
    use std::error::Error;
    use core::convert::TryInto;

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

#[cfg(test)]
mod tests {
    use super::NodePubkey;

    #[test]
    fn empty() {
        let error = "".parse::<NodePubkey>().unwrap_err();
        #[cfg(feature = "alloc")]
        assert_eq!(error.input, "");
        match &error.reason {
            super::ParseErrorInner::NodeId(_) => (),
            super::ParseErrorInner::Pubkey(error) => panic!("unexpected error variant: Pubkey({:?})", error),
        }
    }

    chk_err_impl! {
        parse_node_pubkey_error_empty, "", NodePubkey, [
            "failed to parse '' as Lightning Network node public key",
            "invalid node ID",
            "invalid length (must be 66 chars)",
        ], [
            "failed to parse Lightning Network node public key",
            "invalid node ID",
            "invalid length (must be 66 chars)",
        ];
    }

    #[cfg(any(not(feature = "std"), feature = "secp256k1_std"))]
    chk_err_impl! {
        parse_node_pubkey_error_invalid_pubkey, "020000000000000000000000000000000000000000000000000000000000000000", NodePubkey, [
            "failed to parse '020000000000000000000000000000000000000000000000000000000000000000' as Lightning Network node public key",
            "invalid public key",
            "malformed public key",
        ], [
            "failed to parse Lightning Network node public key",
            "invalid public key",
            "malformed public key",
        ];
    }

    #[cfg(all(feature = "std", not(feature = "secp256k1_std")))]
    chk_err_impl! {
        parse_node_pubkey_error_invalid_pubkey, "020000000000000000000000000000000000000000000000000000000000000000", NodePubkey, [
            "failed to parse '020000000000000000000000000000000000000000000000000000000000000000' as Lightning Network node public key",
            "invalid public key: malformed public key",
        ], [
            "irrelevant, we definitely have std and thus alloc",
        ];
    }
}
