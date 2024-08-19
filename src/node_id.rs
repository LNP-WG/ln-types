//! Node identifier (encoded pubkey)
//!
//! This module provides the [`NodeId`] type and the related error types.

use core::convert::{TryFrom, TryInto};
use core::str::FromStr;
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

/// Byte representation of a node identifier.
///
/// This type is used when referring to nodes without doing cryptographic operations.
/// It can be used in search algorithms, LN explorers, manager UIs etc.
/// By avoiding cryptography it is significantly more performant but may make debugging harder.
/// It is therefore recommended to perform checking at system boundaries where performance is not
/// very important - e.g. user inputs.
///
/// Despite this not being a guaranteed point on the curve it still performs cheap basic sanity
/// check: whether the key begins with 0x02 or 0x03.
///
/// ## Example
///
/// ```
/// let marvin_str = "029ef8ee0ba895e2807ac1df1987a7888116c468e70f42e7b089e06811b0e45482";
/// let marvin = marvin_str.parse::<ln_types::NodeId>().unwrap();
/// assert_eq!(marvin.to_string(), marvin_str);
/// ```
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NodeId([u8; 33]);

impl NodeId {
    /// Creates `NodeId` from raw byte representation.
    #[inline]
    pub fn from_raw_bytes(bytes: [u8; 33]) -> Result<Self, InvalidNodeId> {
        if bytes[0] == 0x02 || bytes[0] == 0x03 {
            Ok(NodeId(bytes))
        } else {
            Err(InvalidNodeId { bad_byte: bytes[0], })
        }
    }

    /// Puts the byte representation into `Vec<u8>`.
    ///
    /// This is meant for convenience around APIs that require `Vec<u8>`. Since it allocates it's
    /// best to avoid it if possible.
    #[cfg(feature = "alloc")]
    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Convenience conversion to byte array.
    ///
    /// This can be used instead of `From` to avoid inference issues.
    pub fn to_array(self) -> [u8; 33] {
        self.0
    }

    /// Internal monomorphic parsing method.
    ///
    /// This should improve codegen without requiring allocations.
    pub(crate) fn parse_raw(s: &str) -> Result<Self, ParseErrorInner> {
        fn decode_digit(digit: u8, pos: usize, s: &str) -> Result<u8, ParseErrorInner> {
            match digit {
                b'0'..=b'9' => Ok(digit - b'0'),
                b'a'..=b'f' => Ok(digit - b'a' + 10),
                b'A'..=b'F' => Ok(digit - b'A' + 10),
                _ => Err(ParseErrorInner::Char { pos, c: s.chars().nth(pos).unwrap(), }),
            }
        }

        let mut result = [0; 33];

        if s.len() != 66 {
            return Err(ParseErrorInner::Length)
        }

        for ((i, pair), dst) in s.as_bytes().chunks_exact(2).enumerate().zip(&mut result) {
            *dst = decode_digit(pair[0], i * 2, s)? * 16 + decode_digit(pair[1], i * 2 + 1, s)?;
        }

        Self::from_raw_bytes(result).map_err(Into::into)
    }

    /// Generic wrapper for parsing that is used to implement parsing from multiple types.
    #[cfg(feature = "alloc")]
    #[inline]
    fn internal_parse<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, ParseError> {
        Self::parse_raw(s.as_ref()).map_err(|error| ParseError {
            input: s.into(),
            reason: error,
        })
    }

    #[cfg(not(feature = "alloc"))]
    #[inline]
    fn internal_parse<S: AsRef<str>>(s: S) -> Result<Self, ParseError> {
        Self::parse_raw(s.as_ref()).map_err(|error| ParseError {
            reason: error,
        })
    }
    /// Writes the fill character required number of times.
    #[cfg(not(feature = "hex-conservative"))]
    fn prefill(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write;

        if let Some(width) = f.width() {
            for _ in 0..width.saturating_sub(66) {
                f.write_char(f.fill())?;
            }
        }
        Ok(())
    }
}

/// Shows `NodeId` as hex
impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

/// Same as Display
impl fmt::Debug for NodeId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Same as Display
impl fmt::LowerHex for NodeId {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "hex-conservative")]
        {
            hex_conservative::fmt_hex_exact!(f, 33, &self.0, hex_conservative::Case::Lower)
        }

        #[cfg(not(feature = "hex-conservative"))]
        {
            self.prefill(f)?;
            for byte in &self.0 {
                write!(f, "{:02x}", byte)?;
            }
            Ok(())
        }
    }
}

/// As `Display` but with upper-case letters
impl fmt::UpperHex for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[cfg(feature = "hex-conservative")]
        {
            hex_conservative::fmt_hex_exact!(f, 33, &self.0, hex_conservative::Case::Upper)
        }

        #[cfg(not(feature = "hex-conservative"))]
        {
            self.prefill(f)?;
            for byte in &self.0 {
                write!(f, "{:02X}", byte)?;
            }
            Ok(())
        }
    }
}

/// Expects hex representation
impl FromStr for NodeId {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::internal_parse(s)
    }
}

/// Expects hex representation
impl<'a> TryFrom<&'a str> for NodeId {
    type Error = ParseError;

    #[inline]
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

/// Expects hex representation
#[cfg(feature = "alloc")]
impl TryFrom<String> for NodeId {
    type Error = ParseError;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

/// Expects hex representation
#[cfg(feature = "alloc")]
impl TryFrom<Box<str>> for NodeId {
    type Error = ParseError;

    #[inline]
    fn try_from(s: Box<str>) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

impl<'a> TryFrom<&'a [u8]> for NodeId {
    type Error = DecodeError;

    #[inline]
    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        let bytes = slice.try_into()
            .map_err(|_| DecodeError { error: DecodeErrorInner::InvalidLen(slice.len()) })?;

        NodeId::from_raw_bytes(bytes).map_err(Into::into)
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Vec<u8>> for NodeId {
    type Error = DecodeError;

    #[inline]
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        (*vec).try_into()
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Box<[u8]>> for NodeId {
    type Error = DecodeError;

    #[inline]
    fn try_from(slice: Box<[u8]>) -> Result<Self, Self::Error> {
        (*slice).try_into()
    }
}

impl From<NodeId> for [u8; 33] {
    fn from(value: NodeId) -> Self {
        value.0
    }
}

impl AsRef<[u8; 33]> for NodeId {
    fn as_ref(&self) -> &[u8; 33] {
        &self.0
    }
}

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::borrow::Borrow<[u8; 33]> for NodeId {
    fn borrow(&self) -> &[u8; 33] {
        &self.0
    }
}

impl core::borrow::Borrow<[u8]> for NodeId {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

/// Error returned when decoding raw bytes fails
///
/// **Important: consumer code MUST NOT match on this using `DecodeError { .. }` syntax.
#[derive(Debug, Clone)]
pub struct DecodeError {
    error: DecodeErrorInner,
}

#[derive(Debug, Clone)]
enum DecodeErrorInner {
    InvalidLen(usize),
    InvalidNodeId(InvalidNodeId),
}

impl From<InvalidNodeId> for DecodeError {
    fn from(value: InvalidNodeId) -> Self {
        DecodeError {
            error: DecodeErrorInner::InvalidNodeId(value),
        }
    }
}


impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.error {
            DecodeErrorInner::InvalidLen(len) => write!(f, "invalid length {} bytes, the lenght must be 33 bytes", len),
            DecodeErrorInner::InvalidNodeId(error) => write_err!(f, "invalid node ID"; error),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.error {
            DecodeErrorInner::InvalidLen(_) => None,
            DecodeErrorInner::InvalidNodeId(error) => Some(error),
        }
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

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "failed to parse{} Lightning Network node ID", opt_fmt!("alloc", format_args!(" '{}' as", &self.input)); &self.reason)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.reason)
    }
}

/// Details about the error.
///
/// This is private to avoid committing to a representation.
#[derive(Debug, Clone)]
pub(crate) enum ParseErrorInner {
    /// Length != 66 chars
    Length,
    Char { pos: usize, c: char, },
    NodeId(InvalidNodeId),
}

impl fmt::Display for ParseErrorInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseErrorInner::Length => f.write_str("invalid length (must be 66 chars)"),
            ParseErrorInner::Char { c, pos, } => write!(f, "invalid character '{}' at position {} (must be hex digit)", c, pos),
            ParseErrorInner::NodeId(error) => write_err!(f, "invalid node ID"; error),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseErrorInner {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseErrorInner::Length | ParseErrorInner::Char { .. } => None,
            ParseErrorInner::NodeId(error) => Some(error),
        }
    }
}

impl From<InvalidNodeId> for ParseErrorInner {
    fn from(value: InvalidNodeId) -> Self {
        ParseErrorInner::NodeId(value)
    }
}

/// Error returned when attempting to convert bytes to `NodeId`
///
/// Conversions to `NodeId` perform a cheap basic sanity check and return this error if it doesn't
/// pass.
///
/// **Important: consumer code MUST NOT match on this using `InvalidNodeId { .. }` syntax.
#[derive(Debug, Clone)]
pub struct InvalidNodeId {
    bad_byte: u8,
}

impl fmt::Display for InvalidNodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // We currently only detect zeroth byte
        write!(f, "invalid zeroth byte 0x{:02x}", self.bad_byte)?;
        Ok(())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidNodeId {}

/// Implementation of `parse_arg::ParseArg` trait
#[cfg(feature = "parse_arg")]
mod parse_arg_impl {
    use core::fmt;
    use super::NodeId;

    impl parse_arg::ParseArgFromStr for NodeId {
        fn describe_type<W: fmt::Write>(mut writer: W) -> fmt::Result {
            writer.write_str("a hex-encoded LN node ID (66 hex digits/33 bytes)")
        }
    }
}

/// Implementations of `serde` traits
#[cfg(feature = "serde")]
mod serde_impl {
    use core::fmt;
    use super::NodeId;
    use serde::{Serialize, Deserialize, Serializer, Deserializer, de::{Visitor, Error}};
    use core::convert::TryFrom;

    /// Visitor for human-readable formats
    struct HRVisitor;

    impl<'de> Visitor<'de> for HRVisitor {
        type Value = NodeId;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a 66 digits long hex string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: Error {
            use super::ParseErrorInner;

            NodeId::parse_raw(v).map_err(|error| {
                match error {
                    ParseErrorInner::Length => E::invalid_length(v.len(), &"66 hex digits beginning with 02 or 03"),
                    ParseErrorInner::Char { c, pos: _, } => E::invalid_value(serde::de::Unexpected::Char(c), &"a hex digit"),
                    ParseErrorInner::NodeId(error) => E::invalid_value(serde::de::Unexpected::Bytes(&[error.bad_byte]), &"02 or 03"),
                }
            })
        }
    }

    /// Visitor for non-human-readable (binary) formats
    struct BytesVisitor;

    impl<'de> Visitor<'de> for BytesVisitor {
        type Value = NodeId;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("33 bytes")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E> where E: Error {
            use super::DecodeErrorInner;

            NodeId::try_from(v).map_err(|error| {
                match error.error {
                    DecodeErrorInner::InvalidLen(len) => E::invalid_length(len, &"33 bytes"),
                    DecodeErrorInner::InvalidNodeId(error) => E::invalid_value(serde::de::Unexpected::Bytes(&[error.bad_byte]), &"02 or 03"),
                }
            })
        }
    }

    /// `NodeId` is serialized as hex to human-readable formats and as bytes to non-human-readable.
    impl Serialize for NodeId {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
            if serializer.is_human_readable() {
                serializer.collect_str(self)
            } else {
                serializer.serialize_bytes(&self.0)        
            }
        }
    }

    /// `NodeId` is deserialized as hex from human-readable formats and as bytes from non-human-readable.
    impl<'de> Deserialize<'de> for NodeId {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                deserializer.deserialize_str(HRVisitor)
            } else {
                deserializer.deserialize_bytes(BytesVisitor)
            }
        }
    }
}

/// Implementations of `postgres-types` traits
#[cfg(feature = "postgres-types")]
mod postgres_impl {
    use alloc::boxed::Box;
    use super::NodeId;
    use postgres_types::{ToSql, FromSql, IsNull, Type};
    use bytes::BytesMut;
    use std::error::Error;
    use core::convert::TryInto;

    /// Supports `BYTEA`, `TEXT`, and `VARCHAR`.
    ///
    /// Stored as bytes if `BYTEA` is used, as hex string otherwise.
    impl ToSql for NodeId {
        fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Send + Sync + 'static>> {
            use core::fmt::Write;

            match *ty {
                Type::BYTEA => (&self.0 as &[_]).to_sql(ty, out),
                _ => write!(out, "{}", self).map(|_| IsNull::No).map_err(|error| Box::new(error) as _)
            }
        }

        fn accepts(ty: &Type) -> bool {
            match *ty {
                Type::BYTEA => true,
                Type::TEXT => true,
                Type::VARCHAR => true,
                _ => false,
            }
        }

        postgres_types::to_sql_checked!();
    }

    /// Supports `BYTEA`, `TEXT`, and `VARCHAR`.
    ///
    /// Decoded as bytes if `BYTEA` is used, as hex string otherwise.
    impl<'a> FromSql<'a> for NodeId {
        fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
            match *ty {
                Type::BYTEA => <&[u8]>::from_sql(ty, raw)?.try_into().map_err(|error| Box::new(error) as _),
                _ => <&str>::from_sql(ty, raw)?.parse().map_err(|error| Box::new(error) as _),
            }
        }

        fn accepts(ty: &Type) -> bool {
            match *ty {
                Type::BYTEA => true,
                Type::TEXT => true,
                Type::VARCHAR => true,
                _ => false,
            }
        }
    }
}

/// Implementations of `slog` traits
#[cfg(feature = "slog")]
mod slog_impl {
    use super::NodeId;
    use slog::{Key, Value, Record, Serializer};

    /// Currently uses `Display` but may use `emit_bytes` if/when it's implemented.
    impl Value for NodeId {
        fn serialize(&self, _rec: &Record, key: Key, serializer: &mut dyn Serializer) -> slog::Result {
            serializer.emit_arguments(key, &format_args!("{}", self))
        }
    }

    impl_error_value!(super::ParseError, super::DecodeError);
}

#[cfg(test)]
mod tests {
    use super::NodeId;

    #[test]
    fn empty() {
        assert!("".parse::<NodeId>().is_err());
    }

    #[test]
    fn one_less() {
        assert!("02234567890123456789012345678901234567890123456789012345678901234".parse::<NodeId>().is_err());
    }

    #[test]
    fn one_more() {
        assert!("0223456789012345678901234567890123456789012345678901234567890123456".parse::<NodeId>().is_err());
    }

    #[test]
    fn invalid_node_id() {
        assert!("012345678901234567890123456789012345678901234567890123456789abcdef".parse::<NodeId>().is_err());
    }

    #[test]
    fn correct_02() {
        let parsed = "022345678901234567890123456789012345678901234567890123456789abcdef".parse::<NodeId>().unwrap();
        let expected = b"\x02\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\xab\xcd\xef";
        assert_eq!(parsed.0, *expected);
    }

    #[test]
    fn correct_03() {
        let parsed = "032345678901234567890123456789012345678901234567890123456789abcdef".parse::<NodeId>().unwrap();
        let expected = b"\x03\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\xab\xcd\xef";
        assert_eq!(parsed.0, *expected);
    }

    #[test]
    fn invalid_digit() {
        assert!("g12345678901234567890123456789012345678901234567890123456789012345".parse::<NodeId>().is_err());
    }

    chk_err_impl! {
        parse_node_id_error_empty, "", NodeId, [
            "failed to parse '' as Lightning Network node ID",
            "invalid length (must be 66 chars)",
        ], [
            "failed to parse Lightning Network node ID",
            "invalid length (must be 66 chars)",
        ];
    }
}
