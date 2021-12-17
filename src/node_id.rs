//! Node identifier (encoded pubkey)
//!
//! This module provides the [`NodeId`] type and the related error types.

use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use std::fmt;

/// Byte representation of a node identifier.
///
/// This type is used when referring to nodes without doing cryptographic operations.
/// It can be used in search algorithms, LN explorers, manager UIs etc.
/// By avoiding cryptography it is significantly more performant but may make debugging harder.
/// It is therefore recommended to perform checking at system boundaries where performance is not
/// very important - e.g. user inputs.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NodeId([u8; 33]);

impl NodeId {
    /// Creates `NodeId` from raw byte representation.
    #[inline]
    pub fn from_raw_bytes(bytes: [u8; 33]) -> Self {
        NodeId(bytes)
    }

    /// Puts the byte representation into `Vec<u8>`.
    ///
    /// This is meant for convenience around APIs that require `Vec<u8>`. Since it allocates it's
    /// best to avoid it if possible.
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
                _ => Err(ParseErrorInner::InvalidChar { pos, c: s.chars().nth(pos).unwrap(), }),
            }
        }

        let mut result = [0; 33];

        if s.len() != 66 {
            return Err(ParseErrorInner::InvalidLen)
        }

        for ((i, pair), dst) in s.as_bytes().chunks_exact(2).enumerate().zip(&mut result) {
            *dst = decode_digit(pair[0], i * 2, s)? * 16 + decode_digit(pair[1], i * 2 + 1, s)?;
        }

        Ok(NodeId(result))
    }

    /// Generic wrapper for parsing that is used to implement parsing from multiple types.
    #[inline]
    fn internal_parse<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, ParseError> {
        Self::parse_raw(s.as_ref()).map_err(|error| ParseError {
            input: s.into(),
            reason: error,
        })
    }

    /// Writes the fill character required number of times.
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
        self.prefill(f)?;
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
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
        fmt::Display::fmt(self, f)
    }
}

/// As `Display` but with upper-case letters
impl fmt::UpperHex for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.prefill(f)?;
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
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
impl TryFrom<String> for NodeId {
    type Error = ParseError;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

/// Expects hex representation
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
        Ok(NodeId(slice.try_into().map_err(|_| DecodeError { len: slice.len() })?))
    }
}

impl TryFrom<Vec<u8>> for NodeId {
    type Error = DecodeError;

    #[inline]
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        (*vec).try_into()
    }
}

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

impl std::borrow::Borrow<[u8; 33]> for NodeId {
    fn borrow(&self) -> &[u8; 33] {
        &self.0
    }
}

impl std::borrow::Borrow<[u8]> for NodeId {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

/// Error returned when decoding raw bytes fails
#[derive(Debug)]
pub struct DecodeError {
    len: usize,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid length {} bytes, the lenght must be 33 bytes", self.len)
    }
}

impl std::error::Error for DecodeError {}

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
        write!(f, "failed to parse '{}' as Lightning Network node ID", self.input)
    }
}

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
    InvalidLen,
    InvalidChar { pos: usize, c: char, },
}

impl fmt::Display for ParseErrorInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseErrorInner::InvalidLen => f.write_str("invalid length (must be 66 chars)"),
            ParseErrorInner::InvalidChar { c, pos, } => write!(f, "invalid character '{}' at position {} (must be hex digit)", c, pos),
        }
    }
}

impl std::error::Error for ParseErrorInner {}

/// Implementation of `parse_arg::ParseArg` trait
#[cfg(feature = "parse_arg")]
mod parse_arg_impl {
    use std::fmt;
    use super::NodeId;

    #[cfg_attr(docsrs, doc(cfg(feature = "parse_arg")))]
    impl parse_arg::ParseArgFromStr for NodeId {
        fn describe_type<W: fmt::Write>(mut writer: W) -> fmt::Result {
            writer.write_str("a hex-encoded LN node ID (66 hex digits/33 bytes)")
        }
    }
}

/// Implementations of `serde` traits
#[cfg(feature = "serde")]
mod serde_impl {
    use std::fmt;
    use super::NodeId;
    use serde::{Serialize, Deserialize, Serializer, Deserializer, de::{Visitor, Error}};
    use std::convert::TryInto;

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
                    ParseErrorInner::InvalidLen => E::invalid_length(v.len(), &"66 hex digits"),
                    ParseErrorInner::InvalidChar { c, pos: _, } => E::invalid_value(serde::de::Unexpected::Char(c), &"a hex digit"),
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
            v.try_into().map_err(|_| E::invalid_length(v.len(), &"33 bytes"))
        }
    }

    /// `NodeId` is serialized as hex to human-readable formats and as bytes to non-human-readable.
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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
    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
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
    use super::NodeId;
    use postgres_types::{ToSql, FromSql, IsNull, Type};
    use bytes::BytesMut;
    use std::error::Error;
    use std::convert::TryInto;

    /// Supports `BYTEA`, `TEXT`, and `VARCHAR`.
    ///
    /// Stored as bytes if `BYTEA` is used, as hex string otherwise.
    #[cfg_attr(docsrs, doc(cfg(feature = "postgres-types")))]
    impl ToSql for NodeId {
        fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Send + Sync + 'static>> {
            use std::fmt::Write;

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
    #[cfg_attr(docsrs, doc(cfg(feature = "postgres-types")))]
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
    #[cfg_attr(docsrs, doc(cfg(feature = "slog")))]
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
        assert!("01234567890123456789012345678901234567890123456789012345678901234".parse::<NodeId>().is_err());
    }

    #[test]
    fn one_more() {
        assert!("0123456789012345678901234567890123456789012345678901234567890123456".parse::<NodeId>().is_err());
    }

    #[test]
    fn correct() {
        let parsed = "012345678901234567890123456789012345678901234567890123456789abcdef".parse::<NodeId>().unwrap();
        let expected = b"\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\x01\x23\x45\x67\x89\xab\xcd\xef";
        assert_eq!(parsed.0, *expected);
    }

    #[test]
    fn invalid_digit() {
        assert!("g12345678901234567890123456789012345678901234567890123456789012345".parse::<NodeId>().is_err());
    }
}
