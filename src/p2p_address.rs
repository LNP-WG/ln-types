//! P2P address (`node_id@host:port`)
//!
//! This module provides the [`P2PAddress`] type and the related error types.

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::str::FromStr;
use std::fmt;
use std::io;
use crate::NodeId;

const LN_DEFAULT_PORT: u16 = 9735;

/// Abstracts over string operations.
///
/// This trait enables efficient conversions.
trait StringOps: AsRef<str> + Into<String> {
    /// Converts given range of `self` into `String`
    fn into_substring(self, start: usize, end: usize) -> String;
}

/// The implementation avoids allocations - whole point of the trait.
impl StringOps for String {
    fn into_substring(mut self, start: usize, end: usize) -> String {
        self.replace_range(0..start, "");
        self.truncate(end - start);
        self
    }
}

impl<'a> StringOps for &'a str {
    fn into_substring(self, start: usize, end: usize) -> String {
        self[start..end].to_owned()
    }
}

/// Avoids allocations but has to store capacity
impl StringOps for Box<str> {
    fn into_substring(self, start: usize, end: usize) -> String {
        String::from(self).into_substring(start, end)
    }
}

/// Internal type that can store IP addresses without allocations.
///
/// This may be (partially) public in the future.
#[derive(Clone)]
enum HostInner {
    Ip(std::net::IpAddr),
    Hostname(String),
    // TODO: onion
}

/// Type representing network address of an LN node.
///
/// This type can avoid allocations if the value is an IP address.
#[derive(Clone)]
pub struct Host(HostInner);

impl Host {
    /// Returns true if it's an onion (Tor) adress.
    pub fn is_onion(&self) -> bool {
        match &self.0 {
            HostInner::Hostname(hostname) => hostname.ends_with(".onion"),
            HostInner::Ip(_) => false,
        }
    }

    /// Returns true if it's an IP adress.
    pub fn is_ip_addr(&self) -> bool {
        match &self.0 {
            HostInner::Hostname(_) => false,
            HostInner::Ip(_) => true,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            HostInner::Ip(addr) => fmt::Display::fmt(&addr, f),
            HostInner::Hostname(addr) => fmt::Display::fmt(&addr, f),
        }
    }
}

/// Helper struct that can be used to correctly display `host:port`
///
/// This is needed because IPv6 addresses need square brackets when displayed as `ip:port` but
/// square brackets are not used when they are displayed standalone.
pub struct HostPort<H: Borrow<Host>>(
    /// Host
    ///
    /// You can use `Host`, `&Host` or other smart pointers here.
    pub H,

    /// Port
    pub u16,
);

/// Makes sure to use square brackets around IPv6
impl<H: Borrow<Host>> fmt::Display for HostPort<H> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0.borrow().0 {
            HostInner::Ip(std::net::IpAddr::V6(addr)) => write!(f, "[{}]:{}", addr, self.1),
            _ => write!(f, "{}:{}", self.0.borrow(), self.1),
        }
    }
}

impl From<Host> for String {
    fn from(value: Host) -> Self {
        match value.0 {
            HostInner::Ip(ip_addr) => ip_addr.to_string(),
            HostInner::Hostname(hostname) => hostname,
        }
    }
}

/// This does **not** attempt to resolve a hostname!
impl TryFrom<Host> for std::net::IpAddr {
    type Error = NotIpAddr;

    fn try_from(value: Host) -> Result<Self, Self::Error> {
        match value.0 {
            HostInner::Ip(ip_addr) => Ok(ip_addr),
            HostInner::Hostname(hostname) => Err(NotIpAddr(hostname)),
        }
    }
}

/// Error returned when attempting to *convert* (not resolve) hostname to IP address.
#[derive(Debug)]
pub struct NotIpAddr(String);

impl fmt::Display for NotIpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "the hostname '{}' is not an IP address", self.0)
    }
}

impl std::error::Error for NotIpAddr {}

/// Parsed Lightning P2P address.
///
/// This type stores parsed representation of P2P address usually written in form `node_id@host:port`.
/// It can efficiently parse and display the address as well as perform various conversions using
/// external crates.
///
/// It also stores host in a way that can avoid allocation if it's **not** a host name.
///
/// **Serde limitations:** non-human-readable formats are not supported yet as it wasn't decided
/// what's the best way of doing it. Please state your preference in GitHub issues.
#[derive(Clone)]
pub struct P2PAddress {
    /// The representation of nodes public key
    pub node_id: NodeId,
    /// Network address of the node
    pub host: Host,
    /// Network port number of the node
    pub port: u16,
}

/// Intermediate representation of host.
///
/// This stores range representing host instead of string directly so that it can be returned from
/// a monomorphic function without requiring allocations.
enum IpOrHostnamePos {
    Ip(std::net::IpAddr),
    Hostname(usize, usize),
}

impl P2PAddress {
    /// Conveniently constructs [`HostPort`].
    ///
    /// This can be used when `NodeId` is not needed - e.g. when creating string representation of
    /// connection information.
    pub fn as_host_port(&self) -> HostPort<&Host> {
        HostPort(&self.host, self.port)
    }

    /// Internal monomorphic parsing method.
    ///
    /// This should improve codegen without requiring allocations.
    fn parse_raw(s: &str) -> Result<(NodeId, IpOrHostnamePos, u16), ParseErrorInner> {
        let at_pos = s.find('@').ok_or(ParseErrorInner::MissingAtSymbol)?;
        let (node_id, host_port) = s.split_at(at_pos);
        let host_port = &host_port[1..];
        let node_id = node_id.parse().map_err(ParseErrorInner::InvalidNodeId)?;
        let (host, port) = match host_port.parse::<std::net::SocketAddr>() {
            Ok(addr) => (IpOrHostnamePos::Ip(addr.ip()), addr.port()),
            // We have to explicitly parse IPv6 without port to avoid confusing `:`
            Err(_) if host_port.starts_with('[') && host_port.len() > 1 => {
                let ip = host_port[1..(host_port.len() - 1)]
                    .parse::<std::net::Ipv6Addr>()
                    .map_err(ParseErrorInner::InvalidIpv6)?;

                (IpOrHostnamePos::Ip(ip.into()), LN_DEFAULT_PORT)
            },
            Err(_) => {
                let (end, port) = match host_port.find(':') {
                    Some(pos) => (pos, host_port[(pos + 1)..].parse().map_err(ParseErrorInner::InvalidPortNumber)?),
                    None => (host_port.len(), LN_DEFAULT_PORT),
                };
                (IpOrHostnamePos::Hostname(at_pos + 1, at_pos + 1 + end), port)
            },
        };
        
        Ok((node_id, host, port))
    }

    /// Generic wrapper for parsing that is used to implement parsing from multiple types.
    fn internal_parse<S: StringOps>(s: S) -> Result<Self, ParseError> {
        let (node_id, host, port) = match Self::parse_raw(s.as_ref()) {
            Ok(result) => result,
            Err(error) => return Err(ParseError {
                input: s.into(),
                reason: error,
            }),
        };
        let host = match host {
            IpOrHostnamePos::Hostname(begin, end) => HostInner::Hostname(s.into_substring(begin, end)),
            IpOrHostnamePos::Ip(ip) => HostInner::Ip(ip),
        };

        Ok(P2PAddress {
            node_id,
            host: Host(host),
            port,
        })
    }
}

/// Alternative formatting displays node ID in upper case
impl fmt::Display for P2PAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{:X}@{}", self.node_id, HostPort(&self.host, self.port))
        } else {
            write!(f, "{:x}@{}", self.node_id, HostPort(&self.host, self.port))
        }
    }
}

/// Same as Display
impl fmt::Debug for P2PAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for P2PAddress {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::internal_parse(s)
    }
}

impl<'a> TryFrom<&'a str> for P2PAddress {
    type Error = ParseError;

    #[inline]
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

impl TryFrom<String> for P2PAddress {
    type Error = ParseError;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

impl TryFrom<Box<str>> for P2PAddress {
    type Error = ParseError;

    #[inline]
    fn try_from(s: Box<str>) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

/// Error returned when parsing text representation fails.
#[derive(Debug, Clone)]
pub struct ParseError {
    input: String,
    reason: ParseErrorInner,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "failed to parse '{}' as Lightning Network P2P address", self.input)
    }
}

impl std::error::Error for ParseError {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let ParseErrorInner::InvalidNodeId(error) = &self.reason {
            Some(error)
        } else {
            Some(&self.reason)
        }
    }
}

#[derive(Debug, Clone)]
enum ParseErrorInner {
    MissingAtSymbol,
    InvalidNodeId(crate::node_id::ParseError),
    InvalidPortNumber(std::num::ParseIntError),
    InvalidIpv6(std::net::AddrParseError),
}

impl fmt::Display for ParseErrorInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseErrorInner::MissingAtSymbol => f.write_str("missing '@' symbol"),
            ParseErrorInner::InvalidNodeId(error) => fmt::Display::fmt(error, f),
            ParseErrorInner::InvalidPortNumber(_) => f.write_str("invalid port number"),
            ParseErrorInner::InvalidIpv6(_) => f.write_str("invalid IPv6 address"),
        }
    }
}

impl std::error::Error for ParseErrorInner {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseErrorInner::MissingAtSymbol => None,
            ParseErrorInner::InvalidNodeId(error) => Some(error),
            ParseErrorInner::InvalidPortNumber(error) => Some(error),
            ParseErrorInner::InvalidIpv6(error) => Some(error),
        }
    }
}

/// Iterator over socket addresses returned by `to_socket_addrs()`
///
/// This is the iterator used in the implementation of [`std::net::ToSocketAddrs`] for [`HostPort`]
/// and [`P2PAddress`].
pub struct SocketAddrs {
    iter: std::iter::Chain<std::option::IntoIter<std::net::SocketAddr>, std::vec::IntoIter<std::net::SocketAddr>>
}

impl Iterator for SocketAddrs {
    type Item = std::net::SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

/// Note that onion addresses can never be resolved, you have to use a proxy instead.
impl<H: Borrow<Host>> std::net::ToSocketAddrs for HostPort<H> {
    type Iter = SocketAddrs;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        if self.0.borrow().is_onion() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, ResolveOnion));
        }

        let iter = match &self.0.borrow().0 {
            HostInner::Ip(ip_addr) => Some(std::net::SocketAddr::new(*ip_addr, self.1)).into_iter().chain(Vec::new()),
            HostInner::Hostname(hostname) => None.into_iter().chain((hostname.as_str(), self.1).to_socket_addrs()?),
        };

        Ok(SocketAddrs {
            iter,
        })
    }
}

/// Note that onion addresses can never be resolved, you have to use a proxy instead.
impl std::net::ToSocketAddrs for P2PAddress {
    type Iter = SocketAddrs;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        HostPort(&self.host, self.port).to_socket_addrs()
    }
}

/// Error type returned when attempting to resolve onion address.
#[derive(Debug)]
struct ResolveOnion;

impl fmt::Display for ResolveOnion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("attempt to resolve onion address")
    }
}

impl std::error::Error for ResolveOnion {}

#[cfg(feature = "parse_arg")]
mod parse_arg_impl {
    use std::fmt;
    use super::P2PAddress;

    impl parse_arg::ParseArgFromStr for P2PAddress {
        fn describe_type<W: fmt::Write>(mut writer: W) -> fmt::Result {
            writer.write_str("a Lightning Network address in the form `nodeid@host:port`")
        }
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use std::fmt;
    use super::P2PAddress;
    use serde::{Serialize, Deserialize, Serializer, Deserializer, de::{Visitor, Error}};
    use std::convert::TryInto;

    struct HRVisitor;

    impl<'de> Visitor<'de> for HRVisitor {
        type Value = P2PAddress;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a 66 digits long hex string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: Error {
            v.try_into().map_err(|error| {
                E::custom(error)
            })
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E> where E: Error {
            v.try_into().map_err(|error| {
                E::custom(error)
            })
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl Serialize for P2PAddress {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
            if serializer.is_human_readable() {
                serializer.collect_str(self)
            } else {
                unimplemented!("serialization is not yet implemented for non-human-readable formatsi, please file a request");
            }
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl<'de> Deserialize<'de> for P2PAddress {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                deserializer.deserialize_str(HRVisitor)
            } else {
                unimplemented!("serialization is not yet implemented for non-human-readable formatsi, please file a request");
            }
        }
    }
}

#[cfg(feature = "postgres-types")]
mod postgres_impl {
    use super::P2PAddress;
    use postgres_types::{ToSql, FromSql, IsNull, Type};
    use bytes::BytesMut;
    use std::error::Error;

    #[cfg_attr(docsrs, doc(cfg(feature = "postgres-types")))]
    impl ToSql for P2PAddress {
        fn to_sql(&self, _ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Send + Sync + 'static>> {
            use std::fmt::Write;

            write!(out, "{}", self).map(|_| IsNull::No).map_err(|error| Box::new(error) as _)
        }

        fn accepts(ty: &Type) -> bool {
            <&str as ToSql>::accepts(ty)
        }

        postgres_types::to_sql_checked!();
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "postgres-types")))]
    impl<'a> FromSql<'a> for P2PAddress {
        fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
            <&str>::from_sql(ty, raw)?.parse().map_err(|error| Box::new(error) as _)
        }

        fn accepts(ty: &Type) -> bool {
            <&str as FromSql>::accepts(ty)
        }
    }
}

/// Implementations of `slog` traits
#[cfg(feature = "slog")]
mod slog_impl {
    use super::P2PAddress;
    use slog::{Key, Value, KV, Record, Serializer};

    /// Uses `Display`
    #[cfg_attr(docsrs, doc(cfg(feature = "slog")))]
    impl Value for P2PAddress {
        fn serialize(&self, _rec: &Record, key: Key, serializer: &mut dyn Serializer) -> slog::Result {
            serializer.emit_arguments(key, &format_args!("{}", self))
        }
    }

    /// Serializes each field separately.
    ///
    /// The fields are:
    ///
    /// * `node_id` - delegates to `NodeId`
    /// * `host` - `Display`
    /// * `port` - `emit_u16`
    #[cfg_attr(docsrs, doc(cfg(feature = "slog")))]
    impl KV for P2PAddress {
        fn serialize(&self, rec: &Record, serializer: &mut dyn Serializer) -> slog::Result {
            // `Key` is a type alias but if `slog/dynamic_keys` feature is enabled it's not
            #![allow(clippy::useless_conversion)]
            self.node_id.serialize(rec, Key::from("node_id"), serializer)?;
            serializer.emit_arguments(Key::from("host"), &format_args!("{}", self.host))?;
            serializer.emit_u16(Key::from("port"), self.port)?;
            Ok(())
        }
    }

    impl_error_value!(super::ParseError);
}

#[cfg(test)]
mod tests {
    use super::P2PAddress;

    #[test]
    fn empty() {
        assert!("".parse::<P2PAddress>().is_err());
    }

    #[test]
    fn invalid_node_id() {
        assert!("@example.com".parse::<P2PAddress>().is_err());
    }

    #[test]
    fn invalid_port() {
        assert!("012345678901234567890123456789012345678901234567890123456789abcdef@example.com:foo".parse::<P2PAddress>().is_err());
    }

    #[test]
    fn correct_no_port() {
        let input = "012345678901234567890123456789012345678901234567890123456789abcdef@example.com";
        let parsed = input.parse::<P2PAddress>().unwrap();
        let output = parsed.to_string();
        let expected = format!("{}{}", input, ":9735");
        assert_eq!(output, expected);
    }

    #[test]
    fn correct_with_port() {
        let input = "012345678901234567890123456789012345678901234567890123456789abcdef@example.com:1234";
        let parsed = input.parse::<P2PAddress>().unwrap();
        let output = parsed.to_string();
        assert_eq!(output, input);
    }

    #[test]
    fn ipv6_no_port() {
        let input = "012345678901234567890123456789012345678901234567890123456789abcdef@[::1]";
        let parsed = input.parse::<P2PAddress>().unwrap();
        let output = parsed.to_string();
        let expected = format!("{}{}", input, ":9735");
        assert_eq!(output, expected);
    }

    #[test]
    fn ipv6_with_port() {
        let input = "012345678901234567890123456789012345678901234567890123456789abcdef@[::1]:1234";
        let parsed = input.parse::<P2PAddress>().unwrap();
        let output = parsed.to_string();
        assert_eq!(output, input);
    }
}
