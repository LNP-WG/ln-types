//! Bitcoin amount with millisatoshi precision.
//!
//! This module provides the [`Amount`] type and the related error types.

use std::fmt;
use std::str::FromStr;
use std::convert::TryFrom;

const SATS_IN_BTC: u64 = 100_000_000;
const MAX_MONEY_SAT: u64 = 21_000_000 * SATS_IN_BTC;
const MAX_MONEY_MSAT: u64 = MAX_MONEY_SAT * 1000;

/// Number of millisatoshis.
///
/// This type represents a number of millisatoshis (thousands of satoshi) which is the base unit of
/// the lightning network.
/// It provides ordinary arithmetic and conversion methods.
///
/// ## Invariants
///
/// This type guarantees that the amount stays less than or equal to 21 million bitcoins.
/// However `unsafe` code **must not** rely on this, at least for now.
/// This implies that arithmetic operations always panic on overflow.
///
/// ## `Display` implementation
///
/// To avoid confusion, the amount is displayed with ` msat` suffix - e.g. `42 msat`.
/// No other representations are supported yet, feel free to contribute!
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct Amount(u64);

impl Amount {
    /// Zero bitcoins.
    pub const ZERO: Amount = Amount(0);

    /// 21 million bitcoins.
    pub const MAX: Amount = Amount(MAX_MONEY_MSAT);

    /// One satoshi
    pub const ONE_SAT: Amount = Amount(1000);

    /// One bitcoin
    pub const ONE_BTC: Amount = Amount(1000 * SATS_IN_BTC);

    /// Constructs the amount from raw millisatosis.
    ///
    /// The value is directly converted with an overflow check.
    ///
    /// ## Errors
    ///
    /// This method returns an error if the amount exceeds Bitcoin supply cap
    #[inline]
    pub fn from_msat(msat: u64) -> Result<Self, OverflowError> {
        if msat > MAX_MONEY_MSAT {
            Err(OverflowError { amount: msat, denomination: "millisatoshis", })
        } else {
            Ok(Amount(msat))
        }
    }

    /// Constructs the amount from raw satosis.
    ///
    /// The value is converted with an overflow check.
    ///
    /// ## Errors
    ///
    /// This method returns an error if the amount exceeds Bitcoin supply cap
    #[inline]
    pub fn from_sat(sat: u64) -> Result<Self, OverflowError> {
        if sat > MAX_MONEY_SAT {
            Err(OverflowError { amount: sat, denomination: "satoshis", })
        } else {
            Ok(Amount(sat * 1000))
        }
    }

    /// Converts the value to raw millisatoshis.
    #[inline]
    pub fn to_msat(self) -> u64 {
        self.0
    }

    /// Attempts to convert the value to raw satoshis.
    ///
    /// ## Errors
    ///
    /// This method returns an error if the number of millisatoshis isn't rounded to thousands.
    #[inline]
    pub fn to_sat(self) -> Result<u64, FractionError> {
        if self.0 % 1000 == 0 {
            Ok(self.0 / 1000)
        } else {
            Err(FractionError { amount: self.0, })
        }
    }

    /// Converts to satoshis rounding down.
    #[inline]
    pub fn to_sat_floor(self) -> u64 {
        self.0 / 1000
    }

    /// Converts to satoshis rounding up.
    #[inline]
    pub fn to_sat_ceiling(self) -> u64 {
        (self.0 + 999) / 1000
    }

    /// Converts to satoshis rounding.
    #[inline]
    pub fn to_sat_round(self) -> u64 {
        (self.0 + 500) / 1000
    }

    /// Internal monomorphic parsing method.
    ///
    /// This should improve codegen without requiring allocations.
    fn parse_raw(mut s: &str) -> Result<Self, ParseErrorInner> {
        if s.ends_with(" msat") {
            s = &s[..(s.len() - 5)];
        }

        let amount = s.parse::<u64>()?;

        Self::from_msat(amount).map_err(Into::into)
    }

    /// Generic wrapper for parsing that is used to implement parsing from multiple types.
    #[inline]
    fn internal_parse<S: AsRef<str> + Into<String>>(s: S) -> Result<Self, ParseError> {
        Self::parse_raw(s.as_ref()).map_err(|error| ParseError {
            input: s.into(),
            reason: error,
        })
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} msat", self.0)
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}


impl std::ops::Add for Amount {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Amount) -> Self::Output {
        let sum = self.0 + rhs.0;
        assert!(
            sum <= MAX_MONEY_MSAT, 
            "adding amounts {} + {} overflowed the maximum number of 21 million bitcoins",
            self,
            rhs,
        );

        Amount(sum)
    }
}

impl std::ops::AddAssign for Amount {
    #[inline]
    fn add_assign(&mut self, rhs: Amount) {
        *self = *self + rhs;
    }
}

impl std::ops::Sub for Amount {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Amount) -> Self::Output {
        Amount(self.0.checked_sub(rhs.0).expect("underflow when subtracting amounts"))
    }
}

impl std::ops::SubAssign for Amount {
    #[inline]
    fn sub_assign(&mut self, rhs: Amount) {
        *self = *self - rhs
    }
}

impl std::ops::Mul<u64> for Amount {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self::Output {
        match self.0.checked_mul(rhs) {
            Some(amount) if amount <= MAX_MONEY_MSAT => Amount(amount),
            _ => panic!("multiplying {} by {} overflowed the maximum number of 21 million bitcoins", self, rhs),
        }
    }
}

impl std::ops::Mul<Amount> for u64 {
    type Output = Amount;

    fn mul(self, rhs: Amount) -> Self::Output {
        rhs * self
    }
}

impl std::ops::MulAssign<u64> for Amount {
    fn mul_assign(&mut self, rhs: u64) {
        *self = *self * rhs;
    }
}

impl std::ops::Div<u64> for Amount {
    type Output = Self;

    fn div(self, rhs: u64) -> Self::Output {
        Amount(self.0 / rhs)
    }
}

impl std::ops::DivAssign<u64> for Amount {
    fn div_assign(&mut self, rhs: u64) {
        *self = *self / rhs;
    }
}

impl std::ops::Rem<u64> for Amount {
    type Output = Self;

    fn rem(self, rhs: u64) -> Self::Output {
        Amount(self.0 % rhs)
    }
}

impl std::ops::RemAssign<u64> for Amount {
    fn rem_assign(&mut self, rhs: u64) {
        *self = *self % rhs;
    }
}

impl FromStr for Amount {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::internal_parse(s)
    }
}

impl<'a> TryFrom<&'a str> for Amount {
    type Error = ParseError;

    #[inline]
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

impl TryFrom<String> for Amount {
    type Error = ParseError;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
    }
}

impl TryFrom<Box<str>> for Amount {
    type Error = ParseError;

    #[inline]
    fn try_from(s: Box<str>) -> Result<Self, Self::Error> {
        Self::internal_parse(s)
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
        write!(f, "failed to parse '{}' as millisatoshis", self.input)
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
enum ParseErrorInner {
    ParseInt(std::num::ParseIntError),
    Overflow(OverflowError),
}

impl From<std::num::ParseIntError> for ParseErrorInner {
    fn from(value: std::num::ParseIntError) -> Self {
        ParseErrorInner::ParseInt(value)
    }
}

impl From<OverflowError> for ParseErrorInner {
    fn from(value: OverflowError) -> Self {
        ParseErrorInner::Overflow(value)
    }
}

impl fmt::Display for ParseErrorInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseErrorInner::ParseInt(_) => f.write_str("invalid integer"),
            ParseErrorInner::Overflow(_) => f.write_str("value above supply cap"),
        }
    }
}

impl std::error::Error for ParseErrorInner {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseErrorInner::ParseInt(error) => Some(error),
            ParseErrorInner::Overflow(error) => Some(error),
        }
    }
}

/// Error returned when a conversion exceeds Bitcoin supply cap.
#[derive(Debug, Clone)]
pub struct OverflowError {
    amount: u64,
    denomination: &'static str,
}

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} exceeds the maximum number of 21 million bitcoins", self.amount, self.denomination)
    }
}

impl std::error::Error for OverflowError {}

/// Error returned when a conversion to satoshis fails due to the value not being round.
#[derive(Debug, Clone)]
pub struct FractionError {
    amount: u64,
}

impl fmt::Display for FractionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} millisatoshis can not be converted to satoshis because it's not round to thousands", self.amount)
    }
}

impl std::error::Error for FractionError {}

#[cfg(feature = "bitcoin")]
mod impl_bitcoin {
    use super::{Amount, OverflowError, FractionError};
    use std::convert::TryFrom;

    impl TryFrom<bitcoin::Amount> for Amount {
        type Error = OverflowError;

        fn try_from(value: bitcoin::Amount) -> Result<Self, Self::Error> {
            Self::from_sat(value.as_sat())
        }
    }

    impl TryFrom<Amount> for bitcoin::Amount {
        type Error = FractionError;

        fn try_from(value: Amount) -> Result<Self, Self::Error> {
            Ok(Self::from_sat(value.to_sat()?))
        }
    }
}

#[cfg(feature = "parse_arg")]
mod parse_arg_impl {
    use std::fmt;
    use super::Amount;

    impl parse_arg::ParseArgFromStr for Amount {
        fn describe_type<W: fmt::Write>(mut writer: W) -> fmt::Result {
            writer.write_str("millisatoshis - a non-negative integer up to 2 100 000 000 000 000 000")
        }
    }
}

#[cfg(feature = "serde")]
mod serde_impl {
    use std::fmt;
    use super::Amount;
    use serde::{Serialize, Deserialize, Serializer, Deserializer, de::{Visitor, Error}};

    struct HRVisitor;

    impl<'de> Visitor<'de> for HRVisitor {
        type Value = Amount;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a non-negative integer up to 2 100 000 000 000 000 000")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> where E: Error {
            Amount::from_msat(v).map_err(|_| {
                E::invalid_value(serde::de::Unexpected::Unsigned(v), &"a non-negative integer up to 2 100 000 000 000 000 000")
            })
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl Serialize for Amount {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
            serializer.serialize_u64(self.0)
        }
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
    impl<'de> Deserialize<'de> for Amount {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
            deserializer.deserialize_u64(HRVisitor)
        }
    }
}

#[cfg(feature = "postgres-types")]
mod postgres_impl {
    use super::Amount;
    use postgres_types::{ToSql, FromSql, IsNull, Type};
    use bytes::BytesMut;
    use std::error::Error;
    use std::convert::TryInto;

    #[cfg_attr(docsrs, doc(cfg(feature = "postgres-types")))]
    impl ToSql for Amount {
        fn to_sql(&self, ty: &Type, out: &mut BytesMut) -> Result<IsNull, Box<dyn Error + Send + Sync + 'static>> {
            // Amount guarantees to always be in bounds
            (self.to_msat() as i64).to_sql(ty, out)
        }

        fn accepts(ty: &Type) -> bool {
            <i64 as ToSql>::accepts(ty)
        }

        postgres_types::to_sql_checked!();
    }

    #[cfg_attr(docsrs, doc(cfg(feature = "postgres-types")))]
    impl<'a> FromSql<'a> for Amount {
        fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
            let msats = <i64>::from_sql(ty, raw)?
                .try_into()
                .map_err(Box::new)?;
            Amount::from_msat(msats).map_err(|error| Box::new(error) as _)
        }

        fn accepts(ty: &Type) -> bool {
            <i64 as FromSql>::accepts(ty)
        }
    }
}

/// Implementations of `slog` traits
#[cfg(feature = "slog")]
mod slog_impl {
    use super::Amount;
    use slog::{Key, Value, Record, Serializer};

    /// Logs msats using `emit_u64`
    #[cfg_attr(docsrs, doc(cfg(feature = "slog")))]
    impl Value for Amount {
        fn serialize(&self, _rec: &Record, key: Key, serializer: &mut dyn Serializer) -> slog::Result {
            serializer.emit_u64(key, self.0)
        }
    }

    impl_error_value!(super::ParseError, super::OverflowError, super::FractionError);
}

#[cfg(test)]
mod tests {
    use super::Amount;

    #[test]
    fn amount_max() {
        assert_eq!(Amount::from_msat(super::MAX_MONEY_MSAT).unwrap(), Amount::MAX);
    }
}
