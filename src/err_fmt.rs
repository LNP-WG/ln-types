/// Macros helping with implementations of error formatting.

#[cfg(any(not(feature = "alloc"), feature = "std"))]
use core::fmt;

/// Zero-sized version of empty string
#[cfg(any(not(feature = "alloc"), feature = "std"))]
pub(crate) struct Empty;

#[cfg(any(not(feature = "alloc"), feature = "std"))]
impl fmt::Display for Empty {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
        Ok(())
    }
}

/// Displays error with sources delimited by `: `
#[cfg(all(not(feature = "slog_std"), feature = "std", feature = "slog"))]
pub(crate) struct JoinErrSources<'a, T: std::error::Error + 'static>(pub &'a T);

#[cfg(all(not(feature = "slog_std"), feature = "std", feature = "slog"))]
impl<'a, T: std::error::Error + 'static> fmt::Display for JoinErrSources<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut error = self.0 as &(dyn std::error::Error + 'static);
        while let Some(source) = error.source() {
            write!(f, ": {}", self.0)?;
            error = source;
        }
        Ok(())
    }
}

/// Displays `$value` conditioned on `$feature`
///
/// `$value` may be an invalid expression (e.g. missing struct field) if the `$feature` is *off*.
/// Using `not("feature)"` negates the effect.
macro_rules! opt_fmt {
    (not($feature:literal), $value:expr) => {
        {
            #[cfg(not(feature = $feature))]
            {
                $value
            }
            #[cfg(feature = $feature)]
            {
                $crate::err_fmt::Empty
            }
        }
    };
    ($feature:literal, $value:expr) => {
        {
            #[cfg(feature = $feature)]
            {
                $value
            }
            #[cfg(not(feature = $feature))]
            {
                $crate::err_fmt::Empty
            }
        }
    };
}

/// Formats error optionally with error source appended (delimited by `: `) *if `$feature` is OFF*
macro_rules! write_err_ext {
    ($feature:literal, $writer:expr, $string:literal $(, $args:expr),*; $source:expr) => {
        {
            let _ = &$source;
            write!($writer, concat!($string, "{}") $(, $args)*, opt_fmt!(not($feature), format_args!(": {}", $source)))
        }
    }
}

/// Formats error optionally with error source appended (delimited by `: `) *if `std` feature is OFF*
macro_rules! write_err {
    ($writer:expr, $string:literal $(, $args:expr)*; $source:expr) => {
        write_err_ext!("std", $writer, $string $(, $args)*; $source)
    }
}

/// Implements feature-agnostic test(s) of error formatting.
///
/// This implements test that works correctly with `alloc`, `std` or without any of them.
/// Thus all combinations can be checked by using this macro once.
/// Obviously, the test must be run multiple times, each with a different set of features.
#[cfg(test)]
macro_rules! chk_err_impl {
    ($($test_name:ident, $input:expr, $type:ty, $sources_alloc:expr, $sources_no_alloc:expr);* $(;)?) => {
        $(
        #[test]
        fn $test_name() {
            use alloc::string::ToString;
            let error = $input.parse::<$type>().unwrap_err();

            #[cfg(feature = "alloc")]
            let sources = $sources_alloc;
            #[cfg(feature = "alloc")]
            let _ = $sources_no_alloc;
            #[cfg(not(feature = "alloc"))]
            let sources = $sources_no_alloc;
            #[cfg(not(feature = "alloc"))]
            let _ = $sources_alloc;

            #[cfg(feature = "std")]
            {
                let mut sources = sources.iter();
                let mut source = Some(&error as &(dyn std::error::Error + 'static));
                loop {
                    match (source, sources.next()) {
                        (Some(produced), Some(expected)) => {
                            assert_eq!(produced.to_string(), *expected);
                            source = produced.source();
                        },
                        (None, None) => break,
                        (Some(_), None) => panic!("more sources than expected"),
                        (None, Some(_)) => panic!("less sources than expected"),
                    }
                }
            }
            #[cfg(not(feature = "std"))]
            {
                let expected = sources.join(": ");
                assert_eq!(error.to_string(), expected);
            }
        }
        )*
    }
}
