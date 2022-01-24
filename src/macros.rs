#[cfg(feature = "slog")]
macro_rules! impl_error_value {
    ($($type:ty),+) => {
        $(
            /// Implemented using `emit_error` if `slog_std` feature is enabled, calls
            /// `emit_arguments` with sources separated by `: ` otherwise.
            #[cfg_attr(docsrs, doc(cfg(feature = "slog")))]
            impl Value for $type {
                fn serialize(&self, _rec: &Record, key: Key, serializer: &mut dyn Serializer) -> slog::Result {
                    {
                        #[cfg(feature = "slog_std")]
                        {
                            serializer.emit_error(key, self)
                        }
                        #[cfg(all(not(feature = "slog_std"), feature = "std"))]
                        {
                            serializer.emit_arguments(key, &format_args!("{}", $crate::err_fmt::JoinErrSources(self)))
                        }
                        #[cfg(not(feature = "std"))]
                        {
                            serializer.emit_arguments(key, &format_args!("{}", self))
                        }
                    }
                }
            }
        )+
    }
}
