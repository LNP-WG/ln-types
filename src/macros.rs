#[cfg(feature = "slog")]
macro_rules! impl_error_value {
    ($($type:ty),+) => {
        $(
            /// Implemented using `emit_error`
            #[cfg_attr(docsrs, doc(cfg(feature = "slog")))]
            impl Value for $type {
                fn serialize(&self, _rec: &Record, key: Key, serializer: &mut dyn Serializer) -> slog::Result {
                    serializer.emit_error(key, self)
                }
            }
        )+
    }
}
