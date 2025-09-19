/// Implements both `From<T> for Enum` (wrap) and `TryFrom<Enum> for T` (unwrap)
/// for the specified enum variants.
#[macro_export]
macro_rules! impl_enum_from_try_from {
    ($enum:ident { $($variant:ident => $t:ty),* $(,)? }) => {
        $(
            // Wrap: From<T> -> Enum
            impl From<$t> for $enum {
                fn from(value: $t) -> Self {
                    $enum::$variant(value)
                }
            }

            // Unwrap: TryFrom<Enum> -> T
            impl std::convert::TryFrom<$enum> for $t {
                type Error = String;

                fn try_from(value: $enum) -> Result<Self, Self::Error> {
                    match value {
                        $enum::$variant(inner) => Ok(inner),
                        other => Err(format!(
                            "variable {:?} is not of type {}",
                            other,
                            stringify!($variant)
                        )),
                    }
                }
            }
        )*
    };
}
