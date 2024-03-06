use primitive_types::{H128, H160, H256, H384, H512, H768, U128, U256, U512};

/// A version of [hex::ToHex] which is also implemented for integer types. This version also prefixes the produced
/// string with `"0x"` and omits leading zeroes for quantities (types with fixed lengths).
pub trait ToHex {
    fn to_hex_inner(&self, prefix: bool) -> String;

    fn to_hex(&self) -> String {
        self.to_hex_inner(true)
    }

    fn to_hex_no_prefix(&self) -> String {
        self.to_hex_inner(false)
    }
}

/// Generates an implementation of [ToHex] for types which implement `AsRef<[u8]>`.
macro_rules! as_ref_impl {
    ($T:ty) => {
        impl ToHex for $T {
            fn to_hex_inner(&self, prefix: bool) -> String {
                if prefix {
                    format!("0x{}", hex::encode(self))
                } else {
                    hex::encode(self)
                }
            }
        }
    };
}

/// Generates an implementation of [ToHex] for types which implement [std::fmt::LowerHex].
macro_rules! int_impl {
    ($T:ty) => {
        impl ToHex for $T {
            fn to_hex_inner(&self, prefix: bool) -> String {
                if prefix {
                    format!("{:#x}", self)
                } else {
                    format!("{:x}", self)
                }
            }
        }
    };
}

impl<T: ToHex> ToHex for &T {
    fn to_hex_inner(&self, prefix: bool) -> String {
        (*self).to_hex_inner(prefix)
    }
}

impl<const N: usize> ToHex for [u8; N] {
    fn to_hex_inner(&self, prefix: bool) -> String {
        self.as_ref().to_hex_inner(prefix)
    }
}

as_ref_impl!(str);
as_ref_impl!(String);
as_ref_impl!([u8]);
as_ref_impl!(Vec<u8>);
as_ref_impl!(H128);
as_ref_impl!(H160);
as_ref_impl!(H256);
as_ref_impl!(H384);
as_ref_impl!(H512);
as_ref_impl!(H768);

int_impl!(i8);
int_impl!(i16);
int_impl!(i32);
int_impl!(i64);
int_impl!(i128);
int_impl!(u8);
int_impl!(u16);
int_impl!(u32);
int_impl!(u64);
int_impl!(u128);
int_impl!(isize);
int_impl!(usize);
int_impl!(U128);
int_impl!(U256);
int_impl!(U512);

#[cfg(test)]
mod tests {
    use std::assert_eq;

    use primitive_types::U128;

    use super::ToHex;

    #[test]
    fn test_as_ref_to_hex() {
        let cases = [
            (vec![], "0x"),
            (vec![0u8, 0, 0, 0], "0x00000000"),
            (vec![0, 0, 0, 1], "0x00000001"),
            (vec![1, 2, 3, 4], "0x01020304"),
        ];

        for (val, expected) in cases {
            let actual = val.to_hex();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_int_to_hex() {
        let cases = [(0, "0x0"), (1, "0x1")];

        for (val, expected) in cases {
            let actual = val.to_hex();
            assert_eq!(expected, actual);
        }
    }

    #[test]
    fn test_big_int_to_hex() {
        let cases = [
            (U128::zero(), "0x0"),
            (256.into(), "0x100"),
            (U128::MAX, "0xffffffffffffffffffffffffffffffff"),
        ];

        for (val, expected) in cases {
            let actual = val.to_hex();
            assert_eq!(expected, actual);
        }
    }
}
