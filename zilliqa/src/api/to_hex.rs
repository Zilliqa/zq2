use primitive_types::{H128, H160, H256, H384, H512, H768, U128, U256, U512};

/// A version of [hex::ToHex] which is also implemented for integer types. This version also prefixes the produced
/// string with `"0x"`.
pub trait ToHex {
    fn to_hex(&self) -> String;
}

/// Generates an implementation of [ToHex] for types which implement `AsRef<[u8]>`.
macro_rules! as_ref_impl {
    ($T:ty) => {
        impl ToHex for $T {
            fn to_hex(&self) -> String {
                format!("0x{}", hex::encode(self))
            }
        }
    };
}

/// Generates an implementation of [ToHex] for types which have a `.to_be_bytes()` method.
macro_rules! int_impl {
    ($T:ty) => {
        impl ToHex for $T {
            fn to_hex(&self) -> String {
                format!("0x{}", hex::encode(self.to_be_bytes()))
            }
        }
    };
}

/// Generates an implementation of [ToHex] for types which have `Self::zero()` and `.to_big_endian(bytes: &mut [u8])`
/// methods.
macro_rules! big_int_impl {
    ($T:ty) => {
        impl ToHex for $T {
            fn to_hex(&self) -> String {
                let mut bytes = [0; <$T>::zero().0.len() * 8];
                self.to_big_endian(&mut bytes);
                format!("0x{}", hex::encode(bytes))
            }
        }
    };
}

impl<T: ToHex> ToHex for &T {
    fn to_hex(&self) -> String {
        (*self).to_hex()
    }
}

impl<const N: usize> ToHex for [u8; N] {
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self))
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

big_int_impl!(U128);
big_int_impl!(U256);
big_int_impl!(U512);
