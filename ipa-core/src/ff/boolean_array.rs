use bitvec::{
    prelude::{bitarr, BitArr, Lsb0},
    slice::Iter,
};
use generic_array::GenericArray;
use typenum::{U32, U8};

use crate::{
    ff::{boolean::Boolean, Serializable},
    protocol::prss::FromRandom,
    secret_sharing::{replicated::ReplicatedSecretSharing, ArrayFromRandom, Block, StdArray},
};

/// The implementation below cannot be constrained without breaking Rust's
/// macro processor.  This noop ensures that the instance of `GenericArray` used
/// is `Copy`.  It should be - it's the same size as the `BitArray` instance.
fn assert_copy<C: Copy>(c: C) -> C {
    c
}

/// this might clash with Galois field, i.e. `galois_field.rs`
/// so only use it for byte sizes for which Block has not been defined yet
macro_rules! store_impl {
    ($arraylength:ty, $bits:expr) => {
        impl Block for BitArr!(for $bits, in u8, Lsb0) {
            type Size = $arraylength;
        }
    };
}

/// iterator for Boolean arrays
pub struct BAIterator<'a> {
    iterator: std::iter::Take<Iter<'a, u8, Lsb0>>,
}

///impl Iterator for all Boolean arrays
impl<'a> Iterator for BAIterator<'a> {
    type Item = Boolean;

    fn next(&mut self) -> Option<Self::Item> {
        self.iterator.next().map(|v| Boolean::from(*v))
    }
}

//macro for implementing Boolean array, only works for a byte size for which Block is defined
macro_rules! boolean_array_impl {
    ($modname:ident, $name:ident, $bits:expr, $bytes:expr, [$($one:expr),+]) => {
        #[allow(clippy::suspicious_arithmetic_impl)]
        #[allow(clippy::suspicious_op_assign_impl)]
        mod $modname {
            use super::*;
            use crate::{
                ff::{boolean::Boolean, ArrayAccess, Expand, Field, Serializable},
                secret_sharing::{
                    replicated::semi_honest::{ASIterator, AdditiveShare},
                    SharedValue,
                },
            };

    type Store = BitArr!(for $bits, in u8, Lsb0);

            ///
            #[derive(Clone, Copy, PartialEq, Eq, Debug)]
            pub struct $name(pub Store);

            impl ArrayAccess for $name {
                type Output = Boolean;

                fn get(&self, index: usize) -> Option<Self::Output> {
                    if index < usize::try_from(<$name>::BITS).unwrap() {
                        Some(self.0[index].into())
                    } else {
                        None
                    }
                }

                fn set(&mut self, index: usize, e: Self::Output) {
                    debug_assert!(index < usize::try_from(<$name>::BITS).unwrap());
                    self.0.set(index, bool::from(e));
                }
            }

            impl SharedValue for $name {
                type Storage = Store;
                type Array<const N: usize> = StdArray<$name, N>;
                const BITS: u32 = $bits;
                const ZERO: Self = Self(<Store>::ZERO);
            }

            impl Serializable for $name {
                type Size = <Store as Block>::Size;

                fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
                    buf.copy_from_slice(self.0.as_raw_slice());
                }

                fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
                    Self(<Store>::new(assert_copy(*buf).into()))
                }
            }

            impl std::ops::Add for $name {
                type Output = Self;
                fn add(self, rhs: Self) -> Self::Output {
                    Self(self.0 ^ rhs.0)
                }
            }

            impl std::ops::AddAssign for $name {
                fn add_assign(&mut self, rhs: Self) {
                    *self.0.as_mut_bitslice() ^= rhs.0;
                }
            }

            impl std::ops::Sub for $name {
                type Output = Self;
                fn sub(self, rhs: Self) -> Self::Output {
                    self + rhs
                }
            }

            impl std::ops::SubAssign for $name {
                fn sub_assign(&mut self, rhs: Self) {
                    *self += rhs;
                }
            }

            impl std::ops::Neg for $name {
                type Output = Self;
                fn neg(self) -> Self::Output {
                    Self(self.0)
                }
            }

            impl ArrayFromRandom<1> for $name {
                type T = <Self as SharedValue>::Array<1>;
            }

            impl Field for $name {
                const ONE: Self = Self(bitarr![const u8, Lsb0; $($one),+]);

                fn as_u128(&self) -> u128 {
                    (*self).into()
                }

                fn truncate_from<T: Into<u128>>(v: T) -> Self {
                    let v = v.into();
                    let mut val = Self::ZERO;
                    for i in 0..std::cmp::min(128, $bits) {
                        val.set(i, Boolean::from((v >> i & 1) == 1));
                    }

                    val
                }
            }

            // TODO: this should only be implemented like this when bits <= 128
            impl rand::distributions::Distribution<$name> for rand::distributions::Standard {
                fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> $name {
                    <$name>::truncate_from(rng.gen::<u128>())
                }
            }

            // TODO: this should only be implemented when bits <= 128
            impl FromRandom for $name {
                type Source = [u128; 1];
                fn len() -> usize { 1 }
                fn from_random(src: [u128; 1]) -> Self {
                    Field::truncate_from(src[0])
                }
            }

            impl std::ops::Mul for $name {
                type Output = Self;
                fn mul(self, rhs: Self) -> Self::Output {
                    Self(self.0 & rhs.0)
                }
            }

            impl std::ops::MulAssign for $name {
                fn mul_assign(&mut self, rhs: Self) {
                    *self = *self * rhs;
                }
            }

            impl TryFrom<u128> for $name {
                type Error = crate::error::Error;

                /// Fallible conversion from `u128` to this data type. The input value must
                /// be at most `Self::BITS` long. That is, the integer value must be less than
                /// or equal to `2^Self::BITS`, or it will return an error.
                fn try_from(v: u128) -> Result<Self, Self::Error> {
                    if u128::BITS - v.leading_zeros() <= Self::BITS {
                        Ok(Self::truncate_from(v))
                    } else {
                        Err(crate::error::Error::FieldValueTruncation(format!(
                            "Bit array size {} is too small to hold the value {}.",
                            Self::BITS,
                            v
                        )))
                    }
                }
            }

            impl From<$name> for Store {
                fn from(v: $name) -> Self {
                    v.0
                }
            }

            impl From<$name> for u128 {
                /// Infallible conversion from this data type to `u128`. We assume that the
                /// inner value is at most 128-bit long. That is, the integer value must be
                /// less than or equal to `2^Self::BITS`. Should be long enough for our use
                /// case.
                fn from(v: $name) -> u128 {
                    debug_assert!(<$name>::BITS <= 128);
                    v.0.iter()
                        .by_refs()
                        .enumerate()
                        .fold(0_u128, |acc, (i, b)| acc + ((*b as u128) << i))
                }
            }

            impl Expand for $name {
                type Input = Boolean;

                fn expand(v: &Boolean) -> Self {
                    let mut result = <$name>::ZERO;
                    for i in 0..usize::try_from(<$name>::BITS).unwrap() {
                        result.set(i, *v);
                    }
                    result
                }
            }

            // complains that no iter method exists, suppressed warnings
            #[allow(clippy::into_iter_on_ref)]
            impl<'a> IntoIterator for &'a $name {
                type Item = Boolean;
                type IntoIter = BAIterator<'a>;

                fn into_iter(self) -> Self::IntoIter {
                    BAIterator {
                        iterator: self.0.iter().take(usize::try_from(<$name>::BITS).unwrap()),
                    }
                }
            }

            // complains that no iter method exists, suppressed warnings
            #[allow(clippy::into_iter_on_ref)]
            impl<'a> IntoIterator for &'a AdditiveShare<$name> {
                type Item = AdditiveShare<Boolean>;
                type IntoIter = ASIterator<BAIterator<'a>>;

                fn into_iter(self) -> Self::IntoIter {
                    ASIterator::<BAIterator<'a>>(self.left().into_iter(), self.right().into_iter())
                }
            }

            impl std::ops::Not for $name {
                type Output = Self;

                fn not(self) -> Self::Output {
                    let mut result = <$name>::ZERO;
                    for i in 0..usize::try_from(<$name>::BITS).unwrap() {
                        result.set(i, !self.get(i).unwrap());
                    }
                    result
                }
            }

            #[cfg(all(test, unit_test))]
            mod tests {
                use rand::{thread_rng, Rng};

                use super::*;

                #[test]
                fn set_boolean_array() {
                    let mut rng = thread_rng();
                    let i = rng.gen::<usize>() % usize::try_from(<$name>::BITS).unwrap();
                    let a = rng.gen::<Boolean>();
                    let mut ba = rng.gen::<$name>();
                    ba.set(i, a);
                    assert_eq!(ba.get(i), Some(a));
                }

                #[test]
                fn iterate_boolean_array() {
                    let bits = $name::ONE;
                    let iter = bits.into_iter();
                    for (i, j) in iter.enumerate() {
                        if i == 0 {
                            assert_eq!(j, Boolean::ONE);
                        } else {
                            assert_eq!(j, Boolean::ZERO);
                        }
                    }
                }
            }

            #[test]
            fn iterate_secret_shared_boolean_array() {
                use crate::secret_sharing::replicated::ReplicatedSecretSharing;
                let bits = AdditiveShare::new($name::ONE, $name::ONE);
                let iter = bits.into_iter();
                for (i, j) in iter.enumerate() {
                    if i == 0 {
                        assert_eq!(j, AdditiveShare::new(Boolean::ONE, Boolean::ONE));
                    } else {
                        assert_eq!(j, AdditiveShare::<Boolean>::ZERO);
                    }
                }
            }
        }

        pub use $modname::$name;
    };
}

//impl store for U8
store_impl!(U8, 64);

//impl store for U32
store_impl!(U32, 256);

//impl BA3
boolean_array_impl!(boolean_array_3, BA3, 3, 1, [1, 0, 0]);

//impl BA4
boolean_array_impl!(boolean_array_4, BA4, 4, 1, [1, 0, 0, 0]);

//impl BA5
boolean_array_impl!(boolean_array_5, BA5, 5, 1, [1, 0, 0, 0, 0]);

//impl BA6
boolean_array_impl!(boolean_array_6, BA6, 6, 1, [1, 0, 0, 0, 0, 0]);

//impl BA7
boolean_array_impl!(boolean_array_7, BA7, 7, 1, [1, 0, 0, 0, 0, 0, 0]);

//impl BA8
boolean_array_impl!(boolean_array_8, BA8, 8, 1, [1, 0, 0, 0, 0, 0, 0, 0]);

//impl BA20
boolean_array_impl!(
    boolean_array_20,
    BA20,
    20,
    3,
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
);

//impl BA32
boolean_array_impl!(
    boolean_array_32,
    BA32,
    32,
    4,
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]
);

//impl BA64
boolean_array_impl!(
    boolean_array_64,
    BA64,
    64,
    8,
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0
    ]
);

// impl BA256
// used to convert into Fp25519
boolean_array_impl!(
    boolean_array_256,
    BA256,
    256,
    32,
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ]
);

impl From<(u128, u128)> for BA256 {
    fn from(value: (u128, u128)) -> Self {
        let iter = value
            .0
            .to_le_bytes()
            .into_iter()
            .chain(value.1.to_le_bytes());
        let arr = GenericArray::<u8, U32>::try_from_iter(iter).unwrap();
        BA256::deserialize(&arr)
    }
}

// TODO: don't generate the default impls; enable these instead.
/*
impl FromPrss for (BA256, BA256) {
    fn from_prss<P: SharedRandomness + ?Sized, I: Into<u128>>(prss: &P, index: I) -> (BA256, BA256) {
        let index = index.into();
        let (l0, r0) = prss.generate_values(2 * index);
        let (l1, r1) = prss.generate_values(2 * index + 1);
        (BA256::from((l0, l1)), BA256::from((r0, r1)))
    }
}

impl rand::distributions::Distribution<BA256> for rand::distributions::Standard {
    fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> BA256 {
        BA256::from((rng.gen(), rng.gen()))
    }
}
*/
