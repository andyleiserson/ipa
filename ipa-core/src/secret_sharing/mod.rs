pub mod replicated;

mod array;
mod decomposed;
mod gf2_array;
mod into_shares;
mod scheme;

use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

pub use array::StdArray;
pub use decomposed::BitDecomposed;
use generic_array::ArrayLength;
pub use gf2_array::{Gf2Array, Width};
pub use into_shares::IntoShares;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing};
pub use scheme::{Bitwise, Linear, LinearRefOps, SecretSharing};

use crate::{
    ff::{AddSub, AddSubAssign, Field, Serializable, Gf2, boolean::Boolean, Fp32BitPrime},
    helpers::Message,
    protocol::prss::FromRandom,
};

/// Operations supported for weak shared values.
pub trait Additive<Rhs = Self, Output = Self>:
    AddSub<Rhs, Output> + AddSubAssign<Rhs> + Neg<Output = Output>
{
}

impl<T, Rhs, Output> Additive<Rhs, Output> for T where
    T: AddSub<Rhs, Output> + AddSubAssign<Rhs> + Neg<Output = Output>
{
}

/// Operations supported for shared values.
pub trait Arithmetic<Rhs = Self, Output = Self>:
    Additive<Rhs, Output> + Mul<Rhs, Output = Output> + MulAssign<Rhs>
{
}

impl<T, Rhs, Output> Arithmetic<Rhs, Output> for T where
    T: Additive<Rhs, Output> + Mul<Rhs, Output = Output> + MulAssign<Rhs>
{
}

// Trait for primitive integer types used to represent the underlying type for shared values
pub trait Block: Sized + Copy + Debug {
    /// Size of a block in bytes big enough to hold the shared value. `Size * 8 >= VALID_BIT_LENGTH`.
    type Size: ArrayLength;
}

/// Trait for types that are input to our additive secret sharing scheme.
///
/// Additive secret sharing requires an addition operation. In cases where arithmetic secret sharing
/// (capable of supporting addition and multiplication) is desired, the `Field` trait extends
/// `SharedValue` to require multiplication.
pub trait SharedValue:
    Clone + Copy + Eq + Debug + Send + Sync + Sized + Additive + Serializable + Vectorizable<1> + 'static
{
    type Storage: Block;
    //type Array<const N: usize>: SharedValueArray<Self> + Into<[Self; N]>;

    const BITS: u32;

    const ZERO: Self;
}

pub trait Vectorizable<const N: usize>: Sized {
    // There are two (three?) kinds of bounds here:
    //  1. Bounds that apply to the array type for vectorized operation, but not universally to
    //     `SharedValue::Array`.
    //  2. Bounds that apply universally to `SharedValue::Array`, but are replicated here due
    //     to a compiler limitation.
    //  3. Field vs. SharedValue
    // https://github.com/rust-lang/rust/issues/41118
    type Array: Message + SharedValueArray<Self> + Clone + Eq + Send + Sync;
}

// TODO: Question: What to do with this?
// When SharedValue had the Array associated type, both Vectorizable and FieldVectorizable
// had an associated type T, which was only used to impose further trait bounds on the array.
// Now, Vectorizable::Array is the canonical array type.
pub trait FieldVectorizable<const N: usize>: SharedValue {
    // There are two (three?) kinds of bounds here:
    //  1. Bounds that apply to the array type for vectorized operation, but not universally to
    //     `SharedValue::Array`.
    //  2. Bounds that apply universally to `SharedValue::Array`, but are replicated here due
    //     to a compiler limitation.
    //  3. Field vs. SharedValue
    // https://github.com/rust-lang/rust/issues/41118
    type T: Message + FromRandom + FieldArray<Self> + Into<[Self; N]> + Clone + Eq + Send + Sync;
    // TODO: do we really want the Into bound here?
}

// The purpose of this trait is to avoid placing a `Message` trait bound on `SharedValueArray`, or
// similar. Doing so would require either (1) a generic impl of `Serializable` for any `N`, which
// is hard to write, or (2) additional trait bounds of something like `F::Array<1>: Message`
// throughout many of our protocols.
//
// Writing `impl<F: Field> Vectorized<1> for F` means that the compiler will always see that it
// is available anywhere an `F: Field` trait bound is effective.

pub trait SharedValueSimd<const N: usize>: SharedValue { }

pub trait FieldSimd<const N: usize>:
    Field
    + SharedValueSimd<N>
    + Vectorizable<N, Array = <Self as FieldVectorizable<N>>::T>
    + FieldVectorizable<N>
{
}

impl<F: Field, const N: usize> SharedValueSimd<N> for F { }

/*
impl<V: SharedValue> Vectorizable<1> for V {
    type Array = StdArray<V, 1>;
}

impl<F: Field + Vectorizable<1>> FieldVectorizable<1> for F {
    type T = <Self as Vectorizable<1>>::Array;
}
*/

//impl<F: Field + FieldVectorizable<1>> FieldSimd<1> for F { }
impl<F: Field + Vectorizable<1> + FieldVectorizable<1, T = <Self as Vectorizable<1>>::Array>> FieldSimd<1> for F { }
/*
impl<F> FieldSimd<1> for F
where
    F: Field + Vectorizable<1, Array = StdArray<F, 1>> + FieldVectorizable<1, T = StdArray<F, 1>>,
{

}
*/

impl FieldSimd<32> for Fp32BitPrime { }

impl FieldSimd<64> for Gf2 { }

pub trait SharedValueArray<V>:
    Clone
    + Eq
    + Debug
    + Send
    + Sync
    + Sized
    + TryFrom<Vec<V>, Error = ()>
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign<Self>
    + for<'a> AddAssign<&'a Self>
    + Neg<Output = Self>
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign<Self>
    + for<'a> SubAssign<&'a Self>
{
    const ZERO: Self;

    fn index(&self, index: usize) -> V;

    fn from_item(item: V) -> Self;
}

impl<T> SharedValueArray<Boolean> for T
where
    T: SharedValueArray<Gf2> + TryFrom<Vec<Boolean>, Error = ()>,
{
    const ZERO: Self = <Self as SharedValueArray<Gf2>>::ZERO;

    fn index(&self, index: usize) -> Boolean { <Self as SharedValueArray<Gf2>>::index(self, index).into() }

    fn from_item(item: Boolean) -> Self { <Self as SharedValueArray<Gf2>>::from_item(item.into()) }
}

pub trait FieldArray<F: SharedValue>:
    SharedValueArray<F>
    + for<'a> Mul<&'a F, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
{
}

#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
impl<V> IntoShares<AdditiveShare<V>> for V
where
    V: SharedValue,
    Standard: Distribution<V>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AdditiveShare<V>; 3] {
        let x1 = rng.gen::<V>();
        let x2 = rng.gen::<V>();
        let x3 = self - (x1 + x2);

        [
            AdditiveShare::new(x1, x2),
            AdditiveShare::new(x2, x3),
            AdditiveShare::new(x3, x1),
        ]
    }
}

#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
impl<V, const N: usize> IntoShares<AdditiveShare<V, N>> for [V; N]
where
    V: SharedValue + Vectorizable<N>,
    Standard: Distribution<V>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AdditiveShare<V, N>; 3] {
        // For arrays large enough that the compiler doesn't just unroll everything, it might be
        // more efficient to avoid the intermediate vector by implementing this as a specialized
        // hybrid of the impls for `F as IntoShares<Replicated<F>>` and `<V: IntoIterator> as
        // IntoShares<Vec<T>>`. Not bothering since this is test-support functionality.
        let [v1, v2, v3] = self.into_iter().share_with(rng);
        let (v1l, v1r): (Vec<V>, Vec<V>) = v1.iter().map(AdditiveShare::as_tuple).unzip();
        let (v2l, v2r): (Vec<V>, Vec<V>) = v2.iter().map(AdditiveShare::as_tuple).unzip();
        let (v3l, v3r): (Vec<V>, Vec<V>) = v3.iter().map(AdditiveShare::as_tuple).unzip();
        [
            AdditiveShare::new_arr(v1l.try_into().unwrap(), v1r.try_into().unwrap()),
            AdditiveShare::new_arr(v2l.try_into().unwrap(), v2r.try_into().unwrap()),
            AdditiveShare::new_arr(v3l.try_into().unwrap(), v3r.try_into().unwrap()),
        ]
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        ff::{Field, Fp31},
        secret_sharing::{
            replicated::{malicious, semi_honest},
            Linear, LinearRefOps,
        },
    };

    fn arithmetic<L: Linear<F> + PartialEq, F: Field>()
    where
        for<'a> &'a L: LinearRefOps<'a, L, F>,
    {
        let a = L::ZERO;
        let b = L::ZERO;

        assert_eq!(L::ZERO, &a + &b);
        assert_eq!(L::ZERO, a.clone() + &b);
        assert_eq!(L::ZERO, &a + b.clone());
        assert_eq!(L::ZERO, a + b);
    }

    fn trait_bounds<L: Linear<F> + PartialEq, F: Field>()
    where
        for<'a> &'a L: LinearRefOps<'a, L, F>,
    {
        fn sum_owned<S: Linear<F>, F: Field>(a: S, b: S) -> S {
            a + b
        }

        fn sum_ref_ref<S, F>(a: &S, b: &S) -> S
        where
            S: Linear<F>,
            F: Field,
            for<'a> &'a S: LinearRefOps<'a, S, F>,
        {
            a + b
        }

        fn sum_owned_ref<S: Linear<F>, F: Field>(a: S, b: &S) -> S {
            a + b
        }

        fn sum_ref_owned<S, F>(a: &S, b: S) -> S
        where
            S: Linear<F>,
            F: Field,
            for<'a> &'a S: LinearRefOps<'a, S, F>,
        {
            a + b
        }

        assert_eq!(L::ZERO, sum_owned(L::ZERO, L::ZERO));
        assert_eq!(L::ZERO, sum_ref_ref(&L::ZERO, &L::ZERO));
        assert_eq!(L::ZERO, sum_owned_ref(L::ZERO, &L::ZERO));
        assert_eq!(L::ZERO, sum_ref_owned(&L::ZERO, L::ZERO));
    }

    #[test]
    fn semi_honest() {
        arithmetic::<semi_honest::AdditiveShare<Fp31>, _>();
        trait_bounds::<semi_honest::AdditiveShare<Fp31>, _>();
    }

    #[test]
    fn malicious() {
        arithmetic::<malicious::AdditiveShare<Fp31>, _>();
        trait_bounds::<malicious::AdditiveShare<Fp31>, _>();
    }
}
