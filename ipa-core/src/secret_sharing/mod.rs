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
pub use gf2_array::Gf2Array;
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
    ff::{AddSub, AddSubAssign, Field, Serializable, Gf2, boolean::Boolean},
    helpers::Message, protocol::prss::{FromPrss, FromRandom},
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
    Clone + Copy + PartialEq + Debug + Send + Sync + Sized + Additive + Serializable + /*FromPrss +*/ 'static
{
    type Storage: Block;
    type Array<const N: usize>: SharedValueArray<Self>;

    const BITS: u32;

    const ZERO: Self;
}

pub trait ArrayFromRandom<const N: usize>: SharedValue {
    // TODO: why are Clone + Send + Sync necessary here?
    // Clone, in particular, was wanted by the compiler, but it seems like it should be available from SharedValueArray?
    // Ditto SharedValueArray. seems like the compiler does not traverse all paths when the associated types are constrained.
    type T: SharedValueArray<Self> + Message + FromRandom + Clone + Send + Sync;
}

/*
impl<V: SharedValue, const N: usize> ArrayFromRandom<N> for V {
    type T = ();
}
*/

// The purpose of this trait is to avoid placing a `Message` trait bound on `SharedValueArray`, or
// similar. Doing so would require either (1) a generic impl of `Serializable` for any `N`, which
// is hard to write, or (2) additional trait bounds of something like `F::Array<1>: Message`
// throughout many of our protocols.
//
// Writing `impl<F: Field> Vectorized<1> for F` means that the compiler will always see that it
// is available anywhere an `F: Field` trait bound is effective.

pub trait Vectorized<const N: usize>: SharedValue /* + FromPrss*/ {
    // TODO: Can we eliminate Clone here? (In existing code, `Message`s are generally
    // `SharedValue`s, which are always Clone.)
    type Message: Message + Clone + Send + Sync;

    fn as_message(v: &Self::Array<N>) -> &Self::Message;

    fn from_message(v: Self::Message) -> Self::Array<N>;
}

pub trait FieldVectorized<const N: usize>:
    Field
    + Vectorized<N>
    + SharedValue<Array<N> = <Self as ArrayFromRandom<N>>::T>
    + ArrayFromRandom<N>
{
}

impl<F: Field> FieldVectorized<1> for F { }

impl<F> Vectorized<1> for F
where
    F: Field /*+ FromPrss*/
{
    type Message = F;

    fn as_message(v: &Self::Array<1>) -> &Self::Message {
        todo!()
    }

    fn from_message(v: Self::Message) -> Self::Array<1> {
        Self::Array::<1>::from_item(v)
    }
}

impl<F> Vectorized<32> for F
where
    F: Field + FromPrss,
    <F as SharedValue>::Array<32>: Message,
{
    type Message = F::Array<32>;

    fn as_message(v: &Self::Array<32>) -> &Self::Message {
        todo!()
    }

    fn from_message(v: Self::Message) -> Self::Array<32> {
        todo!()
    }
}

pub trait SharedValueArray<V: SharedValue>:
    Clone
    + PartialEq
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

    fn capacity() -> usize;

    fn index(&self, index: usize) -> V;

    fn from_item(item: V) -> Self;
}

impl<T> SharedValueArray<Boolean> for T
where
    T: SharedValueArray<Gf2> + TryFrom<Vec<Boolean>, Error = ()>,
{
    const ZERO: Self = <Self as SharedValueArray<Gf2>>::ZERO;

    fn capacity() -> usize { <Self as SharedValueArray<Gf2>>::capacity() }

    fn index(&self, index: usize) -> Boolean { <Self as SharedValueArray<Gf2>>::index(self, index).into() }

    fn from_item(item: Boolean) -> Self { <Self as SharedValueArray<Gf2>>::from_item(item.into()) }
}

// TODO: FromPrss is not correct here, this wants the generic-width equivalent of FromRandomU128
pub trait FieldArray<F: Field>: SharedValueArray<F> /*+ FromPrss*/ {
    fn mul_scalar(lhs: Self, rhs: F) -> Self {
        todo!()
    }

    fn mul_elements(lhs: &Self, rhs: &Self) -> Self {
        todo!();
    }
}

// TODO: ditto above re: FromPrss
impl<F: Field, A: SharedValueArray<F>/* + FromPrss*/> FieldArray<F> for A {}

/*
impl<F: Field, A: SharedValueArray<F, 1>> Serializable for A {
    type Size;

    fn serialize(&self, buf: &mut generic_array::GenericArray<u8, Self::Size>) {
        todo!()
    }

    fn deserialize(buf: &generic_array::GenericArray<u8, Self::Size>) -> Self {
        todo!()
    }
}
*/

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
    V: SharedValue,
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
