use std::{
    array,
    fmt::Debug,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

use generic_array::{ArrayLength, GenericArray};
use typenum::U32;

use crate::{
    ff::{Field, Serializable, Fp32BitPrime, boolean::Boolean, boolean_array::BA64},
    helpers::Message,
    secret_sharing::{SharedValue, SharedValueArray, FieldArray}, protocol::prss::FromRandom,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdArray<V: SharedValue, const N: usize>([V; N]);

impl<V: SharedValue, const N: usize> From<StdArray<V, N>> for [V; N] {
    fn from(value: StdArray<V, N>) -> Self {
        value.0
    }
}

impl<V: SharedValue, const N: usize> SharedValueArray<V> for StdArray<V, N> {
    const ZERO: Self = Self([V::ZERO; N]);

    fn index(&self, index: usize) -> V {
        self.0[index]
    }

    fn from_item(item: V) -> Self {
        let mut res = Self::ZERO;
        res.0[0] = item;
        res
    }
}

impl<F: Field, const N: usize> FieldArray<F> for StdArray<F, N> { }

impl<V: SharedValue, const N: usize> TryFrom<Vec<V>> for StdArray<V, N> {
    type Error = ();
    fn try_from(value: Vec<V>) -> Result<Self, Self::Error> {
        value.try_into().map(Self).map_err(|_| ())
    }
}

impl<'a, 'b, V: SharedValue, const N: usize> Add<&'b StdArray<V, N>> for &'a StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn add(self, rhs: &'b StdArray<V, N>) -> Self::Output {
        StdArray(array::from_fn(|i| self.0[i] + rhs.0[i]))
    }
}

impl<V: SharedValue, const N: usize> Add<Self> for StdArray<V, N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

// add(owned, ref) should be preferred over this.
impl<V: SharedValue, const N: usize> Add<StdArray<V, N>> for &StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn add(self, rhs: StdArray<V, N>) -> Self::Output {
        Add::add(self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> Add<&StdArray<V, N>> for StdArray<V, N> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Add::add(&self, rhs)
    }
}

impl<V: SharedValue, const N: usize> AddAssign<&Self> for StdArray<V, N> {
    fn add_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a += *b;
        }
    }
}

impl<V: SharedValue, const N: usize> AddAssign<Self> for StdArray<V, N> {
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<V: SharedValue, const N: usize> Neg for &StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn neg(self) -> Self::Output {
        StdArray(
            self.0
                .iter()
                .map(|x| -*x)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

impl<V: SharedValue, const N: usize> Neg for StdArray<V, N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Neg::neg(&self)
    }
}

impl<V: SharedValue, const N: usize> Sub<Self> for &StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn sub(self, rhs: Self) -> Self::Output {
        StdArray(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(a, b)| *a - *b)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

impl<V: SharedValue, const N: usize> Sub<Self> for StdArray<V, N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Sub::sub(&self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> Sub<&Self> for StdArray<V, N> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Sub::sub(&self, rhs)
    }
}

impl<V: SharedValue, const N: usize> Sub<StdArray<V, N>> for &StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn sub(self, rhs: StdArray<V, N>) -> Self::Output {
        Sub::sub(self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> SubAssign<&Self> for StdArray<V, N> {
    fn sub_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a -= *b;
        }
    }
}

impl<V: SharedValue, const N: usize> SubAssign<Self> for StdArray<V, N> {
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}

impl<'a, 'b, F: Field, const N: usize> Mul<&'b F> for &'a StdArray<F, N> {
    type Output = StdArray<F, N>;

    fn mul(self, rhs: &'b F) -> Self::Output {
        StdArray(
            self.0
                .iter()
                .map(|a| *a * *rhs)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

impl<F: Field, const N: usize> Mul<F> for StdArray<F, N> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(&self, &rhs)
    }
}

impl<F: Field, const N: usize> Mul<&F> for StdArray<F, N> {
    type Output = Self;

    fn mul(self, rhs: &F) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<F: Field, const N: usize> Mul<F> for &StdArray<F, N> {
    type Output = StdArray<F, N>;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<'a, F: Field, const N: usize> Mul<&'a StdArray<F, N>> for StdArray<F, N> {
    type Output = StdArray<F, N>;

    fn mul(self, rhs: &'a StdArray<F, N>) -> Self::Output {
        StdArray(array::from_fn(|i| self.0[i] * rhs.0[i]))
    }
}

impl<const N: usize> std::ops::Not for StdArray<Boolean, N> {
    type Output = StdArray<Boolean, N>;

    fn not(self) -> Self::Output {
        StdArray(
            self.0
                .iter()
                .map(|x| !*x)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

impl std::ops::Not for StdArray<BA64, 1> {
    type Output = StdArray<BA64, 1>;

    fn not(self) -> Self::Output {
        StdArray([!self.0[0]])
    }
}

impl<F: SharedValue + FromRandom<Source = [u128; 1]>> FromRandom for StdArray<F, 1> {
    type Source = [u128; 1];
    fn len() -> usize { 1 }
    fn from_random(src: Self::Source) -> Self {
        Self([F::from_random(src)])
    }
}

impl FromRandom for StdArray<Fp32BitPrime, 32> {
    type Source = [u128; 8];

    fn len() -> usize { 8 }

    fn from_random(src: [u128; 8]) -> Self {
        // TODO: reduce mod p
        const WORDS_PER_U128: u32 = 4;
        const WORDS: usize = 32;
        let mut res = Vec::with_capacity(WORDS);
        for word in src {
            for j in 0..WORDS_PER_U128 {
                res.push(Fp32BitPrime::truncate_from::<u128>((word >> (j * Fp32BitPrime::BITS)) & u128::from(u32::MAX)));
            }
        }
        res.try_into().unwrap()
    }
}

impl<V: SharedValue> Serializable for StdArray<V, 1> {
    type Size = <V as Serializable>::Size;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        self.0[0].serialize(buf);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        StdArray([V::deserialize(buf)])
    }
}

impl<V: SharedValue> Serializable for StdArray<V, 32>
where
    V: SharedValue,
    <V as Serializable>::Size: Mul<U32>,
    <<V as Serializable>::Size as Mul<U32>>::Output: ArrayLength,
{
    type Size = <<V as Serializable>::Size as Mul<U32>>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        for i in 0..32 {
            self.0[i].serialize(&mut GenericArray::try_from_mut_slice(&mut buf[4*i..4*(i+1)]).unwrap()); // TODO: sizeof
        }
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        Self(array::from_fn(|i| V::deserialize(&GenericArray::from_slice(&buf[4*i..4*(i+1)])))) // TODO: sizeof
    }
}

impl<V: SharedValue, const N: usize> Message for StdArray<V, N> where Self: Serializable {}
