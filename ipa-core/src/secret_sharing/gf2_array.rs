use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign, Div}, array,
};

use bitvec::prelude::{BitSlice, Lsb0};
use generic_array::{GenericArray, ArrayLength};
use typenum::{U1, Const, U63, U64, ToUInt, U, U8};

use crate::{
    ff::{Gf2, Serializable, boolean::Boolean, Field},
    secret_sharing::{SharedValue, SharedValueArray, FieldArray}, protocol::prss::FromRandom, helpers::Message,
};

pub trait Width: WordSize {}

type WORD = u64;

type Words<const BITS: usize> = <<Const<BITS> as Add<U63>>::Output as Div<U64>>::Output;

pub trait WordSize {
    type Size: ArrayLength;
}

impl<const N: usize> WordSize for Const<N>
where
    Const<N>: ToUInt,
    U<N>: Add<U63>,
    <U<N> as Add<U63>>::Output: Div<U64>,
    <<U<N> as Add<U63>>::Output as Div<U64>>::Output: ArrayLength,
{
    type Size = <<U<N> as Add<U63>>::Output as Div<U64>>::Output;
}

/// An array of values in Gf2.
///
/// Note that the size of the array is specified as a number of words, not a number of bits. This is
/// necessary because Rust does not support evaluating expressions involving const generics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gf2Array<const BITS: usize, const WORDS: usize>([WORD; WORDS]);

/*
impl<const N: usize> From<Gf2Array<N>> for [Boolean; N] {
    fn from(_value: Gf2Array<N>) -> Self {
        todo!()
    }
}

impl<const N: usize> From<Gf2Array<N>> for [Gf2; N] {
    fn from(_value: Gf2Array<N>) -> Self {
        todo!()
    }
}
*/

/*
// This is necessary because rust can substitute the associated constant in some places where it
// cannot substitute the type parameter.
impl<const BITS: usize, const WORDS: usize> Gf2Array<BITS, WORDS> {
    const BITS: usize, const WORDS: usize = WORDS;
}
*/

impl<const BITS: usize, const WORDS: usize> SharedValueArray<Gf2> for Gf2Array<BITS, WORDS> {
    const ZERO: Self = Self([0; WORDS]);

    fn index(&self, index: usize) -> Gf2 {
        BitSlice::<_, Lsb0>::from_slice(&self.0)[index].into()
    }

    fn from_item(item: Gf2) -> Self {
        let mut res = [0; WORDS];
        BitSlice::<_, Lsb0>::from_slice_mut(&mut res).set(0, item != Gf2::ZERO);
        Gf2Array(res)
    }
}

impl<const BITS: usize, const WORDS: usize> FieldArray<Gf2> for Gf2Array<BITS, WORDS> { }

impl<const BITS: usize, const WORDS: usize> FieldArray<Boolean> for Gf2Array<BITS, WORDS> { }

impl<const BITS: usize, const WORDS: usize> TryFrom<Vec<Gf2>> for Gf2Array<BITS, WORDS> {
    type Error = ();
    fn try_from(value: Vec<Gf2>) -> Result<Self, Self::Error> {
        assert_eq!(value.len(), BITS);
        let mut res = 0u64;
        for (i, v) in value.into_iter().enumerate() {
            res |= u64::try_from(v.as_u128()).unwrap() << i;
        }
        Ok(Self(vec![res].try_into().unwrap()))
    }
}

impl<const BITS: usize, const WORDS: usize> TryFrom<Vec<Boolean>> for Gf2Array<BITS, WORDS> {
    type Error = ();
    fn try_from(_value: Vec<Boolean>) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl<'a, 'b, const BITS: usize, const WORDS: usize> Add<&'b Gf2Array<BITS, WORDS>> for &'a Gf2Array<BITS, WORDS> {
    type Output = Gf2Array<BITS, WORDS>;

    fn add(self, rhs: &'b Gf2Array<BITS, WORDS>) -> Self::Output {
        Gf2Array(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(a, b)| *a ^ *b)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

impl<const BITS: usize, const WORDS: usize> Add<Self> for Gf2Array<BITS, WORDS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

// add(owned, ref) should be preferred over this.
impl<const BITS: usize, const WORDS: usize> Add<Gf2Array<BITS, WORDS>> for &Gf2Array<BITS, WORDS> {
    type Output = Gf2Array<BITS, WORDS>;

    fn add(self, rhs: Gf2Array<BITS, WORDS>) -> Self::Output {
        Add::add(self, &rhs)
    }
}

impl<const BITS: usize, const WORDS: usize> Add<&Gf2Array<BITS, WORDS>> for Gf2Array<BITS, WORDS> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Add::add(&self, rhs)
    }
}

impl<const BITS: usize, const WORDS: usize> AddAssign<&Self> for Gf2Array<BITS, WORDS> {
    fn add_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= *b;
        }
    }
}

impl<const BITS: usize, const WORDS: usize> AddAssign<Self> for Gf2Array<BITS, WORDS> {
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<const BITS: usize, const WORDS: usize> Neg for &Gf2Array<BITS, WORDS> {
    type Output = Gf2Array<BITS, WORDS>;

    fn neg(self) -> Self::Output {
        self.clone()
    }
}

impl<const BITS: usize, const WORDS: usize> Neg for Gf2Array<BITS, WORDS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Neg::neg(&self)
    }
}

impl<const BITS: usize, const WORDS: usize> Sub<Self> for &Gf2Array<BITS, WORDS> {
    type Output = Gf2Array<BITS, WORDS>;

    fn sub(self, rhs: Self) -> Self::Output {
        Gf2Array(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(a, b)| *a ^ *b)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

impl<const BITS: usize, const WORDS: usize> Sub<Self> for Gf2Array<BITS, WORDS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Sub::sub(&self, &rhs)
    }
}

impl<const BITS: usize, const WORDS: usize> Sub<&Self> for Gf2Array<BITS, WORDS> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Sub::sub(&self, rhs)
    }
}

impl<const BITS: usize, const WORDS: usize> Sub<Gf2Array<BITS, WORDS>> for &Gf2Array<BITS, WORDS> {
    type Output = Gf2Array<BITS, WORDS>;

    fn sub(self, rhs: Gf2Array<BITS, WORDS>) -> Self::Output {
        Sub::sub(self, &rhs)
    }
}

impl<const BITS: usize, const WORDS: usize> SubAssign<&Self> for Gf2Array<BITS, WORDS> {
    fn sub_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= *b;
        }
    }
}

impl<const BITS: usize, const WORDS: usize> SubAssign<Self> for Gf2Array<BITS, WORDS> {
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}

impl<'a, 'b, const BITS: usize, const WORDS: usize> Mul<&'b Gf2> for &'a Gf2Array<BITS, WORDS> {
    type Output = Gf2Array<BITS, WORDS>;

    fn mul(self, rhs: &'b Gf2) -> Self::Output {
        if *rhs != Gf2::ZERO {
            self.clone()
        } else {
            <Gf2Array<BITS, WORDS> as SharedValueArray<Gf2>>::ZERO
        }
    }
}

impl<const BITS: usize, const WORDS: usize> Mul<Gf2> for Gf2Array<BITS, WORDS> {
    type Output = Self;

    fn mul(self, rhs: Gf2) -> Self::Output {
        Mul::mul(&self, &rhs)
    }
}

impl<const BITS: usize, const WORDS: usize> Mul<&Gf2> for Gf2Array<BITS, WORDS> {
    type Output = Self;

    fn mul(self, rhs: &Gf2) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<const BITS: usize, const WORDS: usize> Mul<Gf2> for &Gf2Array<BITS, WORDS> {
    type Output = Gf2Array<BITS, WORDS>;

    fn mul(self, rhs: Gf2) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<'a, const BITS: usize, const WORDS: usize> Mul<&'a Boolean> for Gf2Array<BITS, WORDS> {
    type Output = Self;

    fn mul(self, rhs: &'a Boolean) -> Self::Output {
        Mul::mul(&self, Gf2::from(*rhs))
    }
}

impl<'a, const BITS: usize, const WORDS: usize> Mul<&'a Gf2Array<BITS, WORDS>> for Gf2Array<BITS, WORDS> {
    type Output = Gf2Array<BITS, WORDS>;

    fn mul(self, rhs: &'a Gf2Array<BITS, WORDS>) -> Self::Output {
        Gf2Array(array::from_fn(|i| self.0[i] & rhs.0[i]))
    }
}

impl<const BITS: usize, const WORDS: usize> std::ops::Not for Gf2Array<BITS, WORDS> {
    type Output = Gf2Array<BITS, WORDS>;

    fn not(self) -> Self::Output {
        Gf2Array(
            self.0
                .iter()
                .map(|x| !*x)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )
    }
}

impl FromRandom for Gf2Array<1, 1> {
    type Source = [u128; 1];
    fn len() -> usize { 1 }
    fn from_random(src: Self::Source) -> Self {
        Self([Gf2::from_random(src).as_u128().try_into().unwrap()])
    }
}

impl FromRandom for Gf2Array<64, 1> {
    type Source = [u128; 1];
    fn len() -> usize { 1 }
    fn from_random(src: Self::Source) -> Self {
        Self([(src[0] & u128::from(u64::MAX)).try_into().unwrap()])
    }
}

impl Serializable for Gf2Array<1, 1> {
    type Size = U1;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf[0] = self.0[0].to_le_bytes()[0];
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        Self([(buf[0] & 1).into()])
    }
}

impl Serializable for Gf2Array<64, 1> {
    type Size = U8;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(&self.0[0].to_le_bytes());
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        Self([u64::from_le_bytes(<[u8; 8]>::from(*buf))])
    }
}

impl<const BITS: usize, const WORDS: usize> Message for Gf2Array<BITS, WORDS>
where
    Self: Serializable
{ }

impl Into<[Gf2; 64]> for crate::secret_sharing::Gf2Array<64, 1> {
    fn into(self) -> [Gf2; 64] {
        (0..64).map(|i| if (self.0[0] >> i) & 1 == 1 { Gf2::ONE } else { Gf2::ZERO }).collect::<Vec<_>>().try_into().unwrap()
    }
}
