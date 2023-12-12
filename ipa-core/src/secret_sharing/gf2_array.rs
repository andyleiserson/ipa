use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign}, array,
};

use bitvec::prelude::{BitSlice, Lsb0};
use generic_array::GenericArray;
use typenum::U1;

use crate::{
    ff::{Gf2, Serializable, boolean::Boolean, Field},
    secret_sharing::{SharedValue, SharedValueArray, FieldArray}, protocol::prss::FromRandom, helpers::Message,
};

type WORD = u64;

// Yes, it would be better to calculate this.
//const WORDS_PER_U128: usize = 4;

/// An array of values in Gf2.
///
/// Note that the size of the array is specified as a number of words, not a number of bits. This is
/// necessary because Rust does not support evaluating expressions involving const generics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gf2Array<const WORDS: usize>([WORD; WORDS]);

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

/*
// This is necessary because rust can substitute the associated constant in some places where it
// cannot substitute the type parameter.
impl<const WORDS: usize> Gf2Array<WORDS> {
    const WORDS: usize = WORDS;
}
*/

impl<const WORDS: usize> SharedValueArray<Gf2> for Gf2Array<WORDS> {
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

impl<const WORDS: usize> FieldArray<Gf2> for Gf2Array<WORDS> { }

impl<const WORDS: usize> FieldArray<Boolean> for Gf2Array<WORDS> { }

impl<const WORDS: usize> TryFrom<Vec<Gf2>> for Gf2Array<WORDS> {
    type Error = ();
    fn try_from(_value: Vec<Gf2>) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl<const WORDS: usize> TryFrom<Vec<Boolean>> for Gf2Array<WORDS> {
    type Error = ();
    fn try_from(_value: Vec<Boolean>) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl<'a, 'b, const WORDS: usize> Add<&'b Gf2Array<WORDS>> for &'a Gf2Array<WORDS> {
    type Output = Gf2Array<WORDS>;

    fn add(self, rhs: &'b Gf2Array<WORDS>) -> Self::Output {
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

impl<const WORDS: usize> Add<Self> for Gf2Array<WORDS> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

// add(owned, ref) should be preferred over this.
impl<const WORDS: usize> Add<Gf2Array<WORDS>> for &Gf2Array<WORDS> {
    type Output = Gf2Array<WORDS>;

    fn add(self, rhs: Gf2Array<WORDS>) -> Self::Output {
        Add::add(self, &rhs)
    }
}

impl<const WORDS: usize> Add<&Gf2Array<WORDS>> for Gf2Array<WORDS> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Add::add(&self, rhs)
    }
}

impl<const WORDS: usize> AddAssign<&Self> for Gf2Array<WORDS> {
    fn add_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= *b;
        }
    }
}

impl<const WORDS: usize> AddAssign<Self> for Gf2Array<WORDS> {
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<const WORDS: usize> Neg for &Gf2Array<WORDS> {
    type Output = Gf2Array<WORDS>;

    fn neg(self) -> Self::Output {
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

impl<const WORDS: usize> Neg for Gf2Array<WORDS> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Neg::neg(&self)
    }
}

impl<const WORDS: usize> Sub<Self> for &Gf2Array<WORDS> {
    type Output = Gf2Array<WORDS>;

    fn sub(self, rhs: Self) -> Self::Output {
        Gf2Array(
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

impl<const WORDS: usize> Sub<Self> for Gf2Array<WORDS> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Sub::sub(&self, &rhs)
    }
}

impl<const WORDS: usize> Sub<&Self> for Gf2Array<WORDS> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Sub::sub(&self, rhs)
    }
}

impl<const WORDS: usize> Sub<Gf2Array<WORDS>> for &Gf2Array<WORDS> {
    type Output = Gf2Array<WORDS>;

    fn sub(self, rhs: Gf2Array<WORDS>) -> Self::Output {
        Sub::sub(self, &rhs)
    }
}

impl<const WORDS: usize> SubAssign<&Self> for Gf2Array<WORDS> {
    fn sub_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a -= *b;
        }
    }
}

impl<const WORDS: usize> SubAssign<Self> for Gf2Array<WORDS> {
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}

impl<'a, 'b, const WORDS: usize> Mul<&'b Gf2> for &'a Gf2Array<WORDS> {
    type Output = Gf2Array<WORDS>;

    fn mul(self, rhs: &'b Gf2) -> Self::Output {
        if *rhs != Gf2::ZERO {
            self.clone()
        } else {
            <Gf2Array<WORDS> as SharedValueArray<Gf2>>::ZERO
        }
    }
}

impl<const WORDS: usize> Mul<Gf2> for Gf2Array<WORDS> {
    type Output = Self;

    fn mul(self, rhs: Gf2) -> Self::Output {
        Mul::mul(&self, &rhs)
    }
}

impl<const WORDS: usize> Mul<&Gf2> for Gf2Array<WORDS> {
    type Output = Self;

    fn mul(self, rhs: &Gf2) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<const WORDS: usize> Mul<Gf2> for &Gf2Array<WORDS> {
    type Output = Gf2Array<WORDS>;

    fn mul(self, rhs: Gf2) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<'a, const WORDS: usize> Mul<&'a Boolean> for Gf2Array<WORDS> {
    type Output = Self;

    fn mul(self, rhs: &'a Boolean) -> Self::Output {
        Mul::mul(&self, Gf2::from(*rhs))
    }
}

impl<'a, const WORDS: usize> Mul<&'a Gf2Array<WORDS>> for Gf2Array<WORDS> {
    type Output = Gf2Array<WORDS>;

    fn mul(self, rhs: &'a Gf2Array<WORDS>) -> Self::Output {
        Gf2Array(array::from_fn(|i| self.0[i] & rhs.0[i]))
    }
}

impl FromRandom for Gf2Array<1> {
    type Source = [u128; 1];
    fn len() -> usize { 1 }
    fn from_random(src: Self::Source) -> Self {
        Self([Gf2::from_random(src).as_u128().try_into().unwrap()])
    }
}

impl<const WORDS: usize> Serializable for Gf2Array<WORDS> {
    type Size = U1; // TODO

    fn serialize(&self, _buf: &mut GenericArray<u8, Self::Size>) {
        todo!();
    }

    fn deserialize(_buf: &GenericArray<u8, Self::Size>) -> Self {
        todo!()
    }
}

impl<const WORDS: usize> Message for Gf2Array<WORDS> { }
