use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

use bitvec::prelude::{BitSlice, Lsb0};
use generic_array::GenericArray;
use typenum::U1;

use crate::{
    ff::{Gf2, Serializable},
    secret_sharing::{SharedValue, SharedValueArray},
};

/// An array of values in Gf2.
///
/// The const parameter `N` specifies the number of `usize` values used to hold the array, _not_ the
/// number of elements in the array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gf2Array<const N: usize>([usize; N]);

impl<const N: usize> SharedValueArray<Gf2> for Gf2Array<N> {
    const ZERO: Self = Self([0usize; N]);

    fn capacity() -> usize {
        usize::try_from(usize::BITS).unwrap() * N
    }

    fn index(&self, index: usize) -> Gf2 {
        BitSlice::<_, Lsb0>::from_slice(&self.0)[index].into()
    }

    fn from_item(item: Gf2) -> Self {
        let mut res = [0; N];
        BitSlice::<_, Lsb0>::from_slice_mut(&mut res).set(0, item != Gf2::ZERO);
        Gf2Array(res)
    }
}

impl<const N: usize> TryFrom<Vec<Gf2>> for Gf2Array<N> {
    type Error = ();
    fn try_from(value: Vec<Gf2>) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl<'a, 'b, const N: usize> Add<&'b Gf2Array<N>> for &'a Gf2Array<N> {
    type Output = Gf2Array<N>;

    fn add(self, rhs: &'b Gf2Array<N>) -> Self::Output {
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

impl<const N: usize> Add<Self> for Gf2Array<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

// add(owned, ref) should be preferred over this.
impl<const N: usize> Add<Gf2Array<N>> for &Gf2Array<N> {
    type Output = Gf2Array<N>;

    fn add(self, rhs: Gf2Array<N>) -> Self::Output {
        Add::add(self, &rhs)
    }
}

impl<const N: usize> Add<&Gf2Array<N>> for Gf2Array<N> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Add::add(&self, rhs)
    }
}

impl<const N: usize> AddAssign<&Self> for Gf2Array<N> {
    fn add_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a ^= *b;
        }
    }
}

impl<const N: usize> AddAssign<Self> for Gf2Array<N> {
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<const N: usize> Neg for &Gf2Array<N> {
    type Output = Gf2Array<N>;

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

impl<const N: usize> Neg for Gf2Array<N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Neg::neg(&self)
    }
}

impl<const N: usize> Sub<Self> for &Gf2Array<N> {
    type Output = Gf2Array<N>;

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

impl<const N: usize> Sub<Self> for Gf2Array<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Sub::sub(&self, &rhs)
    }
}

impl<const N: usize> Sub<&Self> for Gf2Array<N> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Sub::sub(&self, rhs)
    }
}

impl<const N: usize> Sub<Gf2Array<N>> for &Gf2Array<N> {
    type Output = Gf2Array<N>;

    fn sub(self, rhs: Gf2Array<N>) -> Self::Output {
        Sub::sub(self, &rhs)
    }
}

impl<const N: usize> SubAssign<&Self> for Gf2Array<N> {
    fn sub_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a -= *b;
        }
    }
}

impl<const N: usize> SubAssign<Self> for Gf2Array<N> {
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}

impl<'a, 'b, const N: usize> Mul<&'b Gf2> for &'a Gf2Array<N> {
    type Output = Gf2Array<N>;

    fn mul(self, rhs: &'b Gf2) -> Self::Output {
        if *rhs != Gf2::ZERO {
            self.clone()
        } else {
            Gf2Array::ZERO
        }
    }
}

impl<const N: usize> Mul<Gf2> for Gf2Array<N> {
    type Output = Self;

    fn mul(self, rhs: Gf2) -> Self::Output {
        Mul::mul(&self, &rhs)
    }
}

impl<const N: usize> Mul<&Gf2> for Gf2Array<N> {
    type Output = Self;

    fn mul(self, rhs: &Gf2) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<const N: usize> Mul<Gf2> for &Gf2Array<N> {
    type Output = Gf2Array<N>;

    fn mul(self, rhs: Gf2) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<const N: usize> Serializable for Gf2Array<N> {
    type Size = U1; // TODO

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        todo!();
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        todo!()
    }
}
