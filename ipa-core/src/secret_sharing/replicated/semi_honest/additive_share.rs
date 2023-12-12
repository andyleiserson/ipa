use std::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

use generic_array::{ArrayLength, GenericArray};
use typenum::{Unsigned, Const};

use crate::{
    ff::{boolean::Boolean, ArrayAccess, Expand, Field, GaloisField, Gf2, Serializable, boolean_array::{BAIterator, BA64}, CustomArray},
    secret_sharing::{
        replicated::ReplicatedSecretSharing, FieldArray, Linear as LinearSecretSharing,
        SecretSharing, SharedValue, SharedValueArray, Gf2Array, FieldSimd, gf2_array::WordSize, Vectorizable,
    },
};

/// Additive secret sharing.
///
/// `AdditiveShare` holds two out of three shares of an additive secret sharing, either of a single
/// value with type `V`, or a vector of such values.
#[derive(Clone, PartialEq, Eq)]
pub struct AdditiveShare<V: SharedValue + Vectorizable<N>, const N: usize = 1>(<V as Vectorizable<N>>::T, <V as Vectorizable<N>>::T);

#[derive(Clone, PartialEq, Eq)]
pub struct ASIterator<T: Iterator>(pub T, pub T);

impl<V: SharedValue, const N: usize> SecretSharing<V> for AdditiveShare<V, N> {
    const ZERO: Self = Self(V::Array::ZERO, V::Array::ZERO);
}

impl<F, const N: usize> LinearSecretSharing<F> for AdditiveShare<F, N>
where
    F: Field,
    //F::Array<N>: FieldArray<F>,
{}

/*
impl<F> LinearSecretSharing<F> for AdditiveShare<F, 1>
where
    F: Field,
    F::Array<1>: FieldArray<F>,
{}
*/

impl<V: SharedValue + Debug, const N: usize> Debug for AdditiveShare<V, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?}, {:?})", self.0, self.1)
    }
}

impl<V: SharedValue> Default for AdditiveShare<V> {
    fn default() -> Self {
        AdditiveShare::new(V::ZERO, V::ZERO)
    }
}

impl<V: SharedValue, const N: usize> AdditiveShare<V, N> {
    /// Replicated secret share where both left and right values are `V::ZERO`
    pub const ZERO: Self = Self(V::Array::ZERO, V::Array::ZERO);
}

impl<V: SharedValue> AdditiveShare<V> {
    pub fn as_tuple(&self) -> (V, V) {
        (self.0.index(0), self.1.index(0))
    }
}

impl<V: SharedValue> ReplicatedSecretSharing<V> for AdditiveShare<V> {
    fn new(a: V, b: V) -> Self {
        Self(V::Array::from_item(a), V::Array::from_item(b))
    }

    fn left(&self) -> V {
        self.0.index(0)
    }

    fn right(&self) -> V {
        self.1.index(0)
    }
}

impl<V: SharedValue, const N: usize> AdditiveShare<V, N> {
    pub fn new_arr(a: V::Array<N>, b: V::Array<N>) -> Self {
        Self(a, b)
    }

    pub fn left_arr(&self) -> &V::Array<N> {
        &self.0
    }

    pub fn right_arr(&self) -> &V::Array<N> {
        &self.1
    }
}

pub trait BorrowReplicated<V> {
    fn borrow_left(&self) -> &V;
    fn borrow_right(&self) -> &V;
}

impl BorrowReplicated<bool> for (bool, bool) {
    fn borrow_left(&self) -> &bool {
        &self.0
    }

    fn borrow_right(&self) -> &bool {
        &self.1
    }
}

impl BorrowReplicated<Gf2Array<1>> for AdditiveShare<Gf2>
where
    Const<1>: WordSize,
{
    fn borrow_left(&self) -> &Gf2Array<1> {
        &self.0
    }

    fn borrow_right(&self) -> &Gf2Array<1> {
        &self.1
    }
}

/*
impl BorrowReplicated<Gf2Array<1>> for AdditiveShare<Boolean> {
    fn borrow_left(&self) -> &bool {
        if self.0.into() {
            &true
        } else {
            &Gf2Array::ZERO
        }
    }

    fn borrow_right(&self) -> &bool {
        if self.1.into() {
            &true
        } else {
            &Gf2Array::ZERO
        }
    }
}
*/

pub trait IndexReplicated<'a, V> {
    type Output: BorrowReplicated<V>;

    fn index(&'a self, index: usize) -> Self::Output;
}

impl<'a, B, T> IndexReplicated<'a, bool> for AdditiveShare<B>
where
    B: SharedValue + ArrayAccess<Output = T>,
    T: Into<bool>,
{
    type Output = (bool, bool);
    fn index(&'a self, index: usize) -> Self::Output {
        (
            self.0.index(0).get(index).unwrap().into(),
            self.1.index(0).get(index).unwrap().into(),
        )
    }
}

impl<V: SharedValue> AdditiveShare<V>
where
    Self: Serializable,
{
    // Deserialize a slice of bytes into an iterator of replicated shares
    pub fn from_byte_slice(from: &[u8]) -> impl Iterator<Item = Self> + '_ {
        debug_assert!(from.len() % <AdditiveShare<V> as Serializable>::Size::USIZE == 0);

        from.chunks(<AdditiveShare<V> as Serializable>::Size::USIZE)
            .map(|chunk| {
                <AdditiveShare<V> as Serializable>::deserialize(GenericArray::from_slice(chunk))
            })
    }
}

impl<'a, 'b, V: SharedValue, const N: usize> Add<&'b AdditiveShare<V, N>>
    for &'a AdditiveShare<V, N>
{
    type Output = AdditiveShare<V, N>;

    fn add(self, rhs: &'b AdditiveShare<V, N>) -> Self::Output {
        AdditiveShare(
            Add::add(self.0.clone(), &rhs.0),
            Add::add(self.1.clone(), &rhs.1),
        )
    }
}

impl<V: SharedValue, const N: usize> Add<Self> for AdditiveShare<V, N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> Add<AdditiveShare<V, N>> for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn add(self, rhs: AdditiveShare<V, N>) -> Self::Output {
        Add::add(self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> Add<&AdditiveShare<V, N>> for AdditiveShare<V, N> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Add::add(&self, rhs)
    }
}

impl<V: SharedValue, const N: usize> AddAssign<&Self> for AdditiveShare<V, N> {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += &rhs.0;
        self.1 += &rhs.1;
    }
}

impl<V: SharedValue, const N: usize> AddAssign<Self> for AdditiveShare<V, N> {
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<V: SharedValue, const N: usize> Neg for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn neg(self) -> Self::Output {
        AdditiveShare(-self.0.clone(), -self.1.clone())
    }
}

impl<V: SharedValue, const N: usize> Neg for AdditiveShare<V, N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Neg::neg(&self)
    }
}

impl<V: SharedValue, const N: usize> Sub<Self> for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn sub(self, rhs: Self) -> Self::Output {
        AdditiveShare(
            Sub::sub(self.0.clone(), &rhs.0),
            Sub::sub(self.1.clone(), &rhs.1),
        )
    }
}

impl<V: SharedValue, const N: usize> Sub<Self> for AdditiveShare<V, N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Sub::sub(&self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> Sub<&Self> for AdditiveShare<V, N> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Sub::sub(&self, rhs)
    }
}

impl<V: SharedValue, const N: usize> Sub<AdditiveShare<V, N>> for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn sub(self, rhs: AdditiveShare<V, N>) -> Self::Output {
        Sub::sub(self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> SubAssign<&Self> for AdditiveShare<V, N> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= &rhs.0;
        self.1 -= &rhs.1;
    }
}

impl<V: SharedValue, const N: usize> SubAssign<Self> for AdditiveShare<V, N> {
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}

impl<'a, 'b, F, const N: usize> Mul<&'b F> for &'a AdditiveShare<F, N>
where
    F: Field + FieldSimd<N>,
    //F::Array<N>: FieldArray<F>,
{
    type Output = AdditiveShare<F, N>;

    fn mul(self, rhs: &'b F) -> Self::Output {
        AdditiveShare(
            self.0.clone() * rhs,
            self.1.clone() * rhs,
        )
    }
}

impl<F: Field, const N: usize> Mul<F> for AdditiveShare<F, N>
where
    F: Field,
    //F::Array<N>: FieldArray<F>,
{
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<'a, F, const N: usize> Mul<&'a F> for AdditiveShare<F, N>
where
    F: Field,
    //F::Array<N>: FieldArray<F>,
{
    type Output = Self;

    fn mul(self, rhs: &F) -> Self::Output {
        Mul::mul(&self, *rhs)
    }
}

impl<F, const N: usize> Mul<F> for &AdditiveShare<F, N>
where
    F: Field,
    //F::Array<N>: FieldArray<F>,
{
    type Output = AdditiveShare<F, N>;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(self, rhs)
    }
}

impl<V: SharedValue> From<(V, V)> for AdditiveShare<V> {
    fn from(s: (V, V)) -> Self {
        AdditiveShare::new(s.0, s.1)
    }
}

// TODO: vectorize
impl<V: std::ops::Not<Output = V> + SharedValue> std::ops::Not for AdditiveShare<V> {
    type Output = Self;

    fn not(self) -> Self::Output {
        AdditiveShare(
            V::Array::from_item(!(self.0.index(0))),
            V::Array::from_item(!(self.1.index(0))),
        )
    }
}

impl<V: SharedValue> Serializable for AdditiveShare<V>
where
    V::Size: Add<V::Size>,
    <V::Size as Add<V::Size>>::Output: ArrayLength,
{
    type Size = <V::Size as Add<V::Size>>::Output;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let (left, right) = buf.split_at_mut(V::Size::USIZE);
        self.left().serialize(GenericArray::from_mut_slice(left));
        self.right().serialize(GenericArray::from_mut_slice(right));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let left = V::deserialize(GenericArray::from_slice(&buf[..V::Size::USIZE]));
        let right = V::deserialize(GenericArray::from_slice(&buf[V::Size::USIZE..]));

        Self::new(left, right)
    }
}

/// Implement `ArrayAccess` for `AdditiveShare` over `SharedValue` that implements `ArrayAccess`
impl<S> ArrayAccess for AdditiveShare<S>
where
    S: ArrayAccess + SharedValue,
    <S as ArrayAccess>::Output: SharedValue,
{
    type Output = AdditiveShare<<S as ArrayAccess>::Output>;

    fn get(&self, index: usize) -> Option<Self::Output> {
        unimplemented!()
        /*
        self.0
            .index(0)
            .get(index)
            .zip(self.1.index(0).get(index))
            .map(|v| AdditiveShare(v.0, v.1))
        */
    }

    fn set(&mut self, index: usize, e: Self::Output) {
        unimplemented!();
        /*
        self.0.index(0).set(index, e.0);
        self.1.index(0).set(index, e.1);
        */
    }
}

impl<S> Expand for AdditiveShare<S>
where
    S: Expand + SharedValue,
    <S as Expand>::Input: SharedValue,
{
    type Input = AdditiveShare<<S as Expand>::Input>;

    fn expand(v: &Self::Input) -> Self {
        unimplemented!()
        //AdditiveShare(S::expand(&v.0), S::expand(&v.1))
    }
}

impl<T> Iterator for ASIterator<T>
where
    T: Iterator,
    T::Item: SharedValue,
{
    type Item = AdditiveShare<T::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        unimplemented!();
        /*
        match (self.0.next(), self.1.next()) {
            (Some(left), Some(right)) => Some(AdditiveShare(left, right)),
            _ => None,
        }
        */
    }
}

impl<S> FromIterator<AdditiveShare<<S as ArrayAccess>::Output>> for AdditiveShare<S>
where
    S: SharedValue + ArrayAccess,
    <S as ArrayAccess>::Output: SharedValue,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = AdditiveShare<<S as ArrayAccess>::Output>>,
    {
        let mut result = AdditiveShare::<S>::ZERO;
        for (i, v) in iter.into_iter().enumerate() {
            result.set(i, v);
        }
        result
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::AdditiveShare;
    use crate::{
        ff::{Field, Fp31},
        secret_sharing::replicated::ReplicatedSecretSharing,
    };

    fn secret_share(
        a: u8,
        b: u8,
        c: u8,
    ) -> (
        AdditiveShare<Fp31>,
        AdditiveShare<Fp31>,
        AdditiveShare<Fp31>,
    ) {
        (
            AdditiveShare::new(Fp31::truncate_from(a), Fp31::truncate_from(b)),
            AdditiveShare::new(Fp31::truncate_from(b), Fp31::truncate_from(c)),
            AdditiveShare::new(Fp31::truncate_from(c), Fp31::truncate_from(a)),
        )
    }

    fn assert_valid_secret_sharing(
        res1: &AdditiveShare<Fp31>,
        res2: &AdditiveShare<Fp31>,
        res3: &AdditiveShare<Fp31>,
    ) {
        assert_eq!(res1.1, res2.0);
        assert_eq!(res2.1, res3.0);
        assert_eq!(res3.1, res1.0);
    }

    fn assert_secret_shared_value(
        a1: &AdditiveShare<Fp31>,
        a2: &AdditiveShare<Fp31>,
        a3: &AdditiveShare<Fp31>,
        expected_value: u128,
    ) {
        assert_eq!(
            a1.left() + a2.left() + a3.left(),
            Fp31::truncate_from(expected_value)
        );
        assert_eq!(
            a1.right() + a2.right() + a3.right(),
            Fp31::truncate_from(expected_value)
        );
    }

    fn addition_test_case(a: (u8, u8, u8), b: (u8, u8, u8), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 + r2
        let res1 = a1 + &b1;
        let res2 = a2 + &b2;
        let res3 = a3 + &b3;

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_simple_addition() {
        addition_test_case((1, 0, 0), (1, 0, 0), 2);
        addition_test_case((1, 0, 0), (0, 1, 0), 2);
        addition_test_case((1, 0, 0), (0, 0, 1), 2);

        addition_test_case((0, 1, 0), (1, 0, 0), 2);
        addition_test_case((0, 1, 0), (0, 1, 0), 2);
        addition_test_case((0, 1, 0), (0, 0, 1), 2);

        addition_test_case((0, 0, 1), (1, 0, 0), 2);
        addition_test_case((0, 0, 1), (0, 1, 0), 2);
        addition_test_case((0, 0, 1), (0, 0, 1), 2);

        addition_test_case((0, 0, 0), (1, 0, 0), 1);
        addition_test_case((0, 0, 0), (0, 1, 0), 1);
        addition_test_case((0, 0, 0), (0, 0, 1), 1);

        addition_test_case((1, 0, 0), (0, 0, 0), 1);
        addition_test_case((0, 1, 0), (0, 0, 0), 1);
        addition_test_case((0, 0, 1), (0, 0, 0), 1);

        addition_test_case((0, 0, 0), (0, 0, 0), 0);

        addition_test_case((1, 3, 5), (10, 0, 2), 21);
    }

    fn subtraction_test_case(a: (u8, u8, u8), b: (u8, u8, u8), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 - r2
        let res1 = a1 - &b1;
        let res2 = a2 - &b2;
        let res3 = a3 - &b3;

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_simple_subtraction() {
        subtraction_test_case((1, 0, 0), (1, 0, 0), 0);
        subtraction_test_case((1, 0, 0), (0, 1, 0), 0);
        subtraction_test_case((1, 0, 0), (0, 0, 1), 0);

        subtraction_test_case((0, 1, 0), (1, 0, 0), 0);
        subtraction_test_case((0, 1, 0), (0, 1, 0), 0);
        subtraction_test_case((0, 1, 0), (0, 0, 1), 0);

        subtraction_test_case((0, 0, 1), (1, 0, 0), 0);
        subtraction_test_case((0, 0, 1), (0, 1, 0), 0);
        subtraction_test_case((0, 0, 1), (0, 0, 1), 0);

        subtraction_test_case((0, 0, 0), (1, 0, 0), 30);
        subtraction_test_case((0, 0, 0), (0, 1, 0), 30);
        subtraction_test_case((0, 0, 0), (0, 0, 1), 30);

        subtraction_test_case((1, 0, 0), (0, 0, 0), 1);
        subtraction_test_case((0, 1, 0), (0, 0, 0), 1);
        subtraction_test_case((0, 0, 1), (0, 0, 0), 1);

        subtraction_test_case((0, 0, 0), (0, 0, 0), 0);

        subtraction_test_case((1, 3, 5), (10, 0, 2), 28);
    }

    fn mult_by_constant_test_case(a: (u8, u8, u8), c: u8, expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);

        let res1 = a1 * Fp31::truncate_from(c);
        let res2 = a2 * Fp31::truncate_from(c);
        let res3 = a3 * Fp31::truncate_from(c);

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_mult_by_constant() {
        mult_by_constant_test_case((1, 0, 0), 2, 2);
        mult_by_constant_test_case((0, 1, 0), 2, 2);
        mult_by_constant_test_case((0, 0, 1), 2, 2);
        mult_by_constant_test_case((0, 0, 0), 2, 0);
    }
}
