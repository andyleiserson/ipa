use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
    slice,
};

use crate::{
    error::Error,
    ff::{boolean::Boolean, ArrayAccessRef, PrimeField},
    protocol::prss::{FromPrss, FromRandom, PrssIndex, SharedRandomness},
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, Linear as LinearSecretSharing, LinearRefOps,
        SharedValue, Vectorizable,
    },
};

#[derive(Clone, Debug, PartialEq)]
pub struct BitDecomposed<S> {
    bits: Vec<S>,
}

impl<S> BitDecomposed<S> {
    const MAX: usize = 256;

    /// Create a new value from an iterator.
    /// # Panics
    /// If the iterator produces more than `Self::MAX` items.
    pub fn new<I: IntoIterator<Item = S>>(bits: I) -> Self {
        let bits = bits.into_iter().collect::<Vec<_>>();
        assert!(bits.len() <= Self::MAX);
        Self { bits }
    }

    /// Decompose `count` values from context, using a counter from `[0, count)`.
    /// # Panics
    /// If `count` is greater than `Self::MAX`.
    pub fn decompose<I, F>(count: I, f: F) -> Self
    where
        I: From<u8> + Copy,
        u8: TryFrom<I>,
        <u8 as TryFrom<I>>::Error: Debug,
        F: Fn(I) -> S,
    {
        let max = u8::try_from(count).unwrap();
        assert!(usize::from(max) <= Self::MAX);

        Self::try_from((0..max).map(I::from).map(f).collect::<Vec<_>>()).unwrap()
    }

    /// Translate this into a different form.
    pub fn map<F: Fn(S) -> T, T>(self, f: F) -> BitDecomposed<T> {
        BitDecomposed::new(self.bits.into_iter().map(f))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    pub fn collect_bits<T: FromIterator<S>>(self) -> T {
        self.into_iter().collect()
    }

    /// The inner vector of this type is a list any field type (e.g. Z2, Zp) and
    /// each element is (should be) a share of 1 or 0. This function iterates
    /// over the shares of bits and computes `Σ(2^i * b_i)`.
    pub fn to_additive_sharing_in_large_field<F>(&self) -> S
    where
        S: LinearSecretSharing<F>,
        for<'a> &'a S: LinearRefOps<'a, S, F>,
        F: PrimeField,
    {
        self.iter().enumerate().fold(S::ZERO, |acc, (i, b)| {
            acc + (b * F::truncate_from(1_u128 << i))
        })
    }

    // Same as above, but without the need to HRTB, as this doesn't used references
    // but rather takes ownership over the BitDecomposed
    pub fn to_additive_sharing_in_large_field_consuming<F>(bits: BitDecomposed<S>) -> S
    where
        S: LinearSecretSharing<F>,
        F: PrimeField,
    {
        bits.into_iter().enumerate().fold(S::ZERO, |acc, (i, b)| {
            acc + (b * F::truncate_from(1_u128 << i))
        })
    }

    #[must_use]
    ///
    /// # Panics
    /// If you provide an index that can't be casted to a usize
    pub fn split_at(self, idx: u32) -> (BitDecomposed<S>, BitDecomposed<S>) {
        let idx: usize = idx.try_into().unwrap();
        let mut left = Vec::with_capacity(idx);
        let mut right = Vec::with_capacity(self.len() - idx);
        for (i, bit) in self.bits.into_iter().enumerate() {
            if i < idx {
                left.push(bit);
            } else {
                right.push(bit);
            }
        }
        (BitDecomposed::new(left), BitDecomposed::new(right))
    }
}

impl BitDecomposed<Boolean> {
    pub fn as_u128(self: &BitDecomposed<Boolean>) -> u128 {
        self.bits
            .iter()
            .enumerate()
            .fold(0, |acc, (i, b)| acc + (b.as_u128() << i))
    }
}

impl<S: Clone> BitDecomposed<S> {
    pub fn resize(&mut self, new_len: usize, value: S) {
        assert!(new_len <= Self::MAX);
        self.bits.resize(new_len, value);
    }

    pub fn push(&mut self, value: S) {
        assert!(self.len() < Self::MAX);
        self.bits.push(value);
    }

    pub fn truncate(&mut self, len: usize) {
        self.bits.truncate(len);
    }

    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity <= Self::MAX);
        Self {
            bits: Vec::with_capacity(capacity),
        }
    }
}

impl<S: SharedValue> BitDecomposed<S> {
    pub fn zero(len: usize) -> Self {
        assert!(len <= Self::MAX);
        Self {
            bits: vec![S::ZERO; len],
        }
    }
}

impl<A, const N: usize> FromPrss<usize> for BitDecomposed<AdditiveShare<Boolean, N>>
where
    A: SharedValue + FromRandom,
    Boolean: Vectorizable<N, Array = A>,
{
    fn from_prss_with<P: SharedRandomness + ?Sized, I: Into<PrssIndex>>(
        prss: &P,
        index: I,
        len: usize,
    ) -> Self {
        let bits = prss
            .generate_chunks_iter::<_, <A as FromRandom>::SourceLength>(index)
            .map(|(l_rand, r_rand)| {
                let l_val = A::from_random(l_rand);
                let r_val = A::from_random(r_rand);
                AdditiveShare::new_arr(l_val, r_val)
            })
            .take(len)
            .collect();
        Self { bits }
    }
}

impl<S> TryFrom<Vec<S>> for BitDecomposed<S> {
    type Error = Error;
    fn try_from(bits: Vec<S>) -> Result<Self, Self::Error> {
        if bits.len() <= Self::MAX {
            Ok(Self { bits })
        } else {
            Err(Error::Internal)
        }
    }
}

impl<S> Deref for BitDecomposed<S> {
    type Target = [S];
    fn deref(&self) -> &Self::Target {
        &self.bits
    }
}

impl<S> DerefMut for BitDecomposed<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bits
    }
}

impl<S> IntoIterator for BitDecomposed<S> {
    type Item = S;
    type IntoIter = <Vec<S> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.bits.into_iter()
    }
}

impl<S: Clone + Send + Sync> ArrayAccessRef for BitDecomposed<S> {
    type Element = S;
    type Ref<'a> = &'a S where S: 'a;
    type Iter<'a> = slice::Iter<'a, S> where S: 'a;

    fn get(&self, index: usize) -> Option<Self::Ref<'_>> {
        self.bits.get(index)
    }

    fn set(&mut self, index: usize, e: Self::Ref<'_>) {
        self.bits[index] = e.clone();
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.bits.iter()
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const MAX_TEST_SIZE: usize = 1024;

    impl<S> Arbitrary for BitDecomposed<S>
    where
        S: Debug,
        Vec<S>: Arbitrary,
    {
        type Parameters = <Vec<S> as Arbitrary>::Parameters;
        type Strategy = prop::strategy::Map<<Vec<S> as Arbitrary>::Strategy, fn(Vec<S>) -> Self>;

        fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
            Vec::<S>::arbitrary_with(args).prop_map(|bits| Self { bits })
        }
    }

    prop_compose! {
        fn val_and_index()
            (vec in prop::collection::vec(any::<u8>(), 2..MAX_TEST_SIZE))
            (index in 0..vec.len(), vec in Just(vec))
        -> (BitDecomposed<u8>, usize) {
            (BitDecomposed { bits: vec }, index)
        }
    }

    proptest! {
        #[test]
        fn arrayaccess_get_set(
            (mut a, ix) in val_and_index(),
            b: u8,
            c: u8,
            d: u8,
        ) {
            prop_assert_eq!(a.get(0), Some(&a.bits[0]));
            a.set(0, &b);
            prop_assert_eq!(a.get(0), Some(&b));
            prop_assert_eq!(a.get(ix), Some(&a.bits[ix]));
            a.set(ix, &c);
            prop_assert_eq!(a.get(ix), Some(&c));
            prop_assert_eq!(a.get(a.len() - 1), Some(&a.bits[a.len() - 1]));
            a.set(a.len() - 1, &d);
            prop_assert_eq!(a.get(a.len() - 1), Some(&d));
            prop_assert_eq!(a.get(a.len()), None);
            let BitDecomposed {
                bits: mut a_mod,
             } = a.clone();
            a_mod[0] = b;
            a_mod[ix] = c;
            a_mod[a.len() - 1] = d;
            prop_assert_eq!(a.bits, a_mod);
        }

        #[test]
        fn arrayaccess_iter(val in any::<BitDecomposed<u8>>()) {
            let mut iter = val.iter().enumerate();
            prop_assert_eq!(iter.len(), val.len());
            while let Some((i, v)) = iter.next() {
                prop_assert_eq!(v, &val.bits[i]);
                prop_assert_eq!(iter.len(), val.len() - 1 - i);
            }
        }
    }
}
