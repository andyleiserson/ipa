use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{
    ff::Field,
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        SharedValue,
    },
};

/// Trait for random generation from random u128s.
///
/// It was previously assumed that our fields were of order << 2^128, in which case
/// `Field::truncate_from` can be used for this purpose. This trait makes the contract explicit.
pub trait FromRandom {
    type Source;

    fn len() -> usize;

    /// Generate a random value of `Self` from a uniformly-distributed random u128.
    fn from_random(src: Self::Source) -> Self;
}

/// Trait for things that can be generated by PRSS.
///
/// The exact semantics of the generation depend on the value being generated, but like
/// `rand::distributions::Standard`, a uniform distribution is typical. When implementing
/// this trait, consider the consequences if the implementation were to be used in
/// an unexpected way. For example, an implementation that draws from a subset of the
/// possible values could be dangerous, if used in an unexpected context where
/// security relies on sampling from the full space.
///
/// At a high level, there are two kinds of PRSS generation:
///  1. Raw values: In this case, two values are generated, one using the randomness that is shared
///     with the left helper, and one with the randomness that is shared with the right helper.
///     Thus, one of the generated values is known to both us and the left helper, and likewise for
///     the right helper.
///  2. Secret sharings: In this case, a single secret-shared random value is generated. The value
///     returned by `FromPrss` is our share of that sharing. Within `FromPrss`, the randomness shared
///     with the left and right helpers is used to construct the sharing.
///
/// In the first case, `FromPrss` is implemented for a tuple type, while in the second case,
/// `FromPrss` is implemented for a secret-shared type.
pub trait FromPrss: Sized {
    fn from_prss<P: SharedRandomness + ?Sized, I: Into<u128>>(prss: &P, index: I) -> Self;
}

/// Generate two random values, one that is known to the left helper
/// and one that is known to the right helper.
impl<T: FromRandom<Source = [u128; N]>, const N: usize> FromPrss for (T, T)
where
    [u128; N]: Default,
{
    fn from_prss<P: SharedRandomness + ?Sized, I: Into<u128>>(prss: &P, index: I) -> (T, T) {
        let (l, r): (Vec<_>, Vec<_>) = (0..<T as FromRandom>::len().try_into().unwrap())
            .map(|i| prss.generate_values::<u128>(index.into() * u128::try_from(<T as FromRandom>::len()).unwrap() + i))
            .unzip();
        (T::from_random(l.try_into().unwrap()), T::from_random(r.try_into().unwrap()))
    }
}

/// Generate a replicated secret sharing of a random value, which none
/// of the helpers knows. This is an implementation of the functionality 2.1 `F_rand`
/// described on page 5 of the paper:
/// "Efficient Bit-Decomposition and Modulus Conversion Protocols with an Honest Majority"
/// by Ryo Kikuchi, Dai Ikarashi, Takahiro Matsuda, Koki Hamada, and Koji Chida
/// <https://eprint.iacr.org/2018/387.pdf>
impl<T> FromPrss for Replicated<T>
where
    T: SharedValue,
    (T, T): FromPrss,
{
    fn from_prss<P: SharedRandomness + ?Sized, I: Into<u128>>(prss: &P, index: I) -> Replicated<T> {
        let (l, r) = FromPrss::from_prss(prss, index);
        Replicated::new(l, r)
    }
}

pub trait SharedRandomness {
    /// Generate two random values, one that is known to the left helper
    /// and one that is known to the right helper.
    #[must_use]
    fn generate_values<I: Into<u128>>(&self, index: I) -> (u128, u128);

    /// Generate two random field values, one that is known to the left helper
    /// and one that is known to the right helper.
    ///
    /// This alias is provided for compatibility with existing code. New code can just use
    /// `generate`.
    #[must_use]
    fn generate_fields<F: Field, I: Into<u128>>(&self, index: I) -> (F, F) {
        self.generate(index)
    }

    /// Generate something that implements the `FromPrss` trait.
    ///
    /// Generation by `FromPrss` is described in more detail in the `FromPrss` documentation.
    #[must_use]
    fn generate<T: FromPrss, I: Into<u128>>(&self, index: I) -> T {
        T::from_prss(self, index)
    }

    /// Generate a non-replicated additive secret sharing of zero.
    ///
    /// This is used for the MAC accumulators for malicious security.
    //
    // Equivalent functionality could be obtained by defining an `Unreplicated<F>` type that
    // implements `FromPrss`.
    #[must_use]
    fn zero<V: SharedValue + FromRandom<Source = [u128; 1]>, I: Into<u128>>(&self, index: I) -> V {
        let (l, r): (V, V) = self.generate(index);
        l - r
    }
}

// The key exchange component of a participant.
pub struct KeyExchange {
    sk: EphemeralSecret,
}

impl KeyExchange {
    pub fn new<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        Self {
            sk: EphemeralSecret::random_from_rng(r),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.sk)
    }

    #[must_use]
    pub fn key_exchange(self, pk: &PublicKey) -> GeneratorFactory {
        debug_assert_ne!(pk, &self.public_key(), "self key exchange detected");
        let secret = self.sk.diffie_hellman(pk);
        let kdf = Hkdf::<Sha256>::new(None, secret.as_bytes());
        GeneratorFactory { kdf }
    }
}

/// This intermediate object exists so that multiple generators can be constructed,
/// with each one dedicated to one purpose.
pub struct GeneratorFactory {
    kdf: Hkdf<Sha256>,
}

impl GeneratorFactory {
    /// Create a new generator using the provided context string.
    #[allow(clippy::missing_panics_doc)] // Panic should be impossible.
    #[must_use]
    pub fn generator(&self, context: &[u8]) -> Generator {
        let mut k = GenericArray::default();
        self.kdf.expand(context, &mut k).unwrap();
        Generator {
            cipher: Aes256::new(&k),
        }
    }
}

/// The basic generator.  This generates values based on an arbitrary index.
#[derive(Debug, Clone)]
pub struct Generator {
    cipher: Aes256,
}

impl Generator {
    /// Generate the value at the given index.
    /// This uses the MMO^{\pi} function described in <https://eprint.iacr.org/2019/074>.
    #[must_use]
    pub fn generate(&self, index: u128) -> u128 {
        let mut buf = index.to_le_bytes();
        self.cipher
            .encrypt_block(GenericArray::from_mut_slice(&mut buf));

        u128::from_le_bytes(buf) ^ index
    }
}
