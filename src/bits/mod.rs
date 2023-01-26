use crate::secret_sharing::BooleanShare;
use std::io;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Index, Not};

mod bit_array;

pub use bit_array::BitArray40;

/// Trait for data types storing arbitrary number of bits.
// TODO: Implement `Message`
pub trait BitArray:
    BooleanShare + TryFrom<u128> + Into<u128> + Index<usize, Output = bool> + Index<u32, Output = bool>
{
    /// Truncates the higher-order bits larger than `Self::BITS`, and converts
    /// into this data type. This conversion is lossy. Callers are encouraged
    /// to use `try_from` if the input is not known in advance.
    fn truncate_from<T: Into<u128>>(v: T) -> Self;

    fn as_u128(self) -> u128 {
        <Self as Into<u128>>::into(self)
    }
}

pub trait BooleanOps:
    BitAnd<Output = Self>
    + BitAndAssign
    + BitOr<Output = Self>
    + BitOrAssign
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + Sized
{
}

impl<T> BooleanOps for T where
    T: BitAnd<Output = Self>
        + BitAndAssign
        + BitOr<Output = Self>
        + BitOrAssign
        + BitXor<Output = Self>
        + BitXorAssign
        + Not<Output = Self>
        + Sized
{
}

pub trait BooleanRefOps:
    for<'a> BitXor<&'a Self, Output = Self> + for<'a> BitXorAssign<&'a Self>
{
}

impl<T> BooleanRefOps for T where
    T: for<'a> BitXor<&'a Self, Output = Self> + for<'a> BitXorAssign<&'a Self>
{
}

/// Trait for items that have fixed-byte length representation.
pub trait Serializable: Sized {
    /// Required number of bytes to store this message on disk/network
    const SIZE_IN_BYTES: usize;

    /// Serialize this message to a mutable slice. Implementations need to ensure `buf` has enough
    /// capacity to store this message.
    ///
    /// ## Errors
    /// Returns an error if `buf` does not have enough capacity to store at least `SIZE_IN_BYTES` more
    /// data.
    fn serialize(self, buf: &mut [u8]) -> io::Result<()>;

    /// Deserialize message from a sequence of bytes.
    ///
    /// ## Errors
    /// Returns an error if the provided buffer does not have enough bytes to read (EOF).
    fn deserialize(buf: &[u8]) -> io::Result<Self>;
}
