use futures_util::future::join;

use async_trait::async_trait;

use crate::{protocol::{Substep, BitOpStep}, error::Error};

/// Trait for transforming values in the manner of `Option::map` or `Iter::map`.
///
/// This is used to implement malicious downgrades.
#[async_trait]
pub trait Map<M: Mapping>: Send {
    type Output: Send;

    async fn map(self, m: M) -> Result<Self::Output, Error>;
}

pub trait Mapping: Clone + Send {
    #[must_use]
    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        self.clone()
    }
}

#[async_trait]
impl<T, U, M: Mapping> Map<M> for (T, U)
where
    T: Map<M>,
    U: Map<M>,
{
    type Output = (<T as Map<M>>::Output, <U as Map<M>>::Output);
    async fn map(self, m: M) -> Result<Self::Output, Error> {
        let m0 = m.narrow(&BitOpStep::from(0));
        let m1 = m.narrow(&BitOpStep::from(1));
        let (first, second) = join(
            self.0.map(m0),
            self.1.map(m1),
        ).await;
        Ok((first?, second?))
    }
}

#[async_trait]
impl<T, M: Mapping> Map<M> for Vec<T>
where
    T: Map<M>,
{
    type Output = Vec<<T as Map<M>>::Output>;
    async fn map(self, m: M) -> Result<Self::Output, Error> {
        self.as_slice().map(m)
    }
}

/*
#[async_trait]
impl<T, M: Mapping> Map<M> for &[T]
where
    T: Map<M>,
{
    type Output = Vec<<T as Map<M>>::Output>;
    async fn map(self, m: M) -> Self::Output {
        self.iter().map(|v| <T as Map<M>>::map(v, m)).collect()
    }
}
*/
