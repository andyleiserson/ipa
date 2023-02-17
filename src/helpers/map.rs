use async_trait::async_trait;

/// Trait for transforming values in the manner of `Option::map` or `Iter::map`.
///
/// This is used to implement malicious downgrades.
#[async_trait]
pub trait Map<M: Mapping>: Send {
    type Output;

    async fn map<'a>(self, m: &'a M) -> Self::Output;
}

pub trait Mapping {}

#[async_trait]
impl<T, U, M: Mapping> Map<M> for (T, U)
where
    T: Map<M>,
    U: Map<M>,
{
    type Output = (<T as Map<M>>::Output, <U as Map<M>>::Output);
    async fn map<'a>(self, m: &'a M) -> Self::Output {
        (self.0.map(m).await, self.1.map(m).await)
    }
}

#[async_trait]
impl<T, M: Mapping> Map<M> for Vec<T>
where
    T: Map<M>,
{
    type Output = Vec<<T as Map<M>>::Output>;
    async fn map<'a>(self, m: &'a M) -> Self::Output {
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
    async fn map<'a>(self, m: &'a M) -> Self::Output {
        self.iter().map(|v| <T as Map<M>>::map(v, m)).collect()
    }
}
*/
