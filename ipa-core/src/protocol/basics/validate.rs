use std::{
    convert::Infallible,
    marker::PhantomData,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use futures::{
    future::try_join,
    stream::{Fuse, Stream, StreamExt},
    Future, FutureExt,
};
use generic_array::GenericArray;
use pin_project::pin_project;
use sha2::{
    digest::{typenum::Unsigned, FixedOutput, OutputSizeUser},
    Digest, Sha256,
};

use crate::{
    error::Error,
    ff::Serializable,
    helpers::{Direction, Message},
    protocol::{context::Context, RecordId},
    secret_sharing::{replicated::ReplicatedSecretSharing, SharedValue},
};

type HashFunction = Sha256;
type HashSize = <HashFunction as OutputSizeUser>::OutputSize;
type HashOutputArray = [u8; <HashSize as Unsigned>::USIZE];

#[derive(Debug, Clone, PartialEq, Eq)]
struct HashValue(GenericArray<u8, HashSize>);

impl Serializable for HashValue {
    type Size = HashSize;
    type DeserializationError = Infallible;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(self.0.as_slice())
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        Ok(Self(buf.to_owned()))
    }
}

impl Message for HashValue {}

struct ReplicatedValidatorFinalization<'a, C: 'a> {
    f: Pin<Box<dyn Future<Output = Result<(), Error>> + 'a>>,
    ctx: C,
}

impl<'a, C: Context + 'a> ReplicatedValidatorFinalization<'a, C> {
    fn new(active: ReplicatedValidatorActive<'a, C>) -> Self {
        let ReplicatedValidatorActive {
            ctx,
            left_hash,
            right_hash,
            phantom_data: _,
        } = active;
        // Ugh: The version of sha2 we currently use doesn't use the same GenericArray version as we do.
        let left_hash = HashValue(GenericArray::from(<HashOutputArray>::from(
            left_hash.finalize_fixed(),
        )));
        let right_hash = HashValue(GenericArray::from(<HashOutputArray>::from(
            right_hash.finalize_fixed(),
        )));
        let left_peer = ctx.role().peer(Direction::Left);
        let right_peer = ctx.role().peer(Direction::Left);
        let ctx_clone = ctx.clone();

        let f = Box::pin(async move {
            let ctx_ref = &ctx_clone;
            try_join(
                ctx_ref
                    .send_channel(left_peer)
                    .send(RecordId::FIRST, left_hash.clone()),
                ctx_ref
                    .send_channel(right_peer)
                    .send(RecordId::FIRST, right_hash.clone()),
            )
            .await?;
            let (left_recvd, right_recvd) = try_join(
                ctx_ref.recv_channel(left_peer).receive(RecordId::FIRST),
                ctx_ref.recv_channel(right_peer).receive(RecordId::FIRST),
            )
            .await?;
            if left_hash == left_recvd && right_hash == right_recvd {
                Ok(())
            } else {
                Err(Error::Internal) // TODO add a code
            }
        });
        Self { f, ctx }
    }

    fn poll(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        self.f.poll_unpin(cx)
    }
}

struct ReplicatedValidatorActive<'a, C> {
    ctx: C,
    left_hash: Sha256,
    right_hash: Sha256,
    phantom_data: PhantomData<&'a ()>,
}

impl<'a, C: Context + 'a> ReplicatedValidatorActive<'a, C> {
    fn new(ctx: C) -> Self {
        Self {
            ctx,
            left_hash: HashFunction::new(),
            right_hash: HashFunction::new(),
            phantom_data: PhantomData,
        }
    }

    fn update<S, V>(&mut self, s: &S)
    where
        S: ReplicatedSecretSharing<V>,
        V: SharedValue,
    {
        let mut buf = GenericArray::default(); // ::<u8, <V as Serializable>::Size>
        s.left().serialize(&mut buf);
        self.left_hash.update(buf.as_slice());
        s.right().serialize(&mut buf);
        self.right_hash.update(buf.as_slice());
    }

    fn finalize(self) -> ReplicatedValidatorFinalization<'a, C> {
        ReplicatedValidatorFinalization::new(self)
    }
}

enum ReplicatedValidatorState<'a, C: 'a> {
    /// While the validator is waiting, it holds a context reference.
    Pending(Option<ReplicatedValidatorActive<'a, C>>),
    /// After the validator has taken all of its inputs, it holds a future.
    Finalizing(ReplicatedValidatorFinalization<'a, C>),
}

impl<'a, C: Context + 'a> ReplicatedValidatorState<'a, C> {
    /// # Panics
    /// This panics if it is called after `finalize()`.
    fn update<S, V>(&mut self, s: &S)
    where
        S: ReplicatedSecretSharing<V>,
        V: SharedValue,
    {
        if let Self::Pending(Some(a)) = self {
            a.update(s);
        } else {
            panic!();
        }
    }

    fn poll(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Error>> {
        match self {
            Self::Pending(ref mut active) => {
                let mut f = active.take().unwrap().finalize();
                let res = f.poll(cx);
                *self = ReplicatedValidatorState::Finalizing(f);
                res
            }
            Self::Finalizing(f) => f.poll(cx),
        }
    }
}

#[pin_project]
struct ReplicatedValidator<'a, C: 'a, T: Stream, S, V> {
    #[pin]
    input: Fuse<T>,
    state: ReplicatedValidatorState<'a, C>,
    _marker: PhantomData<(S, V)>,
}

impl<'a, C: Context + 'a, T: Stream, S, V> ReplicatedValidator<'a, C, T, S, V> {
    pub fn new(ctx: C, s: T) -> Self {
        Self {
            input: s.fuse(),
            state: ReplicatedValidatorState::Pending(Some(ReplicatedValidatorActive::new(ctx))),
            _marker: PhantomData,
        }
    }
}

impl<'a, C, T, S, V> Stream for ReplicatedValidator<'a, C, T, S, V>
where
    C: Context + 'a,
    T: Stream<Item = Result<S, Error>>,
    S: ReplicatedSecretSharing<V>,
    V: SharedValue,
{
    type Item = Result<S, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        match this.input.poll_next(cx) {
            Poll::Ready(Some(v)) => match v {
                Ok(v) => {
                    this.state.update(&v);
                    Poll::Ready(Some(Ok(v)))
                }
                Err(e) => Poll::Ready(Some(Err(e))),
            },
            Poll::Ready(None) => match this.state.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => Poll::Ready(None),
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.input.size_hint()
    }
}
