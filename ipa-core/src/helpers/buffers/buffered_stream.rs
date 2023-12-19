use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    task::{Context, Poll},
};

use futures::Stream;
use pin_project::pin_project;

/// Stream adapter that buffers in multiples of the active work unit.
///
/// The `BufferedStream` stream adapter returns items from the inner stream unchanged, but
/// stores items in a buffer before returning them, and always releases items in multiples
/// of the configured capacity.
///
/// Unlike `futures::stream::Buffered`, `BufferedStream` operates on a stream of items, not a
/// stream of futures.
#[pin_project]
pub struct BufferedStream<S: Stream<Item = T>, T> {
    #[pin]
    inner: S,
    buffer: VecDeque<T>,
    completed: bool,
    capacity: NonZeroUsize,
    fill_count: usize,
    drain_count: usize,
}

impl<S: Stream<Item = T>, T> BufferedStream<S, T> {
    pub fn new(inner: S, capacity: NonZeroUsize) -> Self {
        Self {
            inner,
            buffer: VecDeque::with_capacity(capacity.get()),
            completed: false,
            capacity,
            fill_count: 0,
            drain_count: 0,
        }
    }
}

impl<S: Stream<Item = T>, T> Stream for BufferedStream<S, T> {
    type Item = T;

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let mut out_item = None;
        debug_assert_eq!(*this.fill_count + *this.drain_count, this.buffer.len());
        loop {
            if out_item.is_none() && *this.drain_count > 0 {
                out_item = this.buffer.pop_front();
                *this.drain_count -= 1;
            }
            if *this.completed || this.buffer.len() == this.capacity.get() {
                break;
            }
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(in_item)) => {
                    this.buffer.push_back(in_item);
                    *this.fill_count += 1;
                    if *this.fill_count >= this.capacity.get() {
                        *this.fill_count -= this.capacity.get();
                        *this.drain_count += this.capacity.get();
                    }
                }
                Poll::Ready(None) => {
                    *this.completed = true;
                    *this.drain_count += *this.fill_count;
                    *this.fill_count = 0;
                    // Note that `out_item` can be `None` here even with a non-empty buffer, if the
                    // buffer did not originally satisfy the drain criterion. In that case we need
                    // to loop again to populate `out_item`.
                }
                Poll::Pending => {
                    break;
                }
            }
        }
        match out_item {
            Some(item) => Poll::Ready(Some(item)),
            None if *this.completed && this.buffer.is_empty() => Poll::Ready(None),
            _ => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{ptr::null, task::Waker};

    use futures_util::StreamExt;
    use tokio::sync::mpsc::{channel, error::TrySendError};
    use tokio_stream::wrappers::ReceiverStream;

    use super::*;

    fn fake_waker() -> Waker {
        use std::task::{RawWaker, RawWakerVTable};
        const fn fake_raw_waker() -> RawWaker {
            const TABLE: RawWakerVTable =
                RawWakerVTable::new(|_| fake_raw_waker(), |_| {}, |_| {}, |_| {});
            RawWaker::new(null(), &TABLE)
        }
        unsafe { Waker::from_raw(fake_raw_waker()) }
    }

    #[tokio::test]
    async fn basic_operation() {
        let (tx, rx) = channel(5);

        let mut buf_stream =
            BufferedStream::new(ReceiverStream::new(rx), NonZeroUsize::new(5).unwrap());

        let waker = fake_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Pending);
        tx.send(0).await.unwrap();
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Pending);
        tx.send(1).await.unwrap();
        tx.send(2).await.unwrap();
        tx.send(3).await.unwrap();
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Pending);
        tx.send(4).await.unwrap();
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(0)));
        tx.send(5).await.unwrap();
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(1)));
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(2)));
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(3)));
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(4)));
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Pending);
        drop(tx);
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(5)));
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(None));
    }

    #[tokio::test]
    async fn fills_buffer_eagerly() {
        // Sized one larger than buffer, so the channel contents can contain a full buffer plus an
        // item to return from polling.
        let (tx, rx) = channel(11);

        let mut buf_stream =
            BufferedStream::new(ReceiverStream::new(rx), NonZeroUsize::new(10).unwrap());

        let waker = fake_waker();
        let mut cx = Context::from_waker(&waker);
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Pending);
        for i in 0..11 {
            tx.send(i).await.unwrap();
        }
        // Channel is now full
        assert_eq!(tx.try_send(11), Err(TrySendError::Full(11)));
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(0)));
        // Polling once should transfer everything from the channel to the buffer,
        // so we should be able to put 11 more in the channel.
        for i in 11..21 {
            assert_eq!(tx.try_send(i), Ok(()));
        }
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(1)));
        // Polling with a full buffer should keep the buffer full, if possible.
        // 2 consumed, 10 buffered in DUT, 9 buffered in bench.
        assert_eq!(tx.try_send(21), Ok(()));
        assert_eq!(tx.try_send(22), Ok(()));
        assert_eq!(tx.try_send(23), Err(TrySendError::Full(23)));
        for i in 2..20 {
            assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(i)));
        }
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Pending);
        drop(tx);
        for i in 20..23 {
            assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(Some(i)));
        }
        assert_eq!(buf_stream.poll_next_unpin(&mut cx), Poll::Ready(None));
    }
}
