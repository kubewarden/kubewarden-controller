//! Ownership of a spawned task.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::task::{JoinError, JoinHandle};

/// A spawned task, owned so that it stops when this value drops before it resolves.
///
/// A bare `JoinHandle` detaches its task on drop: the task keeps running on its own,
/// unseen. `AbortOnDrop` aborts the task instead. Awaiting it yields the task's result,
/// the same as awaiting the `JoinHandle` it wraps.
pub(crate) struct AbortOnDrop<T>(Option<JoinHandle<T>>);

impl<T> AbortOnDrop<T> {
    pub(crate) fn new(handle: JoinHandle<T>) -> Self {
        Self(Some(handle))
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, JoinError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let handle = this
            .0
            .as_mut()
            .expect("AbortOnDrop polled again after it resolved");

        match Pin::new(handle).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                // The task ended on its own. There is nothing left to abort.
                this.0 = None;
                Poll::Ready(result)
            }
        }
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use super::*;

    /// A task that finishes quickly on its own, and a flag that tells whether it ran to
    /// completion. The test aborts the task well before that, so the flag must stay
    /// `false`; an abort that silently does nothing would otherwise show up as `true`
    /// once the test waits long enough.
    fn short_lived_task() -> (AbortOnDrop<()>, Arc<AtomicBool>) {
        let completed = Arc::new(AtomicBool::new(false));
        let completed_in_task = completed.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            completed_in_task.store(true, Ordering::SeqCst);
        });

        (AbortOnDrop::new(handle), completed)
    }

    #[tokio::test]
    async fn test_abort_on_drop_aborts_the_task_when_dropped() {
        let (task, completed) = short_lived_task();

        drop(task);
        // Longer than the task needs to complete on its own, so a missing abort shows up.
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(
            !completed.load(Ordering::SeqCst),
            "the task completed, so it was not aborted"
        );
    }

    #[tokio::test]
    async fn test_abort_on_drop_aborts_the_task_when_its_wait_is_cancelled() {
        let (task, completed) = short_lived_task();

        // Polls the task once, then drops it while it is still pending, the way `run`
        // drops the certificate watch when one of the servers fails first.
        let _ = tokio::time::timeout(Duration::from_millis(5), task).await;
        // Longer than the task needs to complete on its own, so a missing abort shows up.
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(
            !completed.load(Ordering::SeqCst),
            "the task completed, so it was not aborted"
        );
    }

    #[tokio::test]
    async fn test_abort_on_drop_yields_the_task_result() {
        let handle = tokio::spawn(async { "the task's result" });
        let task = AbortOnDrop::new(handle);

        let result = task.await;

        assert_eq!(result.unwrap(), "the task's result");
    }
}
