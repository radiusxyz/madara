use std::future::Future;

use tokio::runtime::{Builder, Runtime as TokioRuntime};
use tokio::task::JoinHandle;

pub struct AsyncRuntime(TokioRuntime);

impl AsyncRuntime {
    /// Creates a new instance of `AsyncRuntime` with the specified number of worker threads.
    ///
    /// # Arguments
    ///
    /// * `thread_count` - Number of worker threads for the asynchronous runtime.
    ///
    /// # Panics
    ///
    /// This function will panic if the runtime fails to initialize.
    pub fn new(thread_count: usize) -> Self {
        let async_runtime = Builder::new_multi_thread()
            .enable_all()
            .worker_threads(thread_count)
            .build()
            .unwrap_or_else(|error| crate::unrecoverable!(error));

        Self(async_runtime)
    }

    fn inner(&self) -> &TokioRuntime {
        &self.0
    }

    /// Spawns a future onto the `AsyncRuntime`.
    ///
    /// # Arguments
    ///
    /// * `future` - The future to be spawned on the runtime.
    ///
    /// # Returns
    ///
    /// Returns a handle to the spawned future.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner().spawn(future)
    }
}
