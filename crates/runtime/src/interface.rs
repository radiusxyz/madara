use std::future::Future;
use std::mem::MaybeUninit;
use std::sync::Once;
use std::{fmt, thread};

use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::async_runtime::AsyncRuntime;
use crate::context::Context;
use crate::error_impl::Error;
use crate::subprocess::{ProcessPool, SubProcess};
use crate::thread_pool::ThreadPool;

static mut TOKIORUNTIME: MaybeUninit<TokioRuntime> = MaybeUninit::uninit();
static INIT: Once = Once::new();

/// Spawns a Future into the tokio async executor.
///
/// # Panics
///
/// The function panics if [Runtime] instance has not been initialized.
/// A user must provide the guarantee that [Runtime] is properly initialized
/// before calling the function or any other function that wraps this function.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
///
/// use tokio::time::sleep;
///
/// let handle = runtime::spawn(async {
///     sleep(Duration::from_secs(3)).await;
///     println!("Finished after 3 seconds");
/// });
/// handle.await;
/// ```
pub fn spawn<F>(func: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    runtime().async_runtime().spawn(func)
}

pub async fn spawn_process<T>(name: impl AsRef<str>, pid: impl AsRef<str>, argument: T) -> Result<(), Error>
where
    T: SubProcess,
{
    runtime().process_pool().spawn(name, pid, argument).await
}

pub async fn kill_process(pid: impl AsRef<str>) -> Result<(), Error> {
    runtime().process_pool().kill(pid).await
}

pub async fn try_wait_kill_process(pid: impl AsRef<str>) -> Result<(), Error> {
    if runtime().process_pool().kill(pid.as_ref()).await.is_err() {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        runtime().process_pool().kill(pid.as_ref()).await?
    }

    Ok(())
}

/// Used in an async block to offload CPU-bound tasks to prevent the async
/// executors from blocking.
///
/// # Panics
///
/// The function panics if [Runtime] instance has not been initialized.
/// A user must provide the guarantee that [Runtime] is properly initialized
/// before calling the function or any other function that wraps this function.
///
/// # Examples
///
/// ```rust
/// runtime::spawn(async move {
///     let receiver = runtime::offload(|| (0..1_000_000_000).for_each(|_| {}))
///         .map_err(|e| tracing::error!("{}", e))
///         .unwrap();
///     receiver.await.unwrap();
/// });
/// ```
pub fn offload<F, FR>(func: F) -> Result<oneshot::Receiver<FR>, Error>
where
    F: FnOnce() -> FR + Send + 'static,
    FR: fmt::Debug + Send + 'static,
{
    runtime().thread_pool().offload(func)
}

/// Returns an atomic reference counting pointer to the globally shared context.
///
/// # Panics
///
/// The function panics if [Runtime] instance has not been initialized.
/// A user must provide the guarantee that [Runtime] is properly initialized
/// before calling the function or any other function that wraps this function.
pub fn context() -> Context {
    runtime().context()
}

/// Returns a shared reference to [Runtime] struct.
///
/// # Panics
///
/// The function panics when called without initializing [Runtime].
///
/// # Safety
///
/// It is safe to return a shared reference to [Runtime] as long as the struct
/// has been successfully initialized.
pub(crate) fn runtime() -> &'static TokioRuntime {
    if INIT.is_completed() {
        unsafe { TOKIORUNTIME.assume_init_ref() }
    } else {
        panic!("Runtime has not been initialized");
    }
}

/// Configuration for creating a `Runtime`.
///
/// # Examples
///
/// ```rust
/// use runtime::Runtime;
///
/// let runtime = Runtime::builder()
///     .async_thread(4)
///     .worker_thread(8)
///     .work_queue_capacity(16)
///     .add_context("config_key", "config_value".to_string()).unwrap()
///     // Assume MyRpcParam implements RpcParameter
///     //.register_rpc_method::<MyRpcParam>().unwrap()
///     .rpc_endpoint("127.0.0.1:8088".to_string())
///     .init();
/// ```
pub struct Builder {
    async_thread_count: usize,
    process_count: usize,
    worker_thread_count: usize,
    work_queue_capacity: usize,
    context: Context,
    rpc_endpoint: String,
}

impl Default for Builder {
    fn default() -> Self {
        let process_count = thread::available_parallelism().unwrap().get() - 2;
        Self {
            async_thread_count: 1,
            process_count,
            worker_thread_count: 1,
            work_queue_capacity: 4,
            context: Context::default(),
            rpc_endpoint: String::from("127.0.0.1:8080"),
        }
    }
}

impl Builder {
    // Methods for the Builder struct
    // For each method, use the template to add appropriate documentation.

    /// Sets the number of async threads for the `Runtime`.
    ///
    /// # Arguments
    ///
    /// * `thread_count` - The number of async threads.
    pub fn set_async_thread(mut self, thread_count: usize) -> Self {
        self.async_thread_count = thread_count;
        self
    }

    pub fn set_process_count(mut self, process_count: usize) -> Self {
        self.process_count = process_count;
        self
    }

    /// Sets the number of worker threads for the `Runtime`.
    ///
    /// # Arguments
    ///
    /// * `thread_count` - The number of worker threads.
    pub fn set_worker_thread(mut self, thread_count: usize) -> Self {
        self.worker_thread_count = thread_count;
        self
    }

    pub fn set_work_queue_capacity(mut self, capacity: usize) -> Self {
        self.work_queue_capacity = capacity;
        self
    }

    /// Adds context data to the `Builder`.
    ///
    /// # Arguments
    ///
    /// * `key` - A key under which the context data will be stored.
    /// * `data` - The context data to be stored.
    pub fn add_context<V>(self, key: &'static str, data: V) -> Self
    where
        V: Clone + Send + Sync + 'static,
    {
        self.context.store_blocking(key, data);
        self
    }

    /// Sets the RPC endpoint for the `Builder`.
    ///
    /// # Arguments
    ///
    /// * `address` - The RPC endpoint address.
    pub fn set_rpc_endpoint(mut self, address: String) -> Self {
        self.rpc_endpoint = address;
        self
    }

    /// Initializes the `Runtime` using the current configuration of the `Builder`.
    ///
    /// This method sets up the asynchronous runtime, worker threads, and other configurations.
    ///
    /// # Panics
    ///
    /// This function may panic if the `Runtime` initialization fails or if the RPC server fails to
    /// build or join.
    pub fn init(self) {
        TokioRuntime::init(self.async_thread_count, self.worker_thread_count, self.work_queue_capacity, self.context);
    }
}

/// Represents the main execution context for asynchronous tasks.
pub struct TokioRuntime {
    async_runtime: AsyncRuntime,
    process_pool: ProcessPool,
    thread_pool: ThreadPool,
    context: Context,
}

impl Drop for TokioRuntime {
    fn drop(&mut self) {
        self.thread_pool.stop();
    }
}

impl TokioRuntime {
    /// Returns a default builder for configuring and initializing a `Runtime`.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Initializes the global `Runtime` instance with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `async_thread_count` - The number of async threads.
    /// * `worker_thread_count` - The number of worker threads.
    /// * `work_queue_capacity` - Capacity of the work queue.
    /// * `context` - The shared context.
    pub(crate) fn init(
        async_thread_count: usize,
        worker_thread_count: usize,
        work_queue_capacity: usize,
        context: Context,
    ) {
        let thread_count = thread::available_parallelism().unwrap().get();
        if (async_thread_count + worker_thread_count) > thread_count {
            crate::unrecoverable!("Thread count out of bound")
        }

        unsafe {
            INIT.call_once(|| {
                let runtime = Self {
                    async_runtime: AsyncRuntime::new(async_thread_count),
                    process_pool: ProcessPool::default(),
                    thread_pool: ThreadPool::new(worker_thread_count, work_queue_capacity),
                    context,
                };
                TOKIORUNTIME.write(runtime);
            });
        }
    }

    pub(crate) fn async_runtime(&self) -> &AsyncRuntime {
        &self.async_runtime
    }

    pub(crate) fn process_pool(&self) -> ProcessPool {
        self.process_pool.clone()
    }

    pub(crate) fn thread_pool(&self) -> &ThreadPool {
        &self.thread_pool
    }

    pub(crate) fn context(&self) -> Context {
        self.context.clone()
    }
}
