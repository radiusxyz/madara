use std::fmt::Debug;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crossbeam::channel::{self, Sender};
use tokio::sync::oneshot;

use crate::error::BuilderRuntimeError;
use crate::error_impl::Error;

type Workload = Box<dyn FnOnce() + Send + 'static>;

/// Represents a pool of worker threads that can execute tasks concurrently.
pub struct ThreadPool {
    workers: Vec<Worker>,
    work_queue: Sender<Workload>,
}

impl ThreadPool {
    /// Constructs a new `ThreadPool` with a specified number of threads and a channel capacity.
    ///
    /// # Arguments
    ///
    /// * `thread_count` - The number of threads in the thread pool.
    /// * `channel_capacity` - The capacity of the channel that holds tasks to be executed.
    pub fn new(thread_count: usize, channel_capacity: usize) -> Self {
        let (sender, receiver) = channel::bounded::<Workload>(channel_capacity);

        let handles: Vec<Worker> = (0..thread_count).map(|_| Worker::new(receiver.clone())).collect();

        Self { workers: handles, work_queue: sender }
    }

    /// Offloads a function to be executed by one of the worker threads.
    ///
    /// # Arguments
    ///
    /// * `function` - The function to be executed by the thread pool.
    ///
    /// # Returns
    ///
    /// A receiver to retrieve the result of the function. The result can be an error if
    /// the work queue is full or disconnected.
    pub fn offload<F, FR>(&self, function: F) -> Result<oneshot::Receiver<FR>, Error>
    where
        F: FnOnce() -> FR + Send + 'static,
        FR: Debug + Send + 'static,
    {
        let (sender, receiver) = oneshot::channel::<FR>();

        let workload = move || {
            let output = function();
            sender.send(output).unwrap();
        };

        match self.work_queue.try_send(Box::new(workload)) {
            Ok(()) => Ok(receiver),
            Err(error) => match error.is_full() {
                true => Err(Error::from(BuilderRuntimeError::QueueFull)),
                false => Err(Error::new(BuilderRuntimeError::OffloadWorkload, error)),
            },
        }
    }

    /// Gracefully shuts down all workers in the thread pool.
    ///
    /// # Panics
    ///
    /// This function may panic if sending a stop signal to the workers fails.
    pub fn stop(&mut self) {
        self.work_queue
            .send_timeout(Box::new(|| {}), Duration::from_millis(0))
            .unwrap_or_else(|error| crate::unrecoverable!(error));

        self.workers.iter_mut().for_each(|worker| worker.stop());
    }
}

/// Represents an individual worker in the `ThreadPool`.
///
/// Each worker runs in its own thread and waits for tasks to execute.
struct Worker(Option<JoinHandle<()>>);

impl Worker {
    /// Creates a new worker that listens to a channel for tasks to execute.
    ///
    /// # Arguments
    ///
    /// * `receiver` - The channel from which the worker will receive tasks.
    ///
    /// # Panics
    ///
    /// This function may panic if receiving a task or joining a thread fails.
    pub fn new(receiver: channel::Receiver<Workload>) -> Self {
        let handle = thread::spawn(move || {
            loop {
                match receiver.recv() {
                    Ok(workload) => workload(),
                    Err(error) => crate::unrecoverable!(error),
                }
            }
        });

        Self(Some(handle))
    }

    /// Stops the worker and joins its thread.
    ///
    /// # Panics
    ///
    /// This function may panic if joining the worker's thread fails.
    pub fn stop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.join().unwrap_or_else(|error| crate::unrecoverable!(error));
        }
    }
}
