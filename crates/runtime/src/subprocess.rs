use std::collections::HashMap;
use std::env;
use std::fmt::Debug;
use std::process::ExitStatus;
use std::sync::Arc;

use serde_json;
use sp_core::serde::de::DeserializeOwned;
use sp_core::serde::ser::Serialize;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::{sleep as async_sleep, Duration};

use crate::error::BuilderRuntimeError;
use crate::error_impl::{Error, WrapError};

pub fn run_process<T>() -> Result<(), Error>
where
    T: SubProcess + 'static,
{
    // Validate the number of arguments passed.
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        return Err(Error::from(BuilderRuntimeError::MissingArgument));
    } else if args.len() > 1 {
        return Err(Error::from(BuilderRuntimeError::ArgumentOverflow).with_context("MAX = 1"));
    }

    // Parse argument to a type. Safe to unwrap() because we have checked the argument exists from the
    // above lines.
    let argument_str = args.first().unwrap();

    let argument: T = serde_json::from_str(argument_str)
        .map_err(|error| Error::new(BuilderRuntimeError::DeserializeArgument, error))
        .context(format_args!("{:?}", argument_str))?;

    // Run the function.
    argument.run()?;

    Ok(())
}

pub trait SubProcess: Clone + Debug + DeserializeOwned + Serialize {
    fn run(self) -> Result<(), Error>;
}

pub struct ProcessPool {
    inner: Arc<Mutex<HashMap<String, Process>>>,
    max_process_count: usize,
}

impl Clone for ProcessPool {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), max_process_count: self.max_process_count }
    }
}

impl Default for ProcessPool {
    fn default() -> Self {
        let max_process_count = std::thread::available_parallelism().unwrap().get() - 2;
        Self { inner: Arc::new(Mutex::new(HashMap::default())), max_process_count }
    }
}

impl ProcessPool {
    pub async fn spawn<T>(&self, name: impl AsRef<str>, pid: impl AsRef<str>, argument: T) -> Result<(), Error>
    where
        T: SubProcess,
    {
        let mut inner_lock = self.inner.lock().await;

        // Check if the number of spawned processes exceeds the limit.
        let process_count = inner_lock.len();
        if process_count > self.max_process_count {
            return Err(Error::from(BuilderRuntimeError::MaxProcessReached)
                .with_context(format_args!("MAX = {:?}", process_count)));
        }

        // Check whether the process with the same PID exists.
        if inner_lock.contains_key(pid.as_ref()) {
            return Ok(());
        }

        // Serialize argument to String.
        let argument_string = serde_json::to_string(&argument)
            .map_err(|error| Error::new(BuilderRuntimeError::SerializeArgument, error))
            .context(format_args!("{:?}", argument))?;

        // Set subprocess path.
        let path = env::current_dir()
            .map_err(|error| Error::new(BuilderRuntimeError::GetCurrentDirectory, error))?
            .join("target/release")
            .join(name.as_ref());

        // Spawn a new process.
        let process: Process = Command::new(path)
            .arg(argument_string)
            .spawn()
            .map_err(|error| Error::new(BuilderRuntimeError::SpawnNewProcess, error))?
            .into();

        // Spawn a manager task.
        self.spawn_process_manager(pid.as_ref().to_string(), process.clone());

        // Add the process to the pool.
        inner_lock.insert(pid.as_ref().to_string(), process);

        Ok(())
    }

    pub async fn kill(&self, pid: impl AsRef<str>) -> Result<(), Error> {
        let inner_lock = self.inner.lock().await;

        // Check if a process with a given PID exists.
        let process = inner_lock
            .get(pid.as_ref())
            .ok_or(Error::from(BuilderRuntimeError::DoesNotExist))
            .context(format_args!("PID = {:?}", pid.as_ref()))?;

        // Kill the process.
        process.kill().await?;

        Ok(())
    }

    pub async fn remove(&self, pid: impl AsRef<str>) {
        let mut inner_lock = self.inner.lock().await;

        inner_lock.remove(pid.as_ref());
    }

    fn spawn_process_manager(&self, pid: String, process: Process) {
        let process_pool = self.clone();

        crate::spawn(async move {
            loop {
                match process.try_wait().await {
                    Ok(_exit_status) => {
                        break;
                    }
                    Err(error) => {
                        if error != BuilderRuntimeError::StillRunning {
                            break;
                        }
                    }
                }

                async_sleep(Duration::from_millis(100)).await;
            }

            // Cleanup
            process_pool.remove(pid).await;
        });
    }
}

pub struct Process {
    handle: Arc<Mutex<Child>>,
}

impl Clone for Process {
    fn clone(&self) -> Self {
        Self { handle: self.handle.clone() }
    }
}

impl From<Child> for Process {
    fn from(value: Child) -> Self {
        Self { handle: Arc::new(Mutex::new(value)) }
    }
}

impl Process {
    pub async fn try_wait(&self) -> Result<ExitStatus, Error> {
        let mut handle_lock = self.handle.lock().await;

        let exit_status = handle_lock
            .try_wait()
            .map_err(|error| Error::new(BuilderRuntimeError::WaitForExitStatus, error))?
            .ok_or(Error::from(BuilderRuntimeError::StillRunning))?;

        Ok(exit_status)
    }

    pub async fn kill(&self) -> Result<(), Error> {
        let mut handle_lock = self.handle.lock().await;

        handle_lock.kill().await.map_err(|error| Error::new(BuilderRuntimeError::KillProcess, error))?;

        Ok(())
    }
}
