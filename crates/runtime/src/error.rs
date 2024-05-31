crate::build_error_kind!(
    pub enum BuilderRuntimeError {
        // `context.rs`
        NoneType = "The value returned None",
        Downcast = "Failed to downcast to Type",
        // `subprocess.rs`
        DuplicatePid = "A process with the same PID already exists",
        MissingArgument = "Missing argument for running a subprocess",
        ArgumentOverflow = "The number of argument exceeded the max value",
        DeserializeArgument = "Failed to deserialize the argument",
        SerializeArgument = "Failed to serialize the argument",
        GetCurrentDirectory = "Failed to get the current directory",
        DoesNotExist = "The process does not exist",
        SpawnNewProcess = "Failed to spawn a new process",
        KillProcess = "Failed to kill the process",
        WaitForExitStatus = "Failed to collect the exit status",
        StillRunning = "The process is still running",
        MaxProcessReached = "The number of spawned process reached the maximum value",
        // `thread_pool.rs`
        OffloadWorkload = "Failed to offload work to ThreadPool",
        QueueFull = "Worker queue is full",
    }
);
