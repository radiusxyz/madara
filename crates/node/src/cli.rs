use crate::commands::{ExtendedRunCmd, SetupCmd};

#[derive(Debug, clap::Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<Subcommand>,

    #[clap(flatten)]
    pub run: ExtendedRunCmd,
    // /// Choose sealing method.
    // #[arg(long, value_enum, ignore_case = true)]
    // pub sealing: Option<Sealing>,
}

// #[derive(Debug, clap::Args)]
// pub struct ExtendedRunCmd {
//     #[clap(flatten)]
//     pub run_cmd: RunCmd,

//     #[clap(long)]
//     pub testnet: Option<Testnet>,

//     #[clap(long)]
//     pub madara_path: Option<PathBuf>,

//     #[clap(long)]
//     pub encrypted_mempool: bool,

//     #[clap(long)]
//     pub using_external_decryptor: bool,

//     #[clap(long)]
//     pub chain_spec_url: Option<String>,

//     #[clap(long)]
//     pub genesis_url: Option<String>,

//     #[clap(long)]
//     pub da_layer: Option<DaLayer>,
// }

#[allow(clippy::large_enum_variant)]
#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    /// Sub-commands concerned with benchmarking.
    #[command(subcommand)]
    Benchmark(frame_benchmarking_cli::BenchmarkCmd),

    /// Build a chain specification.
    BuildSpec(sc_cli::BuildSpecCmd),

    /// Db meta columns information.
    ChainInfo(sc_cli::ChainInfoCmd),

    /// Validate blocks.
    CheckBlock(sc_cli::CheckBlockCmd),

    /// Export blocks.
    ExportBlocks(sc_cli::ExportBlocksCmd),

    /// Export the state of a given block into a chain spec.
    ExportState(sc_cli::ExportStateCmd),

    /// Import blocks.
    ImportBlocks(sc_cli::ImportBlocksCmd),

    /// Key management cli utilities
    #[command(subcommand)]
    Key(sc_cli::KeySubcommand),

    /// Remove the whole chain.
    PurgeChain(sc_cli::PurgeChainCmd),

    /// Revert the chain to a previous state.
    Revert(sc_cli::RevertCmd),

    /// Setup madara node
    Setup(SetupCmd),

    /// Try some command against runtime state.
    #[cfg(feature = "try-runtime")]
    TryRuntime(try_runtime_cli::TryRuntimeCmd),

    /// Try some command against runtime state. Note: `try-runtime` feature must be enabled.
    #[cfg(not(feature = "try-runtime"))]
    TryRuntime,
}
