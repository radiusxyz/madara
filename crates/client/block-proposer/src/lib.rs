// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! A consensus proposer for "basic" chains which use the primitive inherent-data.

// FIXME #1021 move this into sp-consensus

use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::time;
use std::time::{Duration, UNIX_EPOCH};

use codec::Encode;
use futures::channel::oneshot;
use futures::future::{Future, FutureExt};
use futures::{future, select};
use log::{debug, error, info, trace, warn};
use mc_rpc::submit_extrinsic_with_order;
use mc_transaction_pool::decryptor::Decryptor;
use mc_transaction_pool::EncryptedTransactionPool;
use mp_transactions::{InvokeTransaction, UserTransaction};
use pallet_starknet_runtime_api::{ConvertTransactionRuntimeApi, StarknetRuntimeApi};
use prometheus_endpoint::Registry as PrometheusRegistry;
use sc_block_builder::{BlockBuilderApi, BlockBuilderProvider};
use sc_client_api::backend;
use sc_proposer_metrics::{EndProposingReason, MetricsLink as PrometheusMetrics};
use sc_telemetry::{telemetry, TelemetryHandle, CONSENSUS_INFO};
use sc_transaction_pool_api::InPoolTransaction;
use sp_api::{ApiExt, ProvideRuntimeApi};
use sp_blockchain::ApplyExtrinsicFailed::Validity;
use sp_blockchain::Error::ApplyExtrinsicFailed;
use sp_blockchain::HeaderBackend;
use sp_consensus::{DisableProofRecording, EnableProofRecording, ProofRecording, Proposal};
use sp_core::traits::SpawnNamed;
use sp_inherents::InherentData;
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT};
use sp_runtime::{Digest, Percent, SaturatedConversion};

/// Default block size limit in bytes used by [`Proposer`].
///
/// Can be overwritten by [`ProposerFactory::set_default_block_size_limit`].
///
/// Be aware that there is also an upper packet size on what the networking code
/// will accept. If the block doesn't fit in such a package, it can not be
/// transferred to other nodes.
pub const DEFAULT_BLOCK_SIZE_LIMIT: usize = 4 * 1024 * 1024 + 512;

const DEFAULT_SOFT_DEADLINE_PERCENT: Percent = Percent::from_percent(50);

const LOG_TARGET: &str = "basic-authorship";

/// [`Proposer`] factory.
pub struct ProposerFactory<A, B, C, PR> {
    spawn_handle: Box<dyn SpawnNamed>,
    /// The client instance.
    client: Arc<C>,
    /// The transaction pool.
    transaction_pool: Arc<A>,
    /// Prometheus Link,
    metrics: PrometheusMetrics,
    /// The default block size limit.
    ///
    /// If no `block_size_limit` is passed to [`sp_consensus::Proposer::propose`], this block size
    /// limit will be used.
    default_block_size_limit: usize,
    /// Soft deadline percentage of hard deadline.
    ///
    /// The value is used to compute soft deadline during block production.
    /// The soft deadline indicates where we should stop attempting to add transactions
    /// to the block, which exhaust resources. After soft deadline is reached,
    /// we switch to a fixed-amount mode, in which after we see `MAX_SKIPPED_TRANSACTIONS`
    /// transactions which exhaust resources, we will conclude that the block is full.
    soft_deadline_percent: Percent,
    telemetry: Option<TelemetryHandle>,
    /// When estimating the block size, should the proof be included?
    include_proof_in_block_size_estimation: bool,
    /// phantom member to pin the `Backend`/`ProofRecording` type.
    _phantom: PhantomData<(B, PR)>,
}

impl<A, B, C> ProposerFactory<A, B, C, DisableProofRecording> {
    /// Create a new proposer factory.
    ///
    /// Proof recording will be disabled when using proposers built by this instance to build
    /// blocks.
    pub fn new(
        spawn_handle: impl SpawnNamed + 'static,
        client: Arc<C>,
        transaction_pool: Arc<A>,
        prometheus: Option<&PrometheusRegistry>,
        telemetry: Option<TelemetryHandle>,
    ) -> Self {
        ProposerFactory {
            spawn_handle: Box::new(spawn_handle),
            transaction_pool,
            metrics: PrometheusMetrics::new(prometheus),
            default_block_size_limit: DEFAULT_BLOCK_SIZE_LIMIT,
            soft_deadline_percent: DEFAULT_SOFT_DEADLINE_PERCENT,
            telemetry,
            client,
            include_proof_in_block_size_estimation: false,
            _phantom: PhantomData,
        }
    }
}

impl<A, B, C> ProposerFactory<A, B, C, EnableProofRecording> {
    /// Create a new proposer factory with proof recording enabled.
    ///
    /// Each proposer created by this instance will record a proof while building a block.
    ///
    /// This will also include the proof into the estimation of the block size. This can be disabled
    /// by calling [`ProposerFactory::disable_proof_in_block_size_estimation`].
    pub fn with_proof_recording(
        spawn_handle: impl SpawnNamed + 'static,
        client: Arc<C>,
        transaction_pool: Arc<A>,
        prometheus: Option<&PrometheusRegistry>,
        telemetry: Option<TelemetryHandle>,
    ) -> Self {
        ProposerFactory {
            client,
            spawn_handle: Box::new(spawn_handle),
            transaction_pool,
            metrics: PrometheusMetrics::new(prometheus),
            default_block_size_limit: DEFAULT_BLOCK_SIZE_LIMIT,
            soft_deadline_percent: DEFAULT_SOFT_DEADLINE_PERCENT,
            telemetry,
            include_proof_in_block_size_estimation: true,
            _phantom: PhantomData,
        }
    }

    /// Disable the proof inclusion when estimating the block size.
    pub fn disable_proof_in_block_size_estimation(&mut self) {
        self.include_proof_in_block_size_estimation = false;
    }
}

impl<A, B, C, PR> ProposerFactory<A, B, C, PR> {
    /// Set the default block size limit in bytes.
    ///
    /// The default value for the block size limit is:
    /// [`DEFAULT_BLOCK_SIZE_LIMIT`].
    ///
    /// If there is no block size limit passed to [`sp_consensus::Proposer::propose`], this value
    /// will be used.
    pub fn set_default_block_size_limit(&mut self, limit: usize) {
        self.default_block_size_limit = limit;
    }

    /// Set soft deadline percentage.
    ///
    /// The value is used to compute soft deadline during block production.
    /// The soft deadline indicates where we should stop attempting to add transactions
    /// to the block, which exhaust resources. After soft deadline is reached,
    /// we switch to a fixed-amount mode, in which after we see `MAX_SKIPPED_TRANSACTIONS`
    /// transactions which exhaust resrouces, we will conclude that the block is full.
    ///
    /// Setting the value too low will significantly limit the amount of transactions
    /// we try in case they exhaust resources. Setting the value too high can
    /// potentially open a DoS vector, where many "exhaust resources" transactions
    /// are being tried with no success, hence block producer ends up creating an empty block.
    pub fn set_soft_deadline(&mut self, percent: Percent) {
        self.soft_deadline_percent = percent;
    }
}

impl<B, Block, C, A, PR> ProposerFactory<A, B, C, PR>
where
    A: EncryptedTransactionPool<Block = Block> + 'static,
    B: backend::Backend<Block> + Send + Sync + 'static,
    Block: BlockT,
    C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + Send + Sync + 'static,
    C::Api: ApiExt<Block> + BlockBuilderApi<Block>,
{
    fn init_with_now(
        &mut self,
        parent_header: &<Block as BlockT>::Header,
        now: Box<dyn Fn() -> time::Instant + Send + Sync>,
    ) -> Proposer<B, Block, C, A, PR> {
        let parent_hash = parent_header.hash();

        info!("🙌 Starting consensus session on top of parent {:?}", parent_hash);

        let proposer = Proposer::<_, _, _, _, PR> {
            spawn_handle: self.spawn_handle.clone(),
            client: self.client.clone(),
            parent_hash,
            parent_number: *parent_header.number(),
            transaction_pool: self.transaction_pool.clone(),
            now,
            metrics: self.metrics.clone(),
            default_block_size_limit: self.default_block_size_limit,
            soft_deadline_percent: self.soft_deadline_percent,
            telemetry: self.telemetry.clone(),
            _phantom: PhantomData,
            include_proof_in_block_size_estimation: self.include_proof_in_block_size_estimation,
        };

        proposer
    }
}

impl<A, B, Block, C, PR> sp_consensus::Environment<Block> for ProposerFactory<A, B, C, PR>
where
    A: EncryptedTransactionPool<Block = Block> + 'static,
    B: backend::Backend<Block> + Send + Sync + 'static,
    Block: BlockT,
    C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + Send + Sync + 'static,
    C::Api: ApiExt<Block> + BlockBuilderApi<Block> + StarknetRuntimeApi<Block> + ConvertTransactionRuntimeApi<Block>,
    PR: ProofRecording,
{
    type CreateProposer = future::Ready<Result<Self::Proposer, Self::Error>>;
    type Proposer = Proposer<B, Block, C, A, PR>;
    type Error = sp_blockchain::Error;

    fn init(&mut self, parent_header: &<Block as BlockT>::Header) -> Self::CreateProposer {
        future::ready(Ok(self.init_with_now(parent_header, Box::new(time::Instant::now))))
    }
}

/// The proposer logic.
pub struct Proposer<B, Block: BlockT, C, A: EncryptedTransactionPool, PR> {
    spawn_handle: Box<dyn SpawnNamed>,
    client: Arc<C>,
    parent_hash: Block::Hash,
    parent_number: <<Block as BlockT>::Header as HeaderT>::Number,
    transaction_pool: Arc<A>,
    now: Box<dyn Fn() -> time::Instant + Send + Sync>,
    metrics: PrometheusMetrics,
    default_block_size_limit: usize,
    include_proof_in_block_size_estimation: bool,
    soft_deadline_percent: Percent,
    telemetry: Option<TelemetryHandle>,
    _phantom: PhantomData<(B, PR)>,
}

impl<A, B, Block, C, PR> sp_consensus::Proposer<Block> for Proposer<B, Block, C, A, PR>
where
    A: EncryptedTransactionPool<Block = Block> + 'static,
    B: backend::Backend<Block> + Send + Sync + 'static,
    Block: BlockT,
    C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + Send + Sync + 'static,
    C::Api: ApiExt<Block> + BlockBuilderApi<Block> + StarknetRuntimeApi<Block> + ConvertTransactionRuntimeApi<Block>,
    PR: ProofRecording,
{
    type Proposal = Pin<Box<dyn Future<Output = Result<Proposal<Block, PR::Proof>, Self::Error>> + Send>>;
    type Error = sp_blockchain::Error;
    type ProofRecording = PR;
    type Proof = PR::Proof;

    fn propose(
        self,
        inherent_data: InherentData,
        inherent_digests: Digest,
        max_duration: time::Duration,
        block_size_limit: Option<usize>,
    ) -> Self::Proposal {
        let (tx, rx) = oneshot::channel();
        let spawn_handle = self.spawn_handle.clone();

        spawn_handle.spawn_blocking(
            "basic-authorship-proposer",
            None,
            Box::pin(async move {
                // leave some time for evaluation and block finalization (33%)
                let deadline = (self.now)() + max_duration - max_duration / 3;
                let res = self.propose_with(inherent_data, inherent_digests, deadline, block_size_limit).await;
                if tx.send(res).is_err() {
                    trace!(
                        target: LOG_TARGET,
                        "Could not send block production result to proposer!"
                    );
                }
            }),
        );

        async move { rx.await? }.boxed()
    }
}

/// If the block is full we will attempt to push at most
/// this number of transactions before quitting for real.
/// It allows us to increase block utilization.
const MAX_SKIPPED_TRANSACTIONS: usize = 8;

impl<A, B, Block, C, PR> Proposer<B, Block, C, A, PR>
where
    A: EncryptedTransactionPool<Block = Block> + 'static,
    B: backend::Backend<Block> + Send + Sync + 'static,
    Block: BlockT,
    C: BlockBuilderProvider<B, Block, C> + HeaderBackend<Block> + ProvideRuntimeApi<Block> + Send + Sync + 'static,
    C::Api: ApiExt<Block> + BlockBuilderApi<Block> + StarknetRuntimeApi<Block> + ConvertTransactionRuntimeApi<Block>,
    PR: ProofRecording,
{
    async fn propose_with(
        self,
        inherent_data: InherentData,
        inherent_digests: Digest,
        deadline: time::Instant,
        block_size_limit: Option<usize>,
    ) -> Result<Proposal<Block, PR::Proof>, sp_blockchain::Error> {
        let block_timer = time::Instant::now();
        let mut block_builder = self.client.new_block_at(self.parent_hash, inherent_digests, PR::ENABLED)?;

        self.apply_inherents(&mut block_builder, inherent_data)?;

        // TODO call `after_inherents` and check if we should apply extrinsincs here
        // <https://github.com/paritytech/substrate/pull/14275/>

        let end_reason = self.apply_extrinsics(&mut block_builder, deadline, block_size_limit).await?;
        let (block, storage_changes, proof) = block_builder.build()?.into_inner();
        let block_took = block_timer.elapsed();

        let proof = PR::into_proof(proof).map_err(|e| sp_blockchain::Error::Application(Box::new(e)))?;

        self.print_summary(&block, end_reason, block_took, block_timer.elapsed());
        Ok(Proposal { block, proof, storage_changes })
    }

    /// Apply all inherents to the block.
    fn apply_inherents(
        &self,
        block_builder: &mut sc_block_builder::BlockBuilder<'_, Block, C, B>,
        inherent_data: InherentData,
    ) -> Result<(), sp_blockchain::Error> {
        let create_inherents_start = time::Instant::now();
        let inherents = block_builder.create_inherents(inherent_data)?;
        let create_inherents_end = time::Instant::now();

        self.metrics.report(|metrics| {
            metrics
                .create_inherents_time
                .observe(create_inherents_end.saturating_duration_since(create_inherents_start).as_secs_f64());
        });

        for inherent in inherents {
            match block_builder.push(inherent) {
                Err(ApplyExtrinsicFailed(Validity(e))) if e.exhausted_resources() => {
                    warn!(
                        target: LOG_TARGET,
                        "⚠️  Dropping non-mandatory inherent from overweight block."
                    )
                }
                Err(ApplyExtrinsicFailed(Validity(e))) if e.was_mandatory() => {
                    error!("❌️ Mandatory inherent extrinsic returned error. Block cannot be produced.");
                    return Err(ApplyExtrinsicFailed(Validity(e)));
                }
                Err(e) => {
                    warn!(
                        target: LOG_TARGET,
                        "❗️ Inherent extrinsic returned unexpected error: {}. Dropping.", e
                    );
                }
                Ok(_) => {}
            }
        }
        Ok(())
    }

    /// Apply as many extrinsics as possible to the block.
    async fn apply_extrinsics(
        &self,
        block_builder: &mut sc_block_builder::BlockBuilder<'_, Block, C, B>,
        deadline: time::Instant,
        block_size_limit: Option<usize>,
    ) -> Result<EndProposingReason, sp_blockchain::Error> {
        // Encrypted Transaction Pool Check and Initialization
        // This block of code is responsible for handling the encrypted transaction pool. It performs
        // several key operations:
        // 1. Checking if an encrypted transaction pool is being used. If not, it sets default values
        //    indicating that no encrypted pool is in use.
        // 2. If an encrypted mempool is being used, it proceeds with further setup: a. Determines whether
        //    an external decryptor is being utilized for the transactions. b. Calculates the block height
        //    and initializes the transaction pool for that specific block. c. Checks whether the
        //    transaction pool for the block is already closed.
        // 3. Retrieves and logs relevant information about the transaction pool's status, such as the
        //    current order of transactions, the total number of transactions, the number of submitted and
        //    ready transactions.
        // 4. Determines the length of encrypted transactions to be processed, and closes the pool for the
        //    current block height if it is not already closed.
        //
        // The outcome of this block is a tuple containing:
        // - is_using_encrypted_mempool: A boolean indicating if an encrypted pool is in use.
        // - using_external_decryptor: A boolean indicating if an external decryptor is being used.
        // - encrypted_txs_len: The length of encrypted transactions in the pool.
        // - block_tx_pool_is_closed: A boolean indicating if the transaction pool for the block is closed.
        //
        let (
            is_using_encrypted_mempool,
            using_external_decryptor,
            encrypted_transaction_pool_orders,
            is_closed_block_encrypted_transaction_pool,
        ) = {
            let encrypted_mempool = self.transaction_pool.encrypted_mempool().clone();
            let mut locked_encrypted_mempool = encrypted_mempool.lock().await;
            let is_using_encrypted_mempool = locked_encrypted_mempool.is_using_encrypted_mempool();
            let mut encrypted_transaction_pool_orders = vec![];

            if !is_using_encrypted_mempool {
                (is_using_encrypted_mempool, false, encrypted_transaction_pool_orders, true)
            } else {
                let is_using_external_decryptor = locked_encrypted_mempool.is_using_external_decryptor();
                let block_height = self.parent_number.to_string().parse::<u64>().map_err(|e| {
                    sp_blockchain::Error::Application(Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to parse block height: {e}"),
                    )))
                })? + 1;
                let block_encrypted_transaction_pool =
                    locked_encrypted_mempool.get_or_init_block_encrypted_transaction_pool(block_height);
                let is_closed_block_encrypted_transaction_pool = block_encrypted_transaction_pool.is_closed();

                let order = block_encrypted_transaction_pool.get_order();
                let tx_cnt = block_encrypted_transaction_pool.get_tx_cnt();
                let dec_cnt = block_encrypted_transaction_pool.get_submitted_tx_count();
                let ready_cnt = self.transaction_pool.status().ready as u64;
                log::info!(
                    "block height: {}, current order: {}, (tx count:submitted tx count:ready count) = ({}:{}:{})",
                    block_height,
                    order,
                    tx_cnt,
                    dec_cnt,
                    ready_cnt
                );

                if !is_closed_block_encrypted_transaction_pool {
                    locked_encrypted_mempool.close(block_height).unwrap();
                    encrypted_transaction_pool_orders = locked_encrypted_mempool
                        .get_block_encrypted_transaction_pool(&block_height)
                        .unwrap()
                        .encrypted_transaction_pool_orders()
                        .cloned()
                        .collect::<Vec<u64>>();
                }

                (
                    is_using_encrypted_mempool,
                    is_using_external_decryptor,
                    encrypted_transaction_pool_orders,
                    is_closed_block_encrypted_transaction_pool,
                )
            }
        };

        // Processing of Encrypted Transactions
        // This section of the code is executed if an encrypted transaction pool is being used and the
        // transaction pool for the block is not closed. It performs the following operations:
        // 1. Captures the current system time to log the start time of the decryption process.
        // 2. Iterates through each encrypted transaction in the pool based on the number of encrypted
        //    transactions.
        // 3. For each transaction, it calls a function to decrypt and submit the transaction to the block.
        //    The decision to use an external decryptor is also considered in this step.
        //
        // - If the encrypted transaction pool is in use (`is_using_encrypted_mempool` is true) and the
        //   transaction pool for the block is not closed (`block_tx_pool_is_closed` is false), then: a. The
        //   current system time is recorded. b. The decryption process starts, and each transaction is
        //   decrypted and submitted in sequence.
        if is_using_encrypted_mempool && !is_closed_block_encrypted_transaction_pool {
            // Records the start time of the decryption process
            let start = std::time::SystemTime::now();
            let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
            log::info!("Decrypt Start in {:?}", since_the_epoch);

            // Iterates through each encrypted transaction and processes them
            encrypted_transaction_pool_orders.iter().for_each(|&order| {
                self.decrypt_and_submit_transaction(order, using_external_decryptor);
            });
        }

        // proceed with transactions
        // We calculate soft deadline used only in case we start skipping transactions.
        let now = (self.now)();
        let left = deadline.saturating_duration_since(now);
        let left_micros: u64 = left.as_micros().saturated_into();
        let soft_deadline = now + time::Duration::from_micros(self.soft_deadline_percent.mul_floor(left_micros));
        let mut skipped = 0;
        let mut unqueue_invalid = Vec::new();

        let mut t1 = self.transaction_pool.ready_at(self.parent_number).fuse();
        let mut t2 = futures_timer::Delay::new(deadline.saturating_duration_since((self.now)()) / 8).fuse();

        let mut pending_iterator = select! {
            res = t1 => res,
            _ = t2 => {
                warn!(target: LOG_TARGET,
                    "Timeout fired waiting for transaction pool at block #{}. \
                    Proceeding with production.",
                    self.parent_number,
                );
                self.transaction_pool.ready()
            },
        };

        let block_size_limit = block_size_limit.unwrap_or(self.default_block_size_limit);

        debug!(target: LOG_TARGET, "Attempting to push transactions from the pool.");
        debug!(target: LOG_TARGET, "Pool status: {:?}", self.transaction_pool.status());
        let mut transaction_pushed = false;

        let end_reason = loop {
            let pending_tx = if let Some(pending_tx) = pending_iterator.next() {
                pending_tx
            } else {
                debug!(
                    target: LOG_TARGET,
                    "No more transactions, proceeding with proposing."
                );

                break EndProposingReason::NoMoreTransactions;
            };

            let now = (self.now)();
            if now > deadline {
                debug!(
                    target: LOG_TARGET,
                    "Consensus deadline reached when pushing block transactions, \
                proceeding with proposing."
                );
                break EndProposingReason::HitDeadline;
            }

            let pending_tx_data = pending_tx.data().clone();
            let pending_tx_hash = pending_tx.hash().clone();

            let block_size = block_builder.estimate_block_size(self.include_proof_in_block_size_estimation);
            if block_size + pending_tx_data.encoded_size() > block_size_limit {
                pending_iterator.report_invalid(&pending_tx);
                if skipped < MAX_SKIPPED_TRANSACTIONS {
                    skipped += 1;
                    debug!(
                        target: LOG_TARGET,
                        "Transaction would overflow the block size limit, \
                     but will try {} more transactions before quitting.",
                        MAX_SKIPPED_TRANSACTIONS - skipped,
                    );
                    continue;
                } else if now < soft_deadline {
                    debug!(
                        target: LOG_TARGET,
                        "Transaction would overflow the block size limit, \
                     but we still have time before the soft deadline, so \
                     we will try a bit more."
                    );
                    continue;
                } else {
                    debug!(
                        target: LOG_TARGET,
                        "Reached block size limit, proceeding with proposing."
                    );
                    break EndProposingReason::HitBlockSizeLimit;
                }
            }

            trace!(target: LOG_TARGET, "[{:?}] Pushing to the block.", pending_tx_hash);
            match sc_block_builder::BlockBuilder::push(block_builder, pending_tx_data) {
                Ok(()) => {
                    transaction_pushed = true;
                    debug!(target: LOG_TARGET, "[{:?}] Pushed to the block.", pending_tx_hash);
                }
                Err(ApplyExtrinsicFailed(Validity(e))) if e.exhausted_resources() => {
                    pending_iterator.report_invalid(&pending_tx);
                    if skipped < MAX_SKIPPED_TRANSACTIONS {
                        skipped += 1;
                        debug!(target: LOG_TARGET,
                            "Block seems full, but will try {} more transactions before quitting.",
                            MAX_SKIPPED_TRANSACTIONS - skipped,
                        );
                    } else if (self.now)() < soft_deadline {
                        debug!(target: LOG_TARGET,
                            "Block seems full, but we still have time before the soft deadline, \
                             so we will try a bit more before quitting."
                        );
                    } else {
                        debug!(
                            target: LOG_TARGET,
                            "Reached block weight limit, proceeding with proposing."
                        );
                        break EndProposingReason::HitBlockWeightLimit;
                    }
                }
                Err(e) => {
                    pending_iterator.report_invalid(&pending_tx);
                    debug!(
                        target: LOG_TARGET,
                        "[{:?}] Invalid transaction: {}", pending_tx_hash, e
                    );
                    unqueue_invalid.push(pending_tx_hash);
                }
            }
        };

        if matches!(end_reason, EndProposingReason::HitBlockSizeLimit) && !transaction_pushed {
            warn!(
                target: LOG_TARGET,
                "Hit block size limit of `{}` without including any transaction!", block_size_limit,
            );
        }

        self.transaction_pool.remove_invalid(&unqueue_invalid);
        Ok(end_reason)
    }

    /// Prints a summary and does telemetry + metrics.
    ///
    /// - `block`: The block that was build.
    /// - `end_reason`: Why did we stop producing the block?
    /// - `block_took`: How long did it took to produce the actual block?
    /// - `propose_took`: How long did the entire proposing took?
    fn print_summary(
        &self,
        block: &Block,
        end_reason: EndProposingReason,
        block_took: time::Duration,
        propose_took: time::Duration,
    ) {
        let extrinsics = block.extrinsics();
        self.metrics.report(|metrics| {
            metrics.number_of_transactions.set(extrinsics.len() as u64);
            metrics.block_constructed.observe(block_took.as_secs_f64());
            metrics.report_end_proposing_reason(end_reason);
            metrics.create_block_proposal_time.observe(propose_took.as_secs_f64());
        });

        let extrinsics_summary = if extrinsics.is_empty() {
            "no extrinsics".to_string()
        } else {
            format!(
                "extrinsics ({}): [{}]",
                extrinsics.len(),
                extrinsics.iter().map(|xt| BlakeTwo256::hash_of(xt).to_string()).collect::<Vec<_>>().join(", ")
            )
        };

        info!(
            "🥷🎁 Prepared block for proposing at {} ({} ms) [hash: {:?}; parent_hash: {}; {extrinsics_summary}",
            block.header().number(),
            block_took.as_millis(),
            <Block as BlockT>::Hash::from(block.header().hash()),
            block.header().parent_hash(),
        );
        telemetry!(
            self.telemetry;
            CONSENSUS_INFO;
            "prepared_block_for_proposing";
            "number" => ?block.header().number(),
            "hash" => ?<Block as BlockT>::Hash::from(block.header().hash()),
        );
    }

    fn decrypt_and_submit_transaction(&self, order: u64, using_external_decryptor: bool) {
        let block_height = self.parent_number.to_string().parse::<u64>().unwrap() + 1;
        let best_block_hash = self.client.info().best_hash;
        let client = self.client.clone();
        let pool = self.transaction_pool.clone();

        let encrypted_mempool = self.transaction_pool.encrypted_mempool();
        self.spawn_handle.spawn_blocking(
            "Decryptor",
            None,
            Box::pin(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;

                let (encrypted_invoke_transaction, decryption_key) = {
                    let locked_encrypted_mempool = encrypted_mempool.lock().await;
                    let Some(encrypted_transaction_block) =
                        locked_encrypted_mempool.get_block_encrypted_transaction_pool(&block_height)
                    else {
                        log::error!("Something wrong. Not exist block_height: {block_height}");
                        return;
                    };

                    let tx = match encrypted_transaction_block.get_encrypted_invoke_tx(order) {
                        Ok(encrypted_tx) => encrypted_tx.clone(),
                        Err(e) => {
                            log::error!("Failed to get encrypted_invoke_transaction: {e}");
                            return;
                        }
                    };

                    (tx, encrypted_transaction_block.get_decryption_key(order).cloned())
                };

                let decryptor = Decryptor::default();
                let invoke_tx_result: Result<InvokeTransaction, _> = if using_external_decryptor {
                    decryptor.delegate_to_decrypt_encrypted_invoke_transaction(encrypted_invoke_transaction).await
                } else {
                    decryptor.decrypt_encrypted_invoke_transaction(encrypted_invoke_transaction, decryption_key).await
                };

                let invoke_tx = match invoke_tx_result {
                    Ok(tx) => tx,
                    Err(e) => {
                        // Should conduct an integrity check in advance to avoid wasting resources on decrypting invalid
                        // transactions.
                        log::error!("Error while decrypting transaction: {e}");
                        let mut locked_encrypted_mempool = encrypted_mempool.lock().await;
                        let encrypted_transaction_block =
                            locked_encrypted_mempool.get_mut_block_encrypted_transaction_pool(&block_height).unwrap();
                        encrypted_transaction_block.delete_invalid_encrypted_tx(order);

                        return;
                    }
                };

                {
                    let mut locked_encrypted_mempool = encrypted_mempool.lock().await;
                    let encrypted_transaction_block =
                        locked_encrypted_mempool.get_mut_block_encrypted_transaction_pool(&block_height).unwrap();

                    encrypted_transaction_block.increase_decrypted_tx_count();
                }

                let end = std::time::SystemTime::now();
                let since_the_epoch = match end.duration_since(UNIX_EPOCH) {
                    Ok(duration) => duration,
                    Err(e) => {
                        log::error!("System time error: {e:?}");
                        return;
                    }
                };
                log::info!("Decrypt {order} End in {since_the_epoch:?}");

                let transaction: UserTransaction = UserTransaction::Invoke(invoke_tx.clone());

                let Ok(extrinsic) = client.runtime_api().convert_transaction(best_block_hash, transaction.clone())
                else {
                    log::error!("Failed to convert transaction to extrinsic.");
                    return;
                };

                match submit_extrinsic_with_order(pool, best_block_hash, extrinsic, order).await {
                    Ok(_hash) => log::info!("Successfully submitted extrinsic"),
                    Err(e) => log::error!("Failed to submit extrinsic: {e:?}"),
                }
            }),
        )
    }
}
