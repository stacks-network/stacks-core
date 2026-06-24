use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use stacks_bench::{Network, StacksBlockRef};
use tokio::sync::mpsc;

use super::bench_ui::run_bench_progress_ui;
use crate::cli::common::{
    CliContext, ExecCommand, run_bench_json_progress, run_indexer_json_progress,
    run_indexer_progress_ui,
};
use crate::commands::bench::baseline::{BaselineCalibrateParams, BaselineCalibrationResult};
use crate::commands::common::{IndexerArgs, IndexerUiSpawner};

#[derive(clap::Args, Debug)]
pub struct BaselineArgs {
    #[command(subcommand)]
    pub command: BaselineCommand,
}

#[derive(clap::Subcommand, Debug)]
pub enum BaselineCommand {
    /// Measure and save a reusable empty-block overhead baseline calibration.
    Calibrate(BaselineCalibrateArgs),
}

#[derive(clap::Args, Debug, Serialize, Deserialize)]
pub struct BaselineCalibrateArgs {
    /// Stacks node data dir (the directory containing the `chainstate` folder).
    #[arg(long = "source", short = 's')]
    source_dir: PathBuf,

    /// Stacks block (height, index_block_hash, or canonical block_hash) to use
    /// as the baseline anchor. Defaults to the node's current canonical tip.
    #[arg(long = "at")]
    #[serde(skip_serializing_if = "Option::is_none")]
    at: Option<StacksBlockRef>,

    /// Tip block used to resolve canonical history for `--at`.
    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    tip: Option<StacksBlockRef>,

    /// The network to use. If not specified, inferred from the chainstate DB.
    #[arg(long, short = 'n', value_enum)]
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<Network>,

    /// **DESTRUCTIVE.** Skip the reflink/CoW copy of the source chainstate
    /// and run calibration directly against `--source`.
    #[arg(long = "dangerous-no-chainstate-copy", default_value_t = false)]
    #[serde(skip)]
    dangerous_no_chainstate_copy: bool,

    /// Whether or not to include pre-Nakamoto blocks in the reflink copy.
    #[arg(long = "with-pre-naka", default_value_t = false)]
    include_pre_nakamoto_blocks: bool,

    /// Parent directory under which the shadow (reflink) copy is created.
    #[arg(long = "shadow-dir-root", value_name = "DIR")]
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow_dir_root: Option<PathBuf>,
}

impl IndexerArgs for BaselineCalibrateArgs {
    fn start_at(&self) -> Option<&StacksBlockRef> {
        self.at.as_ref()
    }

    fn end_at(&self) -> Option<&StacksBlockRef> {
        self.at.as_ref()
    }

    fn block_count(&self) -> Option<u32> {
        None
    }

    fn tip(&self) -> Option<&StacksBlockRef> {
        self.tip.as_ref()
    }

    fn network(&self) -> Option<Network> {
        self.network
    }
}

impl From<&BaselineCalibrateArgs> for BaselineCalibrateParams {
    fn from(args: &BaselineCalibrateArgs) -> Self {
        Self {
            source_dir: args.source_dir.clone(),
            at: args.at.clone(),
            tip: args.tip.clone(),
            network: args.network,
            include_pre_nakamoto_blocks: args.include_pre_nakamoto_blocks,
            dangerous_no_chainstate_copy: args.dangerous_no_chainstate_copy,
            shadow_dir_root: args.shadow_dir_root.clone(),
        }
    }
}

impl ExecCommand for BaselineArgs {
    type Output = BaselineCalibrationResult;

    async fn exec(&self, ctx: &CliContext) -> Result<Self::Output> {
        match &self.command {
            BaselineCommand::Calibrate(args) => args.exec(ctx).await,
        }
    }
}

impl ExecCommand for BaselineCalibrateArgs {
    type Output = BaselineCalibrationResult;

    async fn exec(&self, ctx: &CliContext) -> Result<Self::Output> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let ui_handle = if ctx.interactive() {
            tokio::spawn(run_bench_progress_ui(event_rx))
        } else if ctx.json() {
            tokio::spawn(run_bench_json_progress(event_rx))
        } else {
            tokio::spawn(async move {
                let mut rx = event_rx;
                while rx.recv().await.is_some() {}
                Ok(())
            })
        };

        let interrupted = Arc::new(AtomicBool::new(false));
        {
            let interrupted = interrupted.clone();
            tokio::spawn(async move {
                tokio::signal::ctrl_c().await.ok();
                interrupted.store(true, Ordering::Relaxed);
            });
        }

        let indexer_ui: IndexerUiSpawner = if ctx.interactive() {
            Box::new(|rx, start, end, tip| {
                tokio::spawn(run_indexer_progress_ui(rx, start, end, tip))
            })
        } else if ctx.json() {
            Box::new(|rx, start, end, tip| {
                tokio::spawn(run_indexer_json_progress(rx, start, end, tip))
            })
        } else {
            crate::commands::common::silent_indexer_ui()
        };

        let params = BaselineCalibrateParams::from(self);
        let mut app_db = ctx.app_db();
        let result = crate::commands::bench::baseline::calibrate_baseline(
            &mut app_db,
            &params,
            event_tx,
            interrupted,
            indexer_ui,
        )
        .await;

        ui_handle.await??;
        result
    }
}
