use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use stacks_bench::baseline::run_convergent_baseline;
use stacks_bench::bench_events::{self, BenchEvent, BenchEventSender};
use stacks_bench::context::BenchContext;
use stacks_bench::db::app::AppDb;
use stacks_bench::db::app::models::BaselineCalibration;
use stacks_bench::shadow::ShadowDir;
use stacks_bench::{Network, StacksBlockRef};

use crate::commands::bench::run::{
    baseline_anchor_hex, create_shadow_dir_with_events, run_indexer_pipeline,
};
use crate::commands::common::{
    IndexerArgs, IndexerUiSpawner, get_git_hash, run_cleanup_with_events, setup_bench_env,
    setup_bench_env_and_plan,
};

/// Non-clap parameter struct for standalone empty-block baseline calibration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineCalibrateParams {
    pub source_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<StacksBlockRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tip: Option<StacksBlockRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    pub include_pre_nakamoto_blocks: bool,
    #[serde(skip)]
    pub dangerous_no_chainstate_copy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shadow_dir_root: Option<PathBuf>,
}

impl BaselineCalibrateParams {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).context("Failed to serialize BaselineCalibrateParams to JSON")
    }
}

impl IndexerArgs for BaselineCalibrateParams {
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

/// Structured result returned by `bench baseline calibrate`.
#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct BaselineCalibrationResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calibration_id: Option<i32>,
    pub chainstate_id: i32,
    pub start_parent_index_hash: String,
    pub interrupted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calibration: Option<BaselineCalibrationJson>,
}
crate::wire::wire_payload!(BaselineCalibrationResult, "baseline_calibration", 1);

#[derive(serde::Serialize, schemars::JsonSchema)]
pub struct BaselineCalibrationJson {
    pub warmup_blocks: u32,
    pub measured_blocks: u32,
    pub avg_setup_us: u64,
    pub avg_finalize_us: u64,
    pub avg_clarity_commit_us: u64,
    pub avg_advance_tip_us: u64,
    pub avg_index_commit_us: u64,
    pub converged: bool,
    pub segments_used: u32,
    pub measurement_window: u32,
    pub total_blocks: u32,
    pub duration_secs: f64,
}

pub async fn calibrate_baseline(
    app_db: &mut AppDb,
    params: &BaselineCalibrateParams,
    ev: BenchEventSender,
    interrupted: Arc<AtomicBool>,
    indexer_ui: IndexerUiSpawner,
) -> Result<BaselineCalibrationResult> {
    validate_calibrate_params(params)?;

    let shadow_dir = create_shadow_dir_with_events(
        &params.source_dir,
        params.include_pre_nakamoto_blocks,
        params.shadow_dir_root.as_deref(),
        params.dangerous_no_chainstate_copy,
        &ev,
    )?;

    calibrate_on_shadow(app_db, params, shadow_dir, &ev, interrupted, &indexer_ui).await
}

fn validate_calibrate_params(params: &BaselineCalibrateParams) -> Result<()> {
    if params.dangerous_no_chainstate_copy && params.shadow_dir_root.is_some() {
        bail!(
            "--dangerous-no-chainstate-copy and --shadow-dir-root are mutually exclusive: \
             passthrough mode does not create a shadow directory, so the parent override has no effect"
        );
    }
    Ok(())
}

async fn calibrate_on_shadow(
    app_db: &mut AppDb,
    params: &BaselineCalibrateParams,
    shadow_dir: ShadowDir,
    ev: &BenchEventSender,
    interrupted: Arc<AtomicBool>,
    indexer_ui: &IndexerUiSpawner,
) -> Result<BaselineCalibrationResult> {
    let (env, anchor_tip, start_block, end_block) = if params.at.is_some() {
        let (env, plan) = setup_bench_env_and_plan(&shadow_dir, params).await?;
        let anchor_tip = plan.anchor_tip.clone();
        bench_events::emit(
            ev,
            BenchEvent::EnvironmentReady {
                chain_id: env.chain_id,
                network: env.network.to_string(),
                epochs: env.epochs.iter().map(|e| e.to_string()).collect(),
                source_dir: shadow_dir.source().display().to_string(),
                shadow_dir: if shadow_dir.is_passthrough() {
                    "<skipped - no copy>".to_string()
                } else {
                    shadow_dir.path().display().to_string()
                },
                target_txid: None,
                target_block: params.at.as_ref().map(ToString::to_string),
                target_block_height: None,
                repetitions: None,
            },
        );
        let (resolved, _block_ids) =
            run_indexer_pipeline(app_db, &env, plan, &interrupted, indexer_ui).await?;
        let block = resolved.end;
        (env, anchor_tip, block.clone(), block)
    } else {
        let (env, anchor_tip) =
            setup_bench_env(&shadow_dir, params.network, params.tip.as_ref()).await?;
        bench_events::emit(
            ev,
            BenchEvent::EnvironmentReady {
                chain_id: env.chain_id,
                network: env.network.to_string(),
                epochs: env.epochs.iter().map(|e| e.to_string()).collect(),
                source_dir: shadow_dir.source().display().to_string(),
                shadow_dir: if shadow_dir.is_passthrough() {
                    "<skipped - no copy>".to_string()
                } else {
                    shadow_dir.path().display().to_string()
                },
                target_txid: None,
                target_block: Some(anchor_tip.id.to_string()),
                target_block_height: Some(anchor_tip.height),
                repetitions: None,
            },
        );
        (env, anchor_tip.clone(), anchor_tip.clone(), anchor_tip)
    };

    let (chainstate_model, _) = app_db
        .get_or_create_chainstate(env.network, env.chain_id, &anchor_tip, &env.epochs)
        .await?;

    let bench_context = BenchContext::from_env(&env, anchor_tip, start_block, end_block);
    let anchor_hex = baseline_anchor_hex(bench_context.end_block().id.as_bytes());
    let (mut chainstate, burnchain) = bench_context.open_stacks_chainstate()?;
    let outcome = run_convergent_baseline(
        &mut chainstate,
        &burnchain,
        &bench_context.end_block().id,
        &interrupted,
        ev,
    )?;

    if interrupted.load(Ordering::Relaxed) {
        run_cleanup_with_events(app_db.clone(), shadow_dir, ev).await?;
        return Ok(BaselineCalibrationResult {
            calibration_id: None,
            chainstate_id: chainstate_model.id,
            start_parent_index_hash: anchor_hex,
            interrupted: true,
            calibration: None,
        });
    }

    bench_events::emit(
        ev,
        BenchEvent::BaselineComplete {
            baseline: outcome.baseline.clone(),
            converged: outcome.converged,
            segments_used: outcome.segments_used,
            measurement_window: outcome.measurement_window,
            total_blocks: outcome.total_blocks,
            duration: outcome.duration,
        },
    );

    let calibration = app_db
        .save_baseline_calibration(
            chainstate_model.id,
            Utc::now().naive_utc(),
            get_git_hash().unwrap_or(vec![0u8; 20]),
            params.to_json()?,
            &bench_context.end_block().id,
            &outcome,
        )
        .await?;

    run_cleanup_with_events(app_db.clone(), shadow_dir, ev).await?;
    Ok(result_from_calibration(&calibration, false))
}

fn result_from_calibration(
    calibration: &BaselineCalibration,
    interrupted: bool,
) -> BaselineCalibrationResult {
    BaselineCalibrationResult {
        calibration_id: Some(calibration.id),
        chainstate_id: calibration.chainstate_id,
        start_parent_index_hash: baseline_anchor_hex(&calibration.start_parent_index_hash),
        interrupted,
        calibration: Some(BaselineCalibrationJson {
            warmup_blocks: calibration.warmup_blocks as u32,
            measured_blocks: calibration.measured_blocks as u32,
            avg_setup_us: calibration.avg_setup_us as u64,
            avg_finalize_us: calibration.avg_finalize_us as u64,
            avg_clarity_commit_us: calibration.avg_clarity_commit_us as u64,
            avg_advance_tip_us: calibration.avg_advance_tip_us as u64,
            avg_index_commit_us: calibration.avg_index_commit_us as u64,
            converged: calibration.converged,
            segments_used: calibration.segments_used as u32,
            measurement_window: calibration.measurement_window as u32,
            total_blocks: calibration.total_blocks as u32,
            duration_secs: calibration.duration_us as f64 / 1_000_000.0,
        }),
    }
}
