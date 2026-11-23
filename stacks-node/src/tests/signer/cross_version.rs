// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Cross-version signer integration tests.
//!
//! Every scenario here mixes signers built from this tree (run in-process, as
//! in the rest of the `signer` tests) with signers from a published release,
//! run as `stacks-signer run` child processes. The miner and the test observer
//! stay in-process, so `Counters` and `TEST_*` fault injection remain
//! available on the current side while the baseline side runs the bytes
//! operators actually deployed.
//!
//! The pass criterion for every scenario is full participation: each signer
//! must accept each block. Chain advancement alone would hide a broken
//! minority behind the 70% signing threshold, which is exactly the failure
//! these tests exist to catch.
//!
//! # Chain
//!
//! Every scenario boots to Epoch 4.0, the newest epoch activated on mainnet,
//! with each signer staked in pox-5 so the signer set is read from the
//! on-chain pox-5 contract as it is in production. Epoch 4.1 has no mainnet
//! activation height, so the schedule stops at 4.0. See
//! [`shared_chain_config`].
//!
//! # Running locally
//!
//! Point `STACKS_SIGNER_BASELINE_BIN` at a `stacks-signer` binary from a
//! release archive (`linux-glibc-x64.zip` on the GitHub release). Point
//! `STACKS_NODE_BASELINE_BIN` at a `stacks-node` built from that release's
//! commit with `--features testing`: the embedded node is a `testing` build,
//! and `testing` changes consensus-visible constants (for example
//! `MINER_REWARD_MATURITY`), so the shipped node binary forks from it. The
//! node scenarios also need `STACKS_NODE_BIN` and `STACKS_SIGNER_BIN`, this
//! tree's binaries built with `--features testing`. Then run a scenario like
//! any other signer integration test:
//!
//! ```text
//! export STACKS_SIGNER_BASELINE_BIN=/path/to/release/stacks-signer
//! export STACKS_NODE_BASELINE_BIN=/path/to/release-commit-testing/stacks-node
//! export STACKS_NODE_BIN=/path/to/current/stacks-node
//! export STACKS_SIGNER_BIN=/path/to/current/stacks-signer
//! BITCOIND_TEST=1 cargo test -p stacks-node -- --ignored tests::signer::cross_version::
//! ```
//!
//! In CI, `.github/workflows/_tests-cross-version.yml` installs the latest
//! release's signer through `.github/actions/stacks-baseline`, builds its node
//! from the attested source commit, and runs each scenario in its own job. The scenarios are tagged `ci_skip` so the regular bitcoin test
//! matrix, which has no baseline binary, leaves them out.
//!
//! # Limits
//!
//! Baseline signers are opaque to the harness: release binaries have no
//! `testing` feature, so they answer no `StateInfo` requests and carry no
//! `TEST_*` fault injection. Everything asserted about them comes from what
//! they publish to StackerDB, observed through the test observer, plus whether
//! the process is still alive. Only the configuration keys written by
//! [`baseline_signer_toml`] reach a baseline signer; other changes a test
//! makes to its `GlobalConfig` are not forwarded.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::TryRecvError;
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::Duration;
use std::{env, fs};

use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ContractName;
use libsigner::v0::messages::{
    BlockRejection, BlockResponse, RejectReason, SignerMessage, SignerMessageTypePrefix,
};
use pinny::tag;
use stacks::chainstate::stacks::StacksPrivateKey;
use stacks::core::{StacksEpoch, StacksEpochExtension};
use stacks::types::chainstate::{StacksAddress, StacksPublicKey};
use stacks::types::PublicKey;
use stacks::util::hash::{to_hex, MerkleHashFunc, Sha512Trunc256Sum};
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::StacksEpochId;
use stacks_common::util::tests::TestFlag;
use stacks_signer::config::GlobalConfig as SignerConfig;
use stacks_signer::runloop::{SignerResult, StateInfo};
use stacks_signer::v0::signer_state::SUPPORTED_SIGNER_PROTOCOL_VERSION;
use stacks_signer::v0::SpawnedSigner;

use super::SpawnedSignerTrait;
use crate::tests::nakamoto_integrations::{enable_epoch_4_0, wait_for};
use crate::tests::neon_integrations::{get_account, test_observer};
use crate::tests::signer::v0::{
    get_stackerdb_signer_messages, wait_for_state_machine_update_by_miner_tenure_id,
    SbtcRegistryStub,
};
use crate::tests::signer::SignerTest;
use crate::tests::{self};

/// Environment variable naming the baseline `stacks-signer` binary.
pub const BASELINE_SIGNER_BIN_ENV: &str = "STACKS_SIGNER_BASELINE_BIN";

/// Public keys of the signers that [`CrossVersionSigner::new`] spawns from the
/// baseline binary. Set it before constructing the `SignerTest`; remove a key
/// before restarting that signer to bring it up on the current code instead.
pub static BASELINE_SIGNER_KEYS: LazyLock<TestFlag<Vec<StacksPublicKey>>> =
    LazyLock::new(TestFlag::default);

/// Use a PR-built subprocess when rolling forward onto an existing database.
static USE_CURRENT_SIGNER_PROCESS: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);

/// Path of the baseline `stacks-signer` binary, from [`BASELINE_SIGNER_BIN_ENV`].
fn baseline_signer_bin() -> PathBuf {
    let path = env::var_os(BASELINE_SIGNER_BIN_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "{BASELINE_SIGNER_BIN_ENV} must point at a released stacks-signer binary to run cross-version tests"
            )
        });
    assert!(
        path.is_file(),
        "{BASELINE_SIGNER_BIN_ENV}={} is not a file",
        path.display()
    );
    path
}

/// Render the subset of `config` that a baseline signer is started with.
///
/// Released signers reject unknown configuration keys, so only keys that have
/// been stable across releases are written; everything else takes the
/// baseline's own defaults.
pub fn baseline_signer_toml(config: &SignerConfig) -> String {
    let mut toml = format!(
        r#"stacks_private_key = {}
node_host = {}
endpoint = {}
network = {}
auth_password = {}
db_path = {}
event_timeout_ms = {}
first_proposal_burn_block_timing_secs = {}
block_proposal_timeout_ms = {}
block_proposal_validation_timeout_ms = {}
tenure_idle_timeout_secs = {}
read_count_idle_timeout_secs = {}
"#,
        serde_json::to_string(&config.stacks_private_key.to_hex()).unwrap(),
        serde_json::to_string(&config.node_host).unwrap(),
        serde_json::to_string(&config.endpoint.to_string()).unwrap(),
        serde_json::to_string(&config.network.to_string()).unwrap(),
        serde_json::to_string(&config.auth_password).unwrap(),
        serde_json::to_string(&config.db_path.display().to_string()).unwrap(),
        config.event_timeout.as_millis(),
        config.first_proposal_burn_block_timing.as_secs(),
        config.block_proposal_timeout.as_millis(),
        config.block_proposal_validation_timeout.as_millis(),
        config.tenure_idle_timeout.as_secs(),
        config.read_count_idle_timeout.as_secs(),
    );
    if let Some(metrics_endpoint) = &config.metrics_endpoint {
        toml.push_str(&format!(
            "metrics_endpoint = {:?}\n",
            metrics_endpoint.to_string()
        ));
    }
    if let Some(chain_id) = config.chain_id {
        toml.push_str(&format!("chain_id = {chain_id}\n"));
    }
    toml
}

/// The last `lines` lines of the file at `path`, or nothing if it cannot be read.
fn log_tail(path: &Path, lines: usize) -> Vec<String> {
    let Ok(file) = File::open(path) else {
        return vec![];
    };
    let mut tail = VecDeque::with_capacity(lines);
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if tail.len() == lines {
            tail.pop_front();
        }
        tail.push_back(line);
    }
    tail.into_iter().collect()
}

/// A signer from the baseline release, running as a `stacks-signer run` child process.
pub struct ProcessSigner {
    /// The configuration the process was started with
    pub config: SignerConfig,
    /// Where the process writes its stdout and stderr
    pub log_path: PathBuf,
    child: Mutex<Child>,
    /// Last authenticated advertised version, retained across observer resets
    protocol_version: Mutex<Option<u64>>,
}

impl ProcessSigner {
    /// Spawn a chosen binary, retaining the database path on upgrades.
    fn start(config: SignerConfig, bin: PathBuf) -> Self {
        let dir = config
            .db_path
            .parent()
            .expect("signer db_path must have a parent directory")
            .to_path_buf();
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("signer.toml");
        fs::write(&config_path, baseline_signer_toml(&config)).unwrap();
        let log_path = dir.join("signer.log");
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();
        let child = Command::new(&bin)
            .arg("run")
            .arg("--config")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to spawn {}: {e}", bin.display()));
        info!("Spawned baseline signer process";
            "pid" => child.id(),
            "endpoint" => %config.endpoint,
            "binary" => %bin.display(),
            "log" => %log_path.display()
        );
        Self {
            config,
            log_path,
            child: Mutex::new(child),
            protocol_version: Mutex::new(None),
        }
    }

    /// Whether the child process is still running.
    pub fn is_running(&self) -> bool {
        let mut child = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        matches!(child.try_wait(), Ok(None))
    }

    /// Kill the process if it is still running. Returns the exit status if it
    /// had already exited on its own, which is never expected.
    fn terminate(&self) -> Option<ExitStatus> {
        let mut child = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        match child.try_wait() {
            Ok(Some(status)) => {
                error!("Baseline signer exited on its own";
                    "endpoint" => %self.config.endpoint,
                    "status" => %status,
                    "log" => %self.log_path.display()
                );
                for line in log_tail(&self.log_path, 40) {
                    error!("[baseline signer {}] {line}", self.config.endpoint);
                }
                Some(status)
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                None
            }
            Err(e) => panic!("Failed to poll baseline signer process: {e}"),
        }
    }
}

impl Drop for ProcessSigner {
    fn drop(&mut self) {
        // Never leak a signer process past the test, including on panic.
        let child = self.child.get_mut().unwrap_or_else(PoisonError::into_inner);
        if let Ok(None) = child.try_wait() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl SpawnedSignerTrait for ProcessSigner {
    type ReceiveResult = ();
    type StopResult = ExitStatus;

    fn new(config: SignerConfig) -> Self {
        Self::start(config, baseline_signer_bin())
    }

    fn try_recv(&self) -> Self::ReceiveResult {}

    fn stop(self) -> Option<Self::StopResult> {
        self.terminate()
    }

    fn state_info_from_recv_result(_result: Self::ReceiveResult) -> Option<StateInfo> {
        None
    }

    fn reports_state(&self) -> bool {
        false
    }

    fn supported_protocol_version(&self) -> u64 {
        // Release binaries have no version override, so use the version the
        // signer itself advertises. Before its first update, assume the
        // current constant.
        let address = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&self.config.stacks_private_key),
        );
        let advertised =
            get_stackerdb_signer_messages()
                .into_iter()
                .rev()
                .find_map(|(chunk, message)| {
                    let SignerMessage::StateMachineUpdate(update) = message else {
                        return None;
                    };
                    chunk
                        .verify(&address)
                        .unwrap_or(false)
                        .then_some(update.local_supported_signer_protocol_version)
                });
        let mut cached = self
            .protocol_version
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(version) = advertised {
            *cached = Some(version);
        }
        cached.unwrap_or(SUPPORTED_SIGNER_PROTOCOL_VERSION)
    }
}

/// A signer that is either the current in-process [`SpawnedSigner`] or a
/// baseline [`ProcessSigner`], chosen by whether its public key is listed in
/// [`BASELINE_SIGNER_KEYS`].
pub enum CrossVersionSigner {
    /// A signer from the baseline release binary
    Baseline(ProcessSigner),
    /// A signer built from this tree
    Current(SpawnedSigner),
    /// A PR-built signer reopened on a release-owned database
    Upgraded(ProcessSigner),
}

impl CrossVersionSigner {
    /// The subprocess behind this signer, including an upgraded PR binary.
    pub fn as_process(&self) -> Option<&ProcessSigner> {
        match self {
            Self::Baseline(signer) => Some(signer),
            Self::Upgraded(signer) => Some(signer),
            Self::Current(_) => None,
        }
    }
}

impl SpawnedSignerTrait for CrossVersionSigner {
    type ReceiveResult = Option<Result<SignerResult, TryRecvError>>;
    type StopResult = ();

    fn new(config: SignerConfig) -> Self {
        let public_key = StacksPublicKey::from_private(&config.stacks_private_key);
        if BASELINE_SIGNER_KEYS.get().contains(&public_key) {
            Self::Baseline(ProcessSigner::new(config))
        } else if USE_CURRENT_SIGNER_PROCESS.get() {
            Self::Upgraded(ProcessSigner::start(
                config,
                binary_from_env("STACKS_SIGNER_BIN"),
            ))
        } else {
            Self::Current(SpawnedSigner::new(config))
        }
    }

    fn try_recv(&self) -> Self::ReceiveResult {
        match self {
            Self::Baseline(_) | Self::Upgraded(_) => None,
            Self::Current(signer) => Some(signer.try_recv()),
        }
    }

    fn stop(self) -> Option<Self::StopResult> {
        match self {
            Self::Baseline(signer) | Self::Upgraded(signer) => signer.stop().map(|_| ()),
            Self::Current(signer) => signer.stop().map(|_| ()),
        }
    }

    fn state_info_from_recv_result(result: Self::ReceiveResult) -> Option<StateInfo> {
        result.and_then(<SpawnedSigner as SpawnedSignerTrait>::state_info_from_recv_result)
    }

    fn reports_state(&self) -> bool {
        matches!(self, Self::Current(_))
    }

    fn supported_protocol_version(&self) -> u64 {
        match self {
            Self::Baseline(signer) | Self::Upgraded(signer) => signer.supported_protocol_version(),
            Self::Current(signer) => signer.supported_protocol_version(),
        }
    }
}

/// Deterministic signer keys, so a scenario can pick its baseline set before
/// the harness starts.
fn signer_keys(num_signers: usize) -> Vec<StacksPrivateKey> {
    (0..num_signers)
        .map(|i| StacksPrivateKey::from_seed(format!("cross_version_signer_{i}").as_bytes()))
        .collect()
}

/// Mark the first `num_baseline` of `keys` as baseline signers.
fn select_baseline_signers(keys: &[StacksPrivateKey], num_baseline: usize) {
    BASELINE_SIGNER_KEYS.set(
        keys.iter()
            .take(num_baseline)
            .map(StacksPublicKey::from_private)
            .collect(),
    );
}

/// Panic if any of the given baseline signer processes has exited.
fn assert_processes_running<'a>(processes: impl Iterator<Item = (usize, &'a ProcessSigner)>) {
    for (ix, process) in processes {
        assert!(
            process.is_running(),
            "Baseline signer #{ix} exited; see {}",
            process.log_path.display()
        );
    }
}

/// Panic if any signer in `signer_pks` has written a block response that this
/// tree's codec cannot decode.
///
/// [`get_stackerdb_signer_messages`] drops undecodable chunks, so without this
/// check a wire-format break (for example, a field appended to
/// `BlockResponseData` without bumping its version) only shows up as a
/// participation timeout. Only block responses are checked: the current tree
/// may legitimately stop decoding message types a release still writes.
fn assert_block_responses_decode(signer_pks: &[StacksPublicKey]) {
    let addresses: Vec<StacksAddress> = signer_pks
        .iter()
        .map(|pk| StacksAddress::p2pkh(false, pk))
        .collect();
    let block_response_prefix = SignerMessageTypePrefix::BlockResponse as u8;
    for chunk in test_observer::get_stackerdb_chunks()
        .into_iter()
        .flat_map(|event| event.modified_slots)
    {
        if chunk.data.first() != Some(&block_response_prefix) {
            continue;
        }
        let Some(ix) = addresses
            .iter()
            .position(|address| chunk.verify(address).unwrap_or(false))
        else {
            continue;
        };
        if let Err(e) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice()) {
            panic!(
                "Signer #{ix} wrote a block response this tree cannot decode: {e}; bytes = {}",
                to_hex(&chunk.data)
            );
        }
    }
}

/// Whether `rejection` of a block that reached the chain only shows that the
/// signer answered late. A signer that evaluates a proposal after the rest
/// have already pushed it past the threshold finds the block itself as its
/// node's tenure tip, so the block "does not confirm the expected parent".
/// A chain block confirms the parent the chain expects, so this reason can
/// only come from that timing, unlike every other rejection reason.
fn is_late_answer(rejection: &BlockRejection) -> bool {
    rejection.response_data.reject_reason == RejectReason::InvalidParentBlock
}

/// Wait until every signer in `signer_pks` has accepted every Nakamoto block
/// the test observer has seen since it was last cleared, or answered it late
/// (see [`is_late_answer`]), and return those
/// blocks' signer signature hashes. Pre-Nakamoto blocks carry no signer
/// signature hash and are skipped.
fn wait_for_full_acceptance(signer_pks: &[StacksPublicKey]) -> Vec<Sha512Trunc256Sum> {
    let block_hashes: Vec<Sha512Trunc256Sum> = test_observer::get_blocks()
        .iter()
        .filter_map(|block| {
            // Only Nakamoto blocks carry a miner signature and a signer hash.
            block.get("miner_signature")?;
            let sighash = block["signer_signature_hash"]
                .as_str()
                .expect("Nakamoto block must include signer hash");
            Some(Sha512Trunc256Sum::from_hex(sighash.trim_start_matches("0x")).unwrap())
        })
        .collect();
    for sighash in &block_hashes {
        wait_for(60, || {
            // Fail on the decode error itself rather than waiting out the
            // timeout for a response that will never parse.
            assert_block_responses_decode(signer_pks);
            let messages = get_stackerdb_signer_messages();
            Ok(signer_pks.iter().all(|pk| {
                messages.iter().any(|(chunk, message)| match message {
                    SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) => {
                        accepted.signer_signature_hash == *sighash
                            && pk
                                .verify(sighash.bits(), &accepted.signature)
                                .unwrap_or(false)
                    }
                    SignerMessage::BlockResponse(BlockResponse::Rejected(rejection)) => {
                        rejection.signer_signature_hash == *sighash
                            && is_late_answer(rejection)
                            && chunk.recover_pk().is_ok_and(|signer| &signer == pk)
                    }
                    _ => false,
                })
            }))
        })
        .unwrap_or_else(|e| panic!("Not every signer accepted block {sighash}: {e}"));
    }
    block_hashes
}

/// Wait until block production has settled: every signer has accepted every
/// observed block and `node`'s tip has not moved for a few seconds. A
/// proposal still being signed is not yet observed, so acceptance alone
/// cannot show that no signer is mid-validation.
fn wait_for_signing_to_settle(
    node_config: &stacks::config::Config,
    signer_pks: &[StacksPublicKey],
) {
    let tip_height = || process_chain_info(node_config).map(|info| info.stacks_tip_height);
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        let before = tip_height();
        wait_for_full_acceptance(signer_pks);
        std::thread::sleep(Duration::from_secs(5));
        if before.is_some() && tip_height() == before {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Block production did not settle"
        );
    }
}

/// Every signer in `signer_pks` must have accepted every Nakamoto block the
/// test observer has seen since it was last cleared, and none may have
/// rejected any of those blocks, other than by answering late (see
/// [`is_late_answer`]).
fn assert_full_participation(signer_pks: &[StacksPublicKey]) {
    let block_hashes = wait_for_full_acceptance(signer_pks);
    assert!(!block_hashes.is_empty(), "No Nakamoto blocks were observed");
    // A miner may re-propose at a height whose first proposal signers have
    // already pre-committed to, so rejecting the replacement is expected and
    // only blocks that reached the chain count. A signer that has not yet
    // processed a new sortition may also reject its miner's first proposal
    // transiently and accept the retry; what counts is each signer's last
    // answer for each block. Both nodes can report the same chunks in either
    // order, so order answers by slot version, not arrival: a signer writes
    // all its block responses to one slot.
    let mut last_answers: HashMap<(String, Sha512Trunc256Sum), (u32, Option<BlockRejection>)> =
        HashMap::new();
    for (chunk, message) in get_stackerdb_signer_messages() {
        let SignerMessage::BlockResponse(response) = message else {
            continue;
        };
        let Ok(signer) = chunk.recover_pk() else {
            continue;
        };
        let (sighash, rejection) = match response {
            BlockResponse::Accepted(accepted) => (accepted.signer_signature_hash, None),
            BlockResponse::Rejected(rejection) => {
                let sighash = rejection.signer_signature_hash.clone();
                (sighash, Some(rejection).filter(|r| !is_late_answer(r)))
            }
        };
        if !block_hashes.contains(&sighash) {
            continue;
        }
        let answer = last_answers
            .entry((signer.to_hex(), sighash))
            .or_insert((chunk.slot_version, rejection.clone()));
        if chunk.slot_version >= answer.0 {
            *answer = (chunk.slot_version, rejection);
        }
    }
    let rejections: Vec<_> = last_answers
        .into_values()
        .filter_map(|(_, rejection)| rejection)
        .collect();
    assert!(
        rejections.is_empty(),
        "Signers rejected blocks: {rejections:?}"
    );
    info!(
        "All {} signers accepted all {} blocks",
        signer_pks.len(),
        block_hashes.len()
    );
}

/// The `(local supported, active)` protocol versions from the latest
/// `StateMachineUpdate` of each signer in `addresses`.
fn latest_update_versions(addresses: &[StacksAddress]) -> Vec<Option<(u64, u64)>> {
    let messages = get_stackerdb_signer_messages();
    addresses
        .iter()
        .map(|address| {
            messages.iter().rev().find_map(|(chunk, message)| {
                let SignerMessage::StateMachineUpdate(update) = message else {
                    return None;
                };
                chunk.verify(address).unwrap_or(false).then_some((
                    update.local_supported_signer_protocol_version,
                    update.active_signer_protocol_version,
                ))
            })
        })
        .collect()
}

/// The active protocol version an equal-weight signer set with these locally
/// supported versions agrees on: the highest version supported by at least
/// 70% of the set, the same rule as `determine_latest_supported_signer_protocol_version`.
fn expected_active_version(local_versions: &[u64]) -> u64 {
    let mut candidates: Vec<u64> = local_versions
        .iter()
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    candidates.sort_unstable_by(|a, b| b.cmp(a));
    let total = local_versions.len() as u64;
    candidates
        .into_iter()
        .find(|candidate| {
            let support = local_versions.iter().filter(|v| *v >= candidate).count() as u64;
            support >= total * 7 / 10
        })
        .expect("at least one version is supported by everyone")
}

/// Wait until every signer has published a `StateMachineUpdate`, then check
/// that each one reports the active version the whole set should agree on.
fn assert_protocol_version_agreement(addresses: &[StacksAddress]) {
    wait_for(60, || {
        let versions = latest_update_versions(addresses);
        if !versions.iter().all(Option::is_some) {
            return Ok(false);
        }
        let versions: Vec<_> = versions.into_iter().flatten().collect();
        let local: Vec<_> = versions.iter().map(|(local, _)| *local).collect();
        let expected = expected_active_version(&local);
        Ok(versions.iter().all(|(_, active)| *active == expected))
    })
    .expect("Signers did not converge on the supported protocol version");
}

/// Mine `num_tenures` tenures, each with one interim block carrying a transfer,
/// and check that every signer accepted every block.
fn mine_and_check_participation<S: SpawnedSignerTrait>(
    signer_test: &SignerTest<S>,
    num_tenures: usize,
    sender_sk: &StacksPrivateKey,
    send_fee: u64,
    send_amt: u64,
) {
    let sender_addr = tests::to_addr(sender_sk);
    // Cache release advertisements before clearing their observation history.
    let _ = signer_test.signer_addresses_versions();
    test_observer::clear();
    // Let whatever the caller mined finish before the first burn block.
    wait_for_signing_to_settle(
        &signer_test.running_nodes.conf,
        &signer_test.signer_test_pks(),
    );
    for tenure in 1..=num_tenures {
        info!("------------------------- Mining tenure #{tenure} -------------------------");
        signer_test.mine_nakamoto_block(Duration::from_secs(60), true);
        let (_, nonce) = signer_test
            .submit_transfer_tx(sender_sk, send_fee, send_amt)
            .unwrap();
        wait_for(60, || {
            Ok(get_account(&signer_test.running_nodes.rpc_origin(), &sender_addr).nonce > nonce)
        })
        .expect("Timed out waiting for the interim block");
        // A block appends once 70% accept it. Let the rest answer before the
        // next burn block changes their view mid-validation.
        wait_for_signing_to_settle(
            &signer_test.running_nodes.conf,
            &signer_test.signer_test_pks(),
        );
    }
    assert_full_participation(&signer_test.signer_test_pks());
}

/// Boot a mixed set of `num_baseline` baseline signers and `num_signers - num_baseline`
/// current signers behind the current miner, mine a few tenures, and check full
/// participation and protocol version agreement.
fn mixed_signer_set(num_signers: usize, num_baseline: usize) {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let num_tenures = 3;
    let sender_sk = StacksPrivateKey::from_seed("cross_version_sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;

    let keys = signer_keys(num_signers);
    select_baseline_signers(&keys, num_baseline);
    let signer_test: SignerTest<CrossVersionSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        with_sbtc_publisher(vec![(
            sender_addr,
            (send_amt + send_fee) * num_tenures as u64,
        )]),
        |_| {},
        shared_chain_config,
        None,
        Some(keys),
    );
    info!("------------------------- Booting {num_baseline} baseline + {} current signers -------------------------", num_signers - num_baseline);
    boot_to_shared_epoch(&signer_test);
    let baseline = |signer_test: &SignerTest<CrossVersionSigner>| {
        assert_processes_running(
            signer_test
                .spawned_signers
                .iter()
                .enumerate()
                .filter_map(|(ix, signer)| signer.as_process().map(|process| (ix, process))),
        )
    };
    baseline(&signer_test);

    mine_and_check_participation(&signer_test, num_tenures, &sender_sk, send_fee, send_amt);
    let addresses: Vec<StacksAddress> = signer_test
        .signer_addresses_versions()
        .into_iter()
        .map(|(address, _)| address)
        .collect();
    assert_protocol_version_agreement(&addresses);
    baseline(&signer_test);
    signer_test.shutdown();
}

#[tag(bitcoind, slow, ci_skip)]
#[ignore]
#[test]
/// The current miner with a signer set made only of baseline signers: the
/// proposals, pushes and responses of this tree must stay decodable by the
/// released signer, and every baseline signer must sign every block.
fn current_miner_baseline_signers() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let num_signers = 5;
    let num_tenures = 3;
    let sender_sk = StacksPrivateKey::from_seed("cross_version_sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;

    let signer_test: SignerTest<ProcessSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        with_sbtc_publisher(vec![(
            sender_addr,
            (send_amt + send_fee) * num_tenures as u64,
        )]),
        |_| {},
        shared_chain_config,
        None,
        Some(signer_keys(num_signers)),
    );
    boot_to_shared_epoch(&signer_test);
    assert_processes_running(signer_test.spawned_signers.iter().enumerate());

    mine_and_check_participation(&signer_test, num_tenures, &sender_sk, send_fee, send_amt);
    assert_processes_running(signer_test.spawned_signers.iter().enumerate());
    signer_test.shutdown();
}

#[tag(bitcoind, slow, ci_skip)]
#[ignore]
#[test]
/// Current signers as a blocking minority (4 of 10) among baseline signers.
/// The active protocol version must stay at the baseline's, and every signer
/// on both sides must still sign every block.
fn mixed_signer_set_current_minority() {
    mixed_signer_set(10, 6);
}

#[tag(bitcoind, slow, ci_skip)]
#[ignore]
#[test]
/// Baseline signers as a blocking minority (3 of 10) among current signers.
/// The active protocol version rolls over to the current one once 70% of the
/// set supports it, and the baseline minority must still sign every block.
fn mixed_signer_set_baseline_minority() {
    mixed_signer_set(10, 3);
}

#[tag(bitcoind, slow, ci_skip)]
#[ignore]
#[test]
/// Start with only baseline signers, then replace them one at a time with a
/// current signer restarted on the same signer database. Each upgraded signer
/// must migrate its database, rejoin, and keep signing alongside the rest.
fn rolling_signer_upgrade() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let num_signers = 10;
    let sender_sk = StacksPrivateKey::from_seed("cross_version_sender".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    // One tenure before the upgrade, one after each swap.
    let num_tenures = (num_signers + 1) as u64;

    let keys = signer_keys(num_signers);
    select_baseline_signers(&keys, num_signers);
    USE_CURRENT_SIGNER_PROCESS.set(true);
    let mut signer_test: SignerTest<CrossVersionSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        with_sbtc_publisher(vec![(sender_addr, (send_amt + send_fee) * num_tenures)]),
        |_| {},
        shared_chain_config,
        None,
        Some(keys.clone()),
    );
    boot_to_shared_epoch(&signer_test);
    mine_and_check_participation(&signer_test, 1, &sender_sk, send_fee, send_amt);

    for (ix, key) in keys.iter().enumerate() {
        info!("------------------------- Upgrading signer #{ix} -------------------------");
        let remaining_baseline: Vec<StacksPublicKey> = BASELINE_SIGNER_KEYS
            .get()
            .into_iter()
            .filter(|pk| pk != &StacksPublicKey::from_private(key))
            .collect();
        BASELINE_SIGNER_KEYS.set(remaining_baseline);
        let config = signer_test.stop_signer(ix);
        signer_test.restart_signer(ix, config);
        assert!(
            matches!(
                signer_test.spawned_signers[ix],
                CrossVersionSigner::Upgraded(_)
            ),
            "Signer #{ix} should have restarted on the current code"
        );
        signer_test.wait_for_registered();
        mine_and_check_participation(&signer_test, 1, &sender_sk, send_fee, send_amt);
        let addresses: Vec<_> = signer_test
            .signer_addresses_versions()
            .into_iter()
            .map(|(address, _)| address)
            .collect();
        assert_protocol_version_agreement(&addresses);
    }

    let addresses: Vec<StacksAddress> = signer_test
        .signer_addresses_versions()
        .into_iter()
        .map(|(address, _)| address)
        .collect();
    assert_protocol_version_agreement(&addresses);
    signer_test.shutdown();
}

#[test]
fn baseline_signer_toml_loads_with_the_current_parser() {
    let config = SignerConfig::load_from_str(
        r#"
stacks_private_key = "eb05c83546fdd2c79f10f5ad5434a90dd28f7e3acb7c092157aa1bc3656b012c01"
node_host = "127.0.0.1:20443"
endpoint = "127.0.0.1:30000"
network = "testnet"
auth_password = "12345"
db_path = "/tmp/cross-version/signerdb.sqlite"
event_timeout_ms = 128
metrics_endpoint = "127.0.0.1:9000"
chain_id = 2147483648
block_proposal_timeout_ms = 1234
tenure_idle_timeout_secs = 77
"#,
    )
    .unwrap();

    // Released signers reject unknown keys, and so does the current parser:
    // every key written here must exist in the current config surface.
    let reloaded = SignerConfig::load_from_str(&baseline_signer_toml(&config)).unwrap();
    assert_eq!(reloaded.stacks_private_key, config.stacks_private_key);
    assert_eq!(reloaded.node_host, config.node_host);
    assert_eq!(reloaded.endpoint, config.endpoint);
    assert_eq!(reloaded.network, config.network);
    assert_eq!(reloaded.auth_password, config.auth_password);
    assert_eq!(reloaded.db_path, config.db_path);
    assert_eq!(reloaded.event_timeout, config.event_timeout);
    assert_eq!(reloaded.metrics_endpoint, config.metrics_endpoint);
    assert_eq!(reloaded.chain_id, config.chain_id);
    assert_eq!(
        reloaded.block_proposal_timeout,
        config.block_proposal_timeout
    );
    assert_eq!(reloaded.tenure_idle_timeout, config.tenure_idle_timeout);
    assert_eq!(
        reloaded.first_proposal_burn_block_timing,
        config.first_proposal_burn_block_timing
    );
    assert_eq!(
        reloaded.block_proposal_validation_timeout,
        config.block_proposal_validation_timeout
    );
}

#[test]
fn expected_active_version_follows_the_agreement_threshold() {
    // 70% is enough, 60% is not, and a lone newer signer never wins.
    assert_eq!(expected_active_version(&[3, 3, 3, 3, 3, 3, 3, 2, 2, 2]), 3);
    assert_eq!(expected_active_version(&[3, 3, 3, 3, 3, 3, 2, 2, 2, 2]), 2);
    assert_eq!(expected_active_version(&[2, 2, 2, 2, 5]), 2);
    assert_eq!(expected_active_version(&[2, 2, 2]), 2);
    assert_eq!(expected_active_version(&[3, 3, 3, 2, 2]), 3);
}

/// Name of the sBTC token stub contract that pox-5 reads balances from.
const SBTC_TOKEN_CONTRACT: &str = "sbtc-token-stub";
/// Name of the sBTC registry stub contract that signer-set computation reads.
const SBTC_REGISTRY_CONTRACT: &str = "sbtc-registry-stub";
/// uSTX that each signer stakes in pox-5 while booting.
const POX_5_STAKE_AMOUNT: u128 = 100_000_000_000;
/// Reward cycles each pox-5 stake stays locked; outlasts every scenario.
const POX_5_LOCK_CYCLES: u128 = 12;
/// uSTX funding the account that publishes the sBTC stubs.
const SBTC_PUBLISHER_BALANCE: u64 = 1_000_000;

/// Account that publishes the sBTC stub contracts before Epoch 4.0.
fn sbtc_publisher_key() -> StacksPrivateKey {
    StacksPrivateKey::from_seed(b"cross-version-sbtc-publisher")
}

/// Chain parameters every scenario shares. Both binaries must agree on each
/// consensus-relevant value here, so [`node_toml`] forwards all of them.
///
/// The epoch schedule is the one the other Epoch 4.0 signer tests boot
/// through: `boot_to_epoch_4_with_pox5_lockups` relies on its geometry to
/// stake outside a prepare phase. It stops at Epoch 4.0 because the baseline
/// releases, like mainnet, have not scheduled Epoch 4.1.
fn shared_chain_config(config: &mut stacks::config::Config) {
    let publisher = tests::to_addr(&sbtc_publisher_key());
    let contract = |name: &str| {
        QualifiedContractIdentifier::new(
            publisher.clone().into(),
            ContractName::try_from(name.to_string()).unwrap(),
        )
    };
    config.node.pox_5_sbtc_contract = Some(contract(SBTC_TOKEN_CONTRACT));
    config.node.pox_5_sbtc_registry_contract = Some(contract(SBTC_REGISTRY_CONTRACT));
    config.miner.block_commit_delay = Duration::from_secs(1);
    enable_epoch_4_0(config);
    // A node loading epochs from TOML takes each epoch's block limit from its
    // network's defaults, and the TOML cannot override them. Use the same
    // limits in-process so both binaries validate blocks identically.
    let network = config.burnchain.get_bitcoin_network().1;
    let defaults = StacksEpoch::get_epochs(network, None);
    let epochs = config.burnchain.epochs.as_mut().unwrap();
    epochs.truncate_after(StacksEpochId::Epoch40);
    let ids: Vec<StacksEpochId> = epochs.iter().map(|epoch| epoch.epoch_id).collect();
    for id in ids {
        epochs[id].block_limit = defaults[id].block_limit.clone();
    }
}

/// A scenario's initial balances plus the sBTC stub publisher's.
fn with_sbtc_publisher(mut balances: Vec<(StacksAddress, u64)>) -> Vec<(StacksAddress, u64)> {
    balances.push((
        tests::to_addr(&sbtc_publisher_key()),
        SBTC_PUBLISHER_BALANCE,
    ));
    balances
}

/// Boot to Epoch 4.0 with every signer staked in pox-5, then mine into the
/// first reward cycle whose signer set pox-5 computes, so every scenario
/// signs under a pox-5 reward set rather than the last pox-4 one.
fn boot_to_shared_epoch<S: SpawnedSignerTrait>(signer_test: &SignerTest<S>) {
    let aggregate_pubkey: [u8; 33] =
        StacksPublicKey::from_private(&StacksPrivateKey::from_seed(b"cross-version-sbtc-agg"))
            .to_bytes_compressed()
            .try_into()
            .expect("compressed secp256k1 pubkey is 33 bytes");
    signer_test.boot_to_epoch_4_with_pox5_lockups(
        &sbtc_publisher_key(),
        0,
        SBTC_TOKEN_CONTRACT,
        SBTC_REGISTRY_CONTRACT,
        &aggregate_pubkey,
        SbtcRegistryStub::WithoutSignerData,
        POX_5_STAKE_AMOUNT,
        POX_5_LOCK_CYCLES,
    );
    // The cycle containing the pox-5 activation height still uses the set
    // pox-4 computed in its prepare phase; pox-5 sets begin with the next one.
    let conf = &signer_test.running_nodes.conf;
    let burnchain = conf.get_burnchain();
    let first_pox_5_height = burnchain
        .pox_constants
        .first_pox_waterfall_block(burnchain.first_block_height)
        .expect("pox-5 activates after the first burn block");
    while crate::tests::neon_integrations::get_chain_info(conf).burn_block_height
        <= first_pox_5_height
    {
        signer_test.mine_nakamoto_block(Duration::from_secs(60), true);
    }
    let cycle = burnchain
        .block_height_to_reward_cycle(first_pox_5_height)
        .unwrap();
    let mut reward_set = signer_test.get_signer_public_keys(cycle);
    let mut signers = signer_test.signer_test_pks();
    reward_set.sort_by_key(|pk| pk.to_hex());
    signers.sort_by_key(|pk| pk.to_hex());
    assert_eq!(
        reward_set, signers,
        "The first pox-5 reward set must contain exactly the staked signers"
    );
}

/// A real node with persistent chainstate and file-backed logs. Dropping it
/// reaps the child even when an assertion unwinds the test.
struct ProcessNode {
    config: stacks::config::Config,
    child: Child,
    log_path: PathBuf,
}

impl ProcessNode {
    /// Start a release or PR binary against the supplied working directory.
    fn start(binary: &Path, config: stacks::config::Config, bootstrap: &str) -> Self {
        let dir = Path::new(&config.node.working_dir);
        fs::create_dir_all(dir).unwrap();
        let config_path = dir.join("cross-version.toml");
        fs::write(&config_path, node_toml(&config, bootstrap)).unwrap();
        let log_path = dir.join("node.log");
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();
        let child = Command::new(binary)
            .args(["start", "--config"])
            .arg(config_path)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to start {}: {e}", binary.display()));
        Self {
            config,
            child,
            log_path,
        }
    }

    /// Fail promptly with the node log if startup or synchronization failed.
    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            panic!(
                "Process node exited {status}: {:?}",
                log_tail(&self.log_path, 40)
            );
        }
    }

    /// Wait on public RPC state, without relying on in-process counters.
    fn wait_for_tip(&mut self, height: u64) {
        wait_for(240, || {
            self.assert_running();
            Ok(process_chain_info(&self.config)
                .is_some_and(|info| info.stacks_tip_height >= height))
        })
        .expect("Process node did not synchronize");
    }

    /// Stop and restart against exactly the same configuration and chainstate.
    fn restart(&mut self, binary: &Path, bootstrap: &str) {
        self.stop();
        let replacement = Self::start(binary, self.config.clone(), bootstrap);
        *self = replacement;
    }

    /// Use SIGTERM so SQLite and the node's shutdown path run before a swap.
    fn stop(&mut self) {
        if self.child.try_wait().unwrap().is_some() {
            return;
        }
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("Failed to signal process node");
        assert!(status.success(), "Failed to terminate process node");
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while self.child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
        }
        self.child.wait().unwrap();
    }
}

impl Drop for ProcessNode {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Emit only the release-stable config surface. Parsing and serializing through
/// ConfigFile also checks that values are valid TOML before spawning a child.
fn node_toml(c: &stacks::config::Config, bootstrap: &str) -> String {
    let q = |value: &str| serde_json::to_string(value).unwrap();
    let mut text = format!(
        r#"
[node]
working_dir = {work}
rpc_bind = {rpc}
p2p_bind = {p2p}
p2p_address = {p2p_addr}
data_url = {url}
seed = "{seed}"
local_peer_seed = "{peer_seed}"
bootstrap_node = {bootstrap}
miner = {miner}
stacker = {stacker}
mine_microblocks = false
wait_time_for_blocks = 200
pox_sync_sample_secs = 0
stacker_dbs = {dbs}
use_test_genesis_chainstate = true
pox_5_sbtc_contract = {sbtc_token}
pox_5_sbtc_registry_contract = {sbtc_registry}
[burnchain]
chain = "bitcoin"
mode = "nakamoto-neon"
peer_host = {host}
peer_port = {peer_port}
rpc_port = {rpc_port}
username = {user}
password = {password}
magic_bytes = "T3"
burn_fee_cap = {burn_fee}
poll_time_secs = 1
pox_prepare_length = {prepare}
pox_reward_length = {reward}
local_mining_public_key = {mining_pk}
wallet_name = {wallet}
[connection_options]
auth_token = {auth}
inv_sync_interval = 1
private_neighbors = true
[miner]
mining_key = {mining_key}
activated_vrf_key_path = {vrf_path}
first_attempt_time_ms = {first_attempt}
subsequent_attempt_time_ms = {subsequent_attempt}
wait_on_interim_blocks_ms = 1000
tenure_extend_cost_threshold = 0
[fee_estimation]
disabled = true
"#,
        work = q(&c.node.working_dir),
        rpc = q(&c.node.rpc_bind),
        p2p = q(&c.node.p2p_bind),
        p2p_addr = q(&c.node.p2p_address),
        url = q(&c.node.data_url),
        seed = stacks_common::util::hash::to_hex(&c.node.seed),
        peer_seed = stacks_common::util::hash::to_hex(&c.node.local_peer_seed),
        bootstrap = q(bootstrap),
        sbtc_token = q(&c.node.pox_5_sbtc_contract.as_ref().unwrap().to_string()),
        sbtc_registry = q(&c
            .node
            .pox_5_sbtc_registry_contract
            .as_ref()
            .unwrap()
            .to_string()),
        miner = c.node.miner,
        // Like the embedded signer-test node, replicate the signer StackerDBs
        // even when not mining.
        stacker = c.node.stacker,
        dbs = serde_json::to_string(
            &c.node
                .stacker_dbs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        )
        .unwrap(),
        host = q(&c.burnchain.peer_host),
        peer_port = c.burnchain.peer_port,
        rpc_port = c.burnchain.rpc_port,
        user = q(c.burnchain.username.as_deref().unwrap()),
        password = q(c.burnchain.password.as_deref().unwrap()),
        burn_fee = c.burnchain.burn_fee_cap,
        prepare = c.burnchain.pox_prepare_length.unwrap(),
        reward = c.burnchain.pox_reward_length.unwrap(),
        mining_pk = q(c.burnchain.local_mining_public_key.as_deref().unwrap()),
        // The test bootstrap creates this wallet and imports every miner key
        // into it, so a release miner finds its UTXOs there.
        wallet = q(c.burnchain.wallet_name.as_deref().unwrap()),
        auth = q(c.connection_options.auth_token.as_deref().unwrap()),
        mining_key = q(&c.miner.mining_key.as_ref().unwrap().to_hex()),
        vrf_path = q(&format!("{}/vrf_key", c.node.working_dir)),
        first_attempt = c.miner.first_attempt_time_ms,
        subsequent_attempt = c.miner.subsequent_attempt_time_ms,
    );
    // Unforwarded pox-5 overrides would fork the release node from the miner.
    assert!(
        c.node.pox_5_bond_admin.is_none() && c.node.pox_5_pause_admin.is_none(),
        "node_toml does not forward pox_5_bond_admin or pox_5_pause_admin"
    );
    let names = [
        "1.0", "2.0", "2.05", "2.1", "2.2", "2.3", "2.4", "2.5", "3.0", "3.1", "3.2", "3.3", "3.4",
        "4.0",
    ];
    let epochs = c.burnchain.epochs.as_ref().unwrap();
    assert_eq!(
        epochs.iter().count(),
        names.len(),
        "node_toml must name every configured epoch"
    );
    for (name, epoch) in names.iter().zip(epochs.iter()) {
        text.push_str(&format!(
            "\n[[burnchain.epochs]]\nepoch_name = {name:?}\nstart_height = {}\n",
            epoch.start_height
        ));
    }
    for balance in &c.initial_balances {
        text.push_str(&format!(
            "\n[[ustx_balance]]\naddress = {}\namount = {}\n",
            q(&balance.address.to_string()),
            balance.amount
        ));
    }
    for observer in &c.events_observers {
        text.push_str(&format!("\n[[events_observer]]\nendpoint = {}\nevents_keys = [\"*\", \"stackerdb\", \"block_proposal\"]\n", q(&observer.endpoint)));
    }
    stacks::config::ConfigFile::from_str(&text)
        .unwrap()
        .to_toml()
        .unwrap()
}

/// Locate a required binary without silently substituting the current build.
fn binary_from_env(name: &str) -> PathBuf {
    let path = PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("{name} must be set")));
    assert!(path.is_file(), "{name} is not a file: {}", path.display());
    path
}

/// Run the second node from a fresh release-owned chainstate. Only after it
/// syncs do signers switch their RPC and event source to that node.
fn process_node_scenario(miner: bool, upgrade: bool, baseline_signers: bool) {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let baseline = binary_from_env("STACKS_NODE_BASELINE_BIN");
    let seed = vec![2, 2, 2, 2];
    let primary_seed = vec![1, 1, 1, 1];
    let keys = signer_keys(10);
    select_baseline_signers(&keys, if baseline_signers { keys.len() } else { 0 });
    let primary_pk = crate::Keychain::default(primary_seed.clone()).get_pub_key();
    let secondary_pk = crate::Keychain::default(seed.clone()).get_pub_key();
    let sender = StacksPrivateKey::from_seed(b"cross-version-node-sender");
    let mut harness: SignerTest<CrossVersionSigner> = SignerTest::new_with_config_modifications(
        10,
        with_sbtc_publisher(vec![(tests::to_addr(&sender), 100_000)]),
        |config| {
            config.tenure_idle_timeout = Duration::from_secs(30);
        },
        |config| {
            shared_chain_config(config);
            // At handover the signers move their event endpoints to the process
            // node, so the embedded node's deliveries to the old ones fail.
            // Retrying them forever fills its bounded event queue and blocks
            // its p2p thread, which then never exits on shutdown. The node's
            // observer list cannot change at runtime, so this also applies
            // before handover, where a failed delivery is dropped instead of
            // retried.
            let observer_suffix = format!(":{}", test_observer::EVENT_OBSERVER_PORT);
            config.events_observers = std::mem::take(&mut config.events_observers)
                .into_iter()
                .map(|mut observer| {
                    if !observer.endpoint.ends_with(&observer_suffix) {
                        observer.disable_retries = true;
                    }
                    observer
                })
                .collect();
            config.node.seed = primary_seed.clone();
            config.burnchain.local_mining_public_key = Some(primary_pk.to_hex());
        },
        Some(vec![primary_pk.clone(), secondary_pk.clone()]),
        Some(keys),
    );
    boot_to_shared_epoch(&harness);
    let mut config = harness.running_nodes.conf.clone();
    config.node.working_dir.push_str("-baseline");
    config.node.rpc_bind = "127.0.0.1:30510".into();
    config.node.p2p_bind = "127.0.0.1:30511".into();
    config.node.p2p_address = config.node.p2p_bind.clone();
    config.node.data_url = format!("http://{}", config.node.rpc_bind);
    config.node.seed = seed.clone();
    config.node.local_peer_seed = seed;
    config.burnchain.local_mining_public_key = Some(secondary_pk.to_hex());
    config.miner.mining_key = Some(StacksPrivateKey::from_seed(&[2]));
    config.miner.activated_vrf_key_path = None;
    config.node.miner = false;
    // Until handover the baseline only reports to the observer.
    config.events_observers.retain(|o| {
        o.endpoint
            .ends_with(&test_observer::EVENT_OBSERVER_PORT.to_string())
    });
    let peer_key = StacksPublicKey::from_private(&StacksPrivateKey::from_seed(
        &harness.running_nodes.conf.node.local_peer_seed,
    ));
    let bootstrap = format!(
        "{}@{}",
        peer_key.to_hex(),
        harness.running_nodes.conf.node.p2p_address
    );
    let mut node = ProcessNode::start(&baseline, config, &bootstrap);
    let info = crate::tests::neon_integrations::get_chain_info(&harness.running_nodes.conf);
    node.wait_for_tip(info.stacks_tip_height);
    let synced = crate::tests::neon_integrations::get_chain_info(&node.config);
    assert_eq!(
        synced.stacks_tip, info.stacks_tip,
        "Baseline must sync the same chain"
    );
    if miner {
        // A follower has no registered VRF key. Confirm the release miner's
        // registration while the embedded miner still supplies blocks.
        node.config.node.miner = true;
        node.restart(&baseline, &bootstrap);
        harness.running_nodes.counters.skip_commit_op.set(true);
        wait_for_bitcoin_operation(&node.config, "54335e");
        harness.mine_nakamoto_block_without_commit(Duration::from_secs(120), false);
        let height = crate::tests::neon_integrations::get_chain_info(&harness.running_nodes.conf)
            .stacks_tip_height;
        node.wait_for_tip(height);
    }
    // Signers wrote their StackerDB chunks to the embedded node, and the
    // process node holds them only by replication. A signer reconnecting to a
    // stale replica reloads old state and can reuse slot versions the
    // embedded node already holds, so replication later overwrites its new
    // writes. So before reconnecting any signer, the process node must hold
    // the embedded node's tip and every signer chunk.
    //
    // Wait for the tip to go quiet, then stop every signer so no further
    // block can be signed and the embedded tip stays put. (The observer is
    // cleared first, so this wait checks quiescence, not acceptance; a
    // proposal cut off by the stop is simply retried after reconnect.) StackerDB peers refuse
    // each other's sync requests unless they share a canonical Stacks tip
    // tenure, and a running follower that falls a few tenures behind may not
    // fetch them until a new burn block arrives. Restarting it makes it sync
    // its peer's full inventory, as the miner scenarios' restart already
    // does. Its signer observers are registered only afterwards: while the
    // signers are down, retried deliveries to them would block its p2p
    // thread, and with it the RPC these waits poll.
    test_observer::clear();
    wait_for_signing_to_settle(&harness.running_nodes.conf, &harness.signer_test_pks());
    let signer_configs: Vec<_> = (0..harness.spawned_signers.len())
        .map(|_| harness.stop_signer(0))
        .collect();
    node.restart(&baseline, &bootstrap);
    wait_for(120, || {
        node.assert_running();
        let embedded_tip =
            crate::tests::neon_integrations::get_chain_info(&harness.running_nodes.conf);
        Ok(process_chain_info(&node.config)
            .is_some_and(|info| info.stacks_tip == embedded_tip.stacks_tip))
    })
    .expect("Process node did not reach the embedded node's tip before handover");
    // A node's StackerDB view (`rc_consensus_hash`) is the canonical Stacks
    // tip recorded on its burn-tip snapshot when that sortition was
    // processed. Two nodes that reached the same tip by different paths (one
    // mining, one syncing) can record different tips there, and then refuse
    // each other's sync as stale until the next sortition. Process one so
    // both record the shared tip; with the signers stopped its tenure stays
    // empty until they reconnect.
    let burn_height = crate::tests::neon_integrations::get_chain_info(&harness.running_nodes.conf)
        .burn_block_height;
    harness
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);
    wait_for(60, || {
        node.assert_running();
        let embedded = crate::tests::neon_integrations::get_chain_info(&harness.running_nodes.conf);
        Ok(embedded.burn_block_height > burn_height
            && process_chain_info(&node.config)
                .is_some_and(|info| info.burn_block_height == embedded.burn_block_height))
    })
    .expect("Nodes did not process the handover burn block");
    wait_for_signer_stackerdb_replication(&harness.running_nodes.conf, &node.config);
    node.config.events_observers = harness.running_nodes.conf.events_observers.clone();
    node.config.events_observers = std::mem::take(&mut node.config.events_observers)
        .into_iter()
        .map(|mut listener| {
            // The test observer ("localhost:<port>") keeps its address; only
            // signer endpoints, which are socket addresses, move.
            let observer_suffix = format!(":{}", test_observer::EVENT_OBSERVER_PORT);
            if !listener.endpoint.ends_with(&observer_suffix) {
                let mut addr: std::net::SocketAddr = listener.endpoint.parse().unwrap();
                addr.set_port(addr.port() + 10000);
                listener.endpoint = addr.to_string();
            }
            listener
        })
        .collect();
    node.config.node.miner = miner;
    if miner {
        harness.running_nodes.counters.skip_commit_op.set(true);
        crate::nakamoto_node::miner::TEST_MINE_SKIP.set(true);
    }
    node.restart(&baseline, &bootstrap);
    for (ix, mut signer_config) in signer_configs.into_iter().enumerate() {
        signer_config.node_host = node.config.node.rpc_bind.clone();
        signer_config
            .endpoint
            .set_port(signer_config.endpoint.port() + 10000);
        harness.restart_signer(ix, signer_config);
    }
    node.wait_for_tip(info.stacks_tip_height);
    if !miner {
        // Signers recompute the active miner on burn block events, and the
        // handover sortition happened while they were stopped, so on
        // reconnect they still hold the previous tenure and reject the
        // embedded miner's blocks. Give them a sortition to process live, then
        // let them agree on its tenure before the scenario mines on.
        let burn_height = process_chain_info(&node.config)
            .expect("Process node must serve its chain info")
            .burn_block_height;
        wait_for_bitcoin_operation(&node.config, "54335b");
        harness
            .running_nodes
            .btc_regtest_controller
            .build_next_block(1);
        wait_for(60, || {
            node.assert_running();
            Ok(process_chain_info(&node.config).is_some_and(|i| i.burn_block_height > burn_height))
        })
        .expect("Process node did not process the reconnect burn block");
        let tenure_id = process_chain_info(&node.config)
            .expect("Process node must serve its chain info")
            .pox_consensus;
        wait_for_state_machine_update_by_miner_tenure_id(
            60,
            &tenure_id,
            &harness.signer_addresses_versions_majority(),
        )
        .expect("Reconnected signers did not agree on the current tenure");
        // The embedded miner submitted its next commit before this tenure's
        // first block was signed. Let the tip settle so it replaces that
        // commit with one on the current tip before the next burn block;
        // otherwise it wins with a stale commit, keeps mining the old tenure,
        // and signers reject those blocks.
        wait_for_signing_to_settle(&node.config, &harness.signer_test_pks());
    }
    if miner {
        // A winner must have committed in MINING_COMMITMENT_FREQUENCY_NAKAMOTO
        // of the last MINING_COMMITMENT_WINDOW sortitions, and the embedded
        // miner stopped committing at handover. Confirm the process miner's
        // commits until it wins a sortition rather than expecting a tenure
        // from its first few, which are rejected as too infrequent.
        let mut won = false;
        for _ in 0..stacks_common::types::MINING_COMMITMENT_WINDOW {
            let before =
                crate::tests::neon_integrations::get_sortition_info(&node.config).burn_block_height;
            wait_for_bitcoin_operation(&node.config, "54335b");
            harness
                .running_nodes
                .btc_regtest_controller
                .build_next_block(1);
            wait_for(60, || {
                node.assert_running();
                Ok(process_chain_info(&node.config).is_some_and(|i| i.burn_block_height > before))
            })
            .expect("Process node did not process the burn block");
            if crate::tests::neon_integrations::get_sortition_info(&node.config).was_sortition {
                won = true;
                break;
            }
        }
        assert!(won, "Process miner never won a sortition after handover");
    }
    for round in 0..if upgrade { 2 } else { 1 } {
        if round == 1 {
            let before_upgrade = crate::tests::neon_integrations::get_chain_info(&node.config);
            node.restart(&binary_from_env("STACKS_NODE_BIN"), &bootstrap);
            node.wait_for_tip(before_upgrade.stacks_tip_height);
            let after_upgrade = crate::tests::neon_integrations::get_chain_info(&node.config);
            assert_eq!(before_upgrade.stacks_tip, after_upgrade.stacks_tip);
        }
        test_observer::clear();
        for _ in 0..3 {
            let before = crate::tests::neon_integrations::get_chain_info(&node.config);
            // A published commit is observable even in a release binary.
            wait_for_bitcoin_operation(&node.config, "54335b");
            harness
                .running_nodes
                .btc_regtest_controller
                .build_next_block(1);
            wait_for(120, || {
                node.assert_running();
                Ok(process_chain_info(&node.config)
                    .is_some_and(|i| i.stacks_tip_height > before.stacks_tip_height))
            })
            .expect("Process topology did not mine a tenure");
            node.wait_for_tip(before.stacks_tip_height + 1);
            let sortition = crate::tests::neon_integrations::get_sortition_info(&node.config);
            let tip = crate::tests::neon_integrations::get_chain_info(&node.config);
            assert_eq!(sortition.consensus_hash, tip.pox_consensus);
            let tx = stacks::core::test_util::make_stacks_transfer_serialized(
                &sender,
                get_account(
                    &format!("http://{}", node.config.node.rpc_bind),
                    &tests::to_addr(&sender),
                )
                .nonce,
                180,
                node.config.burnchain.chain_id,
                // Mempools reject transfers whose recipient is the sender.
                &tests::to_addr(&StacksPrivateKey::from_seed(
                    b"cross-version-node-recipient",
                ))
                .into(),
                100,
            );
            crate::tests::neon_integrations::submit_tx(
                &format!("http://{}", node.config.node.rpc_bind),
                &tx,
            );
            wait_for(60, || {
                Ok(
                    crate::tests::neon_integrations::get_chain_info(&node.config).stacks_tip_height
                        > tip.stacks_tip_height,
                )
            })
            .expect("Process miner must produce an interim block");
            // A block appends once 70% accept it. Let the rest answer before
            // the next burn block changes their sortition view mid-signature,
            // which would make them reject a block already in the chain.
            wait_for_signing_to_settle(&node.config, &harness.signer_test_pks());
        }
        if miner {
            check_process_tenure_extensions(&mut harness, &mut node, &sender);
        }
        assert_full_participation(&harness.signer_test_pks());
    }
    node.stop();
    crate::nakamoto_node::miner::TEST_MINE_SKIP.set(false);
    harness.shutdown();
}

#[tag(bitcoind, slow, ci_skip)]
#[ignore]
#[test]
fn baseline_miner_current_signers() {
    process_node_scenario(true, false, false);
}

#[tag(bitcoind, slow, ci_skip)]
#[ignore]
#[test]
fn baseline_follower_current_signers() {
    process_node_scenario(false, false, false);
}

#[tag(bitcoind, slow, ci_skip)]
#[ignore]
#[test]
fn node_upgrade_in_place() {
    process_node_scenario(true, true, false);
}

#[tag(bitcoind, slow, ci_skip)]
#[ignore]
#[test]
fn baseline_sanity() {
    process_node_scenario(true, false, true);
}

#[tag(bitcoind, slow, ci_skip)]
#[ignore]
#[test]
fn current_sanity() {
    USE_CURRENT_SIGNER_PROCESS.set(true);
    mixed_signer_set(10, 0);
}

#[test]
fn node_config_round_trips() {
    let (mut config, _) = crate::tests::nakamoto_integrations::naka_neon_integration_conf(None);
    shared_chain_config(&mut config);
    config.connection_options.auth_token = Some("test-password".into());
    let text = node_toml(&config, "");
    let file = stacks::config::ConfigFile::from_str(&text).unwrap();
    let reloaded = stacks::config::Config::from_config_file(file, false).unwrap();
    assert_eq!(reloaded.node.seed, config.node.seed);
    assert_eq!(
        reloaded.burnchain.get_epoch_list(),
        config.burnchain.get_epoch_list()
    );
    assert_eq!(reloaded.node.stacker_dbs, config.node.stacker_dbs);
    assert_eq!(reloaded.node.stacker, config.node.stacker);
    assert_eq!(reloaded.initial_balances, config.initial_balances);
    assert_eq!(
        reloaded.node.pox_5_sbtc_contract,
        config.node.pox_5_sbtc_contract
    );
    assert_eq!(
        reloaded.node.pox_5_sbtc_registry_contract,
        config.node.pox_5_sbtc_registry_contract
    );
}

/// Wait until Bitcoin has a pending Stacks operation. Decode the OP_RETURN
/// rather than sleeping for a guessed release miner initialization time.
fn wait_for_bitcoin_operation(config: &stacks::config::Config, prefix: &str) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let rpc = |method: &str, params: serde_json::Value| -> Option<serde_json::Value> {
        let response: serde_json::Value = client.post(format!("http://{}:{}", config.burnchain.peer_host, config.burnchain.rpc_port))
            .basic_auth(config.burnchain.username.as_ref().unwrap(), config.burnchain.password.as_ref())
            .json(&serde_json::json!({"jsonrpc":"1.0", "id":"cross-version", "method":method, "params":params}))
            .send().ok()?.json().ok()?;
        response.get("result").cloned()
    };
    wait_for(120, || {
        let Some(ids) = rpc("getrawmempool", serde_json::json!([])) else {
            return Ok(false);
        };
        let Some(ids) = ids.as_array() else {
            return Ok(false);
        };
        Ok(ids.iter().any(|id| {
            let Some(tx) = rpc("getrawtransaction", serde_json::json!([id, true])) else {
                return false;
            };
            tx["vout"].as_array().is_some_and(|outputs| {
                outputs.iter().any(|output| {
                    output["scriptPubKey"]["hex"]
                        .as_str()
                        .is_some_and(|script| script.starts_with("6a") && script.contains(prefix))
                })
            })
        }))
    })
    .expect("Bitcoin did not receive the expected Stacks operation");
}

/// Exercise both extension reasons through the release miner's normal policy,
/// using contract reads to reach its compiled read-count threshold.
fn check_process_tenure_extensions(
    harness: &mut SignerTest<CrossVersionSigner>,
    node: &mut ProcessNode,
    sender: &StacksPrivateKey,
) {
    use stacks::chainstate::stacks::{StacksTransaction, TenureChangeCause, TransactionPayload};
    // Restarting a signer while it is still validating a block makes it
    // re-check that block against fresh state and reject it after the rest
    // accepted it. Let signing settle before each batch of restarts.
    wait_for_signing_to_settle(&node.config, &harness.signer_test_pks());
    for ix in 0..harness.spawned_signers.len() {
        let mut config = harness.stop_signer(ix);
        config.tenure_idle_timeout = Duration::from_secs(30);
        harness.restart_signer(ix, config);
    }
    let wait_extension = |cause: TenureChangeCause| {
        wait_for(120, || Ok(test_observer::get_blocks().iter().any(|block| {
            block["transactions"].as_array().is_some_and(|txs| txs.iter().any(|tx| {
                let bytes = stacks_common::util::hash::hex_bytes(tx["raw_tx"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                let parsed = StacksTransaction::consensus_deserialize(&mut bytes.as_slice()).unwrap();
                matches!(parsed.payload, TransactionPayload::TenureChange(payload) if payload.cause.is_eq(&cause))
            }))
        }))).expect("Process miner did not extend its tenure");
    };
    wait_extension(TenureChangeCause::Extended);
    wait_for_signing_to_settle(&node.config, &harness.signer_test_pks());
    // Signers keep their existing databases, but advertise a long ordinary
    // idle timeout so the next extension must be caused by read-count usage.
    for ix in 0..harness.spawned_signers.len() {
        let mut config = harness.stop_signer(ix);
        config.tenure_idle_timeout = Duration::from_secs(36000);
        config.read_count_idle_timeout = Duration::from_secs(30);
        harness.restart_signer(ix, config);
    }
    let origin = format!("http://{}", node.config.node.rpc_bind);
    let address = tests::to_addr(sender);
    let nonce = get_account(&origin, &address).nonce;
    let name = format!("reads-{nonce}");
    // The miner extends on read count once a tenure uses 25% of the epoch's
    // read_count budget: 7,500 of Epoch 4.0's 30,000. 45 calls of 200
    // `map-get?` reads clear that with margin; 100 per call would not.
    let indices = (0..200)
        .map(|i| format!("u{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    let source = format!("(define-map entries uint uint) (define-read-only (lookup (i uint) (total uint)) (+ total (default-to u0 (map-get? entries i)))) (define-public (read-lots) (ok (fold lookup (list {indices}) u0)))");
    let deploy = stacks::core::test_util::make_contract_publish(
        sender,
        nonce,
        // The minimum fee scales with the contract's size.
        5000,
        node.config.burnchain.chain_id,
        &name,
        &source,
    );
    crate::tests::neon_integrations::submit_tx(&origin, &deploy);
    wait_for(60, || Ok(get_account(&origin, &address).nonce > nonce))
        .expect("Read contract must deploy");
    for offset in 1..=45 {
        let tx = stacks::core::test_util::make_contract_call(
            sender,
            nonce + offset,
            180,
            node.config.burnchain.chain_id,
            &address,
            &name,
            "read-lots",
            &[],
        );
        crate::tests::neon_integrations::submit_tx(&origin, &tx);
        if offset % 10 == 0 {
            wait_for(60, || {
                Ok(get_account(&origin, &address).nonce > nonce + offset)
            })
            .expect("Read transaction batch must confirm");
        }
    }
    wait_for(120, || {
        Ok(get_account(&origin, &address).nonce >= nonce + 46)
    })
    .expect("Read transactions must confirm");
    wait_extension(TenureChangeCause::ExtendedReadCount);
    node.assert_running();
}

/// Wait until `replica` holds the same version of every signer StackerDB slot
/// as `source`, comparing each slot's version and data hash.
fn wait_for_signer_stackerdb_replication(
    source: &stacks::config::Config,
    replica: &stacks::config::Config,
) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let slots = |config: &stacks::config::Config, contract: &QualifiedContractIdentifier| {
        let url = format!(
            "http://{}/v2/stackerdb/{}/{}",
            config.node.rpc_bind, contract.issuer, contract.name
        );
        let metadata: Vec<serde_json::Value> = client.get(url).send().ok()?.json().ok()?;
        Some(
            metadata
                .into_iter()
                .map(|slot| {
                    (
                        slot["slot_id"].clone(),
                        slot["slot_version"].clone(),
                        slot["data_hash"].clone(),
                    )
                })
                .collect::<Vec<_>>(),
        )
    };
    let signer_contracts: Vec<_> = source
        .node
        .stacker_dbs
        .iter()
        .filter(|contract| contract.name.as_str().starts_with("signers-"))
        .collect();
    let mismatches = || -> Vec<String> {
        signer_contracts
            .iter()
            .filter_map(|contract| {
                let expected = slots(source, contract);
                let actual = slots(replica, contract);
                if expected.is_some() && expected == actual {
                    return None;
                }
                let differing: Vec<_> = match (&expected, &actual) {
                    (Some(expected), Some(actual)) => expected
                        .iter()
                        .zip(actual.iter())
                        .filter(|(e, a)| e != a)
                        .map(|(e, a)| format!("slot {} source v{} replica v{}", e.0, e.1, a.1))
                        .collect(),
                    _ => vec![],
                };
                Some(format!(
                    "{}: source {} slots, replica {} slots, differing [{}]",
                    contract.name,
                    expected
                        .as_ref()
                        .map_or("unreadable".into(), |s| s.len().to_string()),
                    actual
                        .as_ref()
                        .map_or("unreadable".into(), |s| s.len().to_string()),
                    differing.join(", ")
                ))
            })
            .collect()
    };
    if wait_for(120, || Ok(mismatches().is_empty())).is_err() {
        panic!(
            "Process node did not replicate the signer StackerDB: {}",
            mismatches().join("; ")
        );
    }
}

/// A hung HTTP endpoint must not defeat the harness polling deadline.
fn process_chain_info(
    config: &stacks::config::Config,
) -> Option<stacks::net::api::getinfo::RPCPeerInfoData> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?
        .get(format!("http://{}/v2/info", config.node.rpc_bind))
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .ok()
}
