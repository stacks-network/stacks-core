use std::collections::HashMap;
use std::convert::From;
use std::fs;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use stacks::burnchains::stacks::{AppChainClient, AppChainConfig};
use stacks::burnchains::Burnchain;
use stacks::burnchains::BurnchainParameters;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::types::chainstate::BurnchainHeaderHash;
use stacks::types::chainstate::StacksAddress;
use stacks::util::sleep_ms;
use stacks::util_lib::strings::StacksString;
use stacks::vm::ContractName;

use crate::config::BurnchainConfig;
use crate::config::Config;
use crate::config::InitialBalance;
use crate::BitcoinRegtestController;
use crate::BurnchainController;
use crate::StacksController;

#[derive(Clone, Debug, Deserialize)]
pub struct AppchainRuntime {
    pub config: AppChainConfig,
    pub boot_code: Vec<(ContractName, StacksString)>,
}

impl Config {
    pub fn describes_appchain(&self) -> bool {
        self.burnchain.appchain_runtime.is_some()
    }

    /// NOTE: may stall forever
    pub fn boot_into_appchain(
        &mut self,
        available_boot_code: &HashMap<ContractName, StacksString>,
    ) {
        let appchain_runtime = self
            .burnchain
            .download_appchain_runtime(&self, available_boot_code);

        // patch config with runtime
        self.burnchain.appchain_runtime = Some(appchain_runtime.clone());
        self.burnchain.chain_id = appchain_runtime.config.chain_id();

        self.node.set_bootstrap_nodes(
            appchain_runtime
                .config
                .boot_nodes()
                .iter()
                .map(|((boot_node_pubkey, boot_node_p2p_addr), _)| {
                    format!("{}@{}", &boot_node_pubkey.to_hex(), &boot_node_p2p_addr)
                })
                .collect(),
            appchain_runtime.config.chain_id(),
            self.burnchain.peer_version,
        );

        for node in self.node.bootstrap_node.iter_mut() {
            node.addr.network_id = self.burnchain.chain_id;
        }

        if self.initial_balances.len() > 0 {
            warn!("Appchain config overrides initial balances");
        }
        self.initial_balances = appchain_runtime
            .config
            .initial_balances()
            .into_iter()
            .map(|(principal, amount)| InitialBalance {
                address: principal,
                amount: amount,
            })
            .collect();

        assert!(self.describes_appchain());
    }

    pub fn get_burnchain_genesis_info(&self) -> (u64, BurnchainHeaderHash, u64) {
        if let Some(appchain_runtime) = self.burnchain.appchain_runtime.as_ref() {
            // burnchain is another Stacks chain
            let appchain_start_block_height = appchain_runtime.config.start_block();
            let appchain_start_block_hash = appchain_runtime.config.start_block_hash();
            (appchain_start_block_height, appchain_start_block_hash, 0)
        } else {
            // burnchain is Bitcoin
            let (network, _) = self.burnchain.get_bitcoin_network();
            let burnchain_params =
                BurnchainParameters::from_params(&self.burnchain.chain, &network)
                    .expect("Bitcoin network unsupported");

            (
                burnchain_params.first_block_height,
                burnchain_params.first_block_hash,
                burnchain_params.first_block_timestamp as u64,
            )
        }
    }
}

impl BurnchainConfig {
    /// NOTE: may stall forever
    fn download_appchain_runtime(
        &self,
        config: &Config,
        available_boot_code: &HashMap<ContractName, StacksString>,
    ) -> AppchainRuntime {
        let burnchain_mode = &self.mode;

        // this is an appchain. boot off the mining contract
        if let Some(contract_id) = self.mining_contract.as_ref() {
            let issuer_addr = StacksAddress::from(contract_id.issuer.clone());

            // issuer must be consistent with mainnet/testnet|regtest mode
            if burnchain_mode == "mainnet" && !issuer_addr.is_mainnet() {
                panic!(
                    "Invalid mining contract identifier `{}`: not a mainnet address",
                    &contract_id
                );
            } else if issuer_addr.is_mainnet() {
                panic!(
                    "Invalid mining contract identifier `{}`: is a mainnet address",
                    &contract_id
                );
            }

            // boot the app chain to learn the configuration data
            let working_dir = config.get_burnchain_path();
            if fs::metadata(&working_dir).is_err() {
                fs::create_dir_all(&working_dir).expect(&format!(
                    "Failed to set up working directory `{:?}`",
                    &working_dir
                ));
            }
            let headers_path = config.get_spv_headers_file_path();

            // spin up the appchain and get its config and (missing) boot code
            let mut appchain_client = AppChainClient::new(
                burnchain_mode.as_str() == "mainnet",
                &headers_path,
                self.chain_id,
                (self.peer_host.as_str(), self.rpc_port),
                contract_id.clone(),
                self.magic_bytes.clone(),
                self.genesis_hash.clone(),
                None,
            );

            loop {
                match appchain_client.bootup(available_boot_code) {
                    Ok(_) => {
                        break;
                    }
                    Err(e) => {
                        warn!("Appchain bootup failed: {:?}; try again in 30s", &e);
                        sleep_ms(30_000);
                    }
                }
            }

            let boot_code = appchain_client
                .get_boot_code()
                .expect("BUG: appchain booted but not all boot code was obtained");

            let appchain_config = appchain_client.config.clone().expect(&format!(
                "FATAL: no appchain config discovered from `{}'",
                &contract_id
            ));
            AppchainRuntime {
                config: appchain_config,
                boot_code,
            }
        } else {
            panic!("Attempted to run an appchain without `mining_contract` set");
        }
    }
}

pub fn make_burnchain_submitter(config: Config) -> Box<dyn BurnchainController> {
    let is_appchain = config.describes_appchain();
    let burnchain_controller: Box<dyn BurnchainController> = if is_appchain {
        Box::new(
            StacksController::new_submitter(config.clone())
                .map_err(|e| {
                    error!(
                        "FATAL: failed to instantiate Stacks transaction submitter: {:?}",
                        &e
                    );
                    panic!();
                })
                .unwrap(),
        )
    } else {
        Box::new(BitcoinRegtestController::new_dummy(config.clone()))
    };

    burnchain_controller
}

pub fn make_burnchain_client(
    config: Config,
    burnchain_opt: Option<Burnchain>,
    coordinator_senders: CoordinatorChannels,
    should_keep_running: Arc<AtomicBool>,
) -> Box<dyn BurnchainController> {
    let burnchain_client: Box<dyn BurnchainController> = if config.describes_appchain() {
        let mut appchain_controller =
            StacksController::new(config, coordinator_senders, should_keep_running)
                .expect("BUG: failed to instantiate Stacks controller");
        appchain_controller
            .bootup()
            .expect("FATAL: failed to boot up appchain controller");
        Box::new(appchain_controller)
    } else {
        Box::new(BitcoinRegtestController::with_burnchain(
            config,
            Some(coordinator_senders),
            burnchain_opt,
            Some(should_keep_running),
        ))
    };
    burnchain_client
}
