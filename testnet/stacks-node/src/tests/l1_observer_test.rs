use std;
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};

use crate::neon;
use crate::tests::neon_integrations::{get_account, submit_tx};
use crate::tests::{make_contract_publish, to_addr};
use stacks::burnchains::Burnchain;
use stacks::chainstate::stacks::StacksPrivateKey;
use stacks::vm::types::QualifiedContractIdentifier;
use std::env;
use std::io::{BufRead, BufReader};
use std::time::Duration;

#[derive(std::fmt::Debug)]
pub enum SubprocessError {
    SpawnFailed(String),
}

type SubprocessResult<T> = Result<T, SubprocessError>;

/// In charge of running L1 `stacks-node`.
pub struct StacksL1Controller {
    sub_process: Option<Child>,
    config_path: String,
    printer_handle: Option<JoinHandle<()>>,
    log_process: bool,
}

lazy_static! {
    pub static ref MOCKNET_PRIVATE_KEY_1: StacksPrivateKey = StacksPrivateKey::from_hex(
        "aaf57b4730f713cf942bc63f0801c4a62abe5a6ac8e3da10389f9ca3420b0dc701"
    )
    .unwrap();
    pub static ref MOCKNET_PRIVATE_KEY_2: StacksPrivateKey = StacksPrivateKey::from_hex(
        "0916e2eb04b5702e0e946081829cee67d3bb76e1792af506646843db9252ff4101"
    )
    .unwrap();
}

impl StacksL1Controller {
    pub fn new(config_path: String, log_process: bool) -> StacksL1Controller {
        StacksL1Controller {
            sub_process: None,
            config_path,
            printer_handle: None,
            log_process,
        }
    }

    pub fn start_process(&mut self) -> SubprocessResult<()> {
        let binary = match env::var("STACKS_BASE_DIR") {
            Err(_) => {
                // assume stacks-node is in path
                "stacks-node".into()
            }
            Ok(path) => path,
        };
        let mut command = Command::new(&binary);
        command
            .stderr(Stdio::piped())
            .arg("start")
            .arg("--config=".to_owned() + &self.config_path);

        info!("stacks-node mainchain spawn: {:?}", command);

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Err(SubprocessError::SpawnFailed(format!("{:?}", e))),
        };

        let printer_handle = if self.log_process {
            let child_out = process.stderr.take().unwrap();
            Some(thread::spawn(|| {
                let buffered_out = BufReader::new(child_out);
                for line in buffered_out.lines() {
                    let line = match line {
                        Ok(x) => x,
                        Err(e) => return,
                    };
                    println!("L1: {}", line);
                }
            }))
        } else {
            None
        };

        info!("stacks-node mainchain spawned, waiting for startup");

        self.sub_process = Some(process);
        self.printer_handle = printer_handle;

        Ok(())
    }

    pub fn kill_process(&mut self) {
        if let Some(mut sub_process) = self.sub_process.take() {
            sub_process.kill().unwrap();
        }
        if let Some(handle) = self.printer_handle.take() {
            println!("Joining print handler: {:?}", handle.join());
        }
    }
}

impl Drop for StacksL1Controller {
    fn drop(&mut self) {
        self.kill_process();
    }
}

/// This test brings up the Stacks-L1 chain in "mocknet" mode, and ensures that our listener can hear and record burn blocks
/// from the Stacks-L1 chain.
#[test]
fn l1_observer_test() {
    if env::var("STACKS_NODE_TEST") != Ok("1".into()) {
        return;
    }

    // Start Stacks L1.
    let l1_toml_file = "../../contrib/conf/stacks-l1-mocknet.toml";
    let mut stacks_l1_controller = StacksL1Controller::new(l1_toml_file.to_string(), true);
    let _stacks_res = stacks_l1_controller
        .start_process()
        .expect("stacks l1 controller didn't start");

    // Start the L2 run loop.
    let mut config = super::new_test_conf();
    config.burnchain.chain = "stacks_layer_1".to_string();
    config.burnchain.mode = "hyperchain".to_string();
    config.burnchain.rpc_ssl = false;
    config.burnchain.rpc_port = 20443;
    config.burnchain.peer_host = "127.0.0.1".into();

    let mut run_loop = neon::RunLoop::new(config.clone());
    let channel = run_loop.get_coordinator_channel().unwrap();
    thread::spawn(move || run_loop.start(None, 0));

    // Sleep to give the run loop time to listen to blocks.
    thread::sleep(Duration::from_millis(45000));

    // The burnchain should have registered what the listener recorded.
    let burnchain = Burnchain::new(
        &config.get_burn_db_path(),
        &config.burnchain.chain,
        &config.burnchain.mode,
    )
    .unwrap();
    let (_, burndb) = burnchain.open_db(true).unwrap();
    let tip = burndb
        .get_canonical_chain_tip()
        .expect("couldn't get chain tip");
    info!("burnblock chain tip is {:?}", &tip);

    // Ensure that the tip height has moved beyond height 0.
    // We check that we have moved past 3 just to establish we are reliably getting blocks.
    assert!(tip.block_height > 3);

    channel.stop_chains_coordinator();
    stacks_l1_controller.kill_process();
}

#[test]
fn l1_integration_test() {
    // running locally:
    // STACKS_BASE_DIR=~/devel/stacks-blockchain/target/release/stacks-node STACKS_NODE_TEST=1 cargo test --workspace l1_integration_test
    if env::var("STACKS_NODE_TEST") != Ok("1".into()) {
        return;
    }

    // Start Stacks L1.
    let l1_toml_file = "../../contrib/conf/stacks-l1-mocknet.toml";
    let l1_rpc_origin = "http://127.0.0.1:20443";

    let mut stacks_l1_controller = StacksL1Controller::new(l1_toml_file.to_string(), false);
    let _stacks_res = stacks_l1_controller
        .start_process()
        .expect("stacks l1 controller didn't start");

    // Start the L2 run loop.
    let mut config = super::new_test_conf();
    config.node.mining_key = Some(MOCKNET_PRIVATE_KEY_2.clone());
    let miner_account = to_addr(&MOCKNET_PRIVATE_KEY_2);

    config.burnchain.chain = "stacks_layer_1".to_string();
    config.burnchain.mode = "hyperchain".to_string();
    config.burnchain.rpc_ssl = false;
    config.burnchain.rpc_port = 20443;
    config.burnchain.peer_host = "127.0.0.1".into();
    config.node.wait_time_for_microblocks = 10_000;
    config.node.rpc_bind = "127.0.0.1:30443".into();
    config.node.p2p_bind = "127.0.0.1:30444".into();
    let l2_rpc_origin = format!("http://{}", &config.node.rpc_bind);

    config.burnchain.contract_identifier = QualifiedContractIdentifier::new(
        to_addr(&MOCKNET_PRIVATE_KEY_1).into(),
        "hyperchain-controller".into(),
    );

    config.node.miner = true;

    let mut run_loop = neon::RunLoop::new(config.clone());
    let channel = run_loop.get_coordinator_channel().unwrap();
    thread::spawn(move || run_loop.start(None, 0));

    // Sleep to give the L1 chain time to start
    thread::sleep(Duration::from_millis(10_000));

    // Publish the default hyperchains contract on the L1 chain
    let contract_content = include_str!("../../../../core-contracts/contracts/hyperchains.clar");
    let hc_contract_publish = make_contract_publish(
        &MOCKNET_PRIVATE_KEY_1,
        0,
        1_000_000,
        config.burnchain.contract_identifier.name.as_str(),
        &contract_content,
    );

    submit_tx(l1_rpc_origin, &hc_contract_publish);

    println!("Submitted contract!");

    // Sleep to give the run loop time to listen to blocks,
    //  and start mining L2 blocks
    thread::sleep(Duration::from_millis(60000));

    // The burnchain should have registered what the listener recorded.
    let burnchain = Burnchain::new(
        &config.get_burn_db_path(),
        &config.burnchain.chain,
        &config.burnchain.mode,
    )
    .unwrap();
    let (_, burndb) = burnchain.open_db(true).unwrap();
    let tip = burndb
        .get_canonical_chain_tip()
        .expect("couldn't get chain tip");
    info!("burnblock chain tip is {:?}", &tip);

    // Ensure that the tip height has moved beyond height 0.
    // We check that we have moved past 3 just to establish we are reliably getting blocks.
    assert!(tip.block_height > 3);

    eprintln!("Miner account: {}", miner_account);

    // test the miner's nonce has incremented: this shows that L2 blocks have
    //  been mined (because the coinbase transactions bump the miner's nonce)
    let account = get_account(&l2_rpc_origin, &miner_account);
    assert_eq!(account.balance, 0);
    assert!(
        account.nonce >= 2,
        "Miner should have produced at least 2 coinbase transactions"
    );

    channel.stop_chains_coordinator();
    stacks_l1_controller.kill_process();
}
