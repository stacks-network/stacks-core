use std;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time;

use crate::config::InitialBalance;
use crate::tests::to_addr;
use crate::Config;

use stacks::chainstate::stacks::StacksPrivateKey;
use stacks::core::StacksEpochId;
use stacks::util::hash::hex_bytes;

use super::PUBLISH_CONTRACT;
use crate::neon::RunLoop;
use crate::ConfigFile;
use stacks::vm::costs::ExecutionCost;
use std::env;
use std::io::{BufRead, BufReader};

#[derive(std::fmt::Debug)]
pub enum SubprocessError {
    SpawnFailed(String),
}

type SubprocessResult<T> = Result<T, SubprocessError>;

pub struct BitcoinCoreController {
    sub_process: Option<Child>,
    config: Config,
}

impl BitcoinCoreController {
    pub fn new(config: Config) -> BitcoinCoreController {
        BitcoinCoreController {
            sub_process: None,
            config,
        }
    }

    pub fn start_process(&mut self) -> SubprocessResult<()> {
        std::fs::create_dir_all(&self.config.get_burnchain_path_str()).unwrap();

        let mut command = Command::new("bitcoind");
        command
            .stdout(Stdio::piped())
            .arg("-regtest")
            .arg("-nodebug")
            .arg("-nodebuglogfile")
            .arg("-rest")
            .arg("-txindex=1")
            .arg("-server=1")
            .arg("-listenonion=0")
            .arg("-rpcbind=127.0.0.1")
            .arg(&format!("-port={}", self.config.burnchain.peer_port))
            .arg(&format!(
                "-datadir={}",
                self.config.get_burnchain_path_str()
            ))
            .arg(&format!("-rpcport={}", self.config.burnchain.rpc_port));

        match (
            &self.config.burnchain.username,
            &self.config.burnchain.password,
        ) {
            (Some(username), Some(password)) => {
                command
                    .arg(&format!("-rpcuser={}", username))
                    .arg(&format!("-rpcpassword={}", password));
            }
            _ => {}
        }

        eprintln!("bitcoind spawn: {:?}", command);

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Err(SubprocessError::SpawnFailed(format!("{:?}", e))),
        };

        eprintln!("bitcoind spawned, waiting for startup");
        let mut out_reader = BufReader::new(process.stdout.take().unwrap());

        let mut line = String::new();
        while let Ok(bytes_read) = out_reader.read_line(&mut line) {
            // info!("{:?}", &line);
            if bytes_read == 0 {
                return Err(SubprocessError::SpawnFailed(
                    "Bitcoind closed before spawning network".into(),
                ));
            }
            if line.contains("Done loading") {
                break;
            }
        }

        eprintln!("bitcoind startup finished");

        self.sub_process = Some(process);

        Ok(())
    }

    pub fn kill_process(&mut self) {
        if let Some(mut sub_process) = self.sub_process.take() {
            sub_process.kill().unwrap();
        }
    }
}

pub struct StacksMainchainController {
    sub_process: Option<Child>,
    config: Config,
    out_reader: Option<BufReader<std::process::ChildStdout>>,
}

impl StacksMainchainController {
    pub fn new(config: Config) -> StacksMainchainController {
        StacksMainchainController {
            sub_process: None,
            config,
            out_reader: None,
        }
    }

    pub fn start_process(&mut self) -> SubprocessResult<()> {
        //        std::fs::create_dir_all(&self.config.get_burnchain_path_str()).unwrap();

        let base_dir = env::var("STACKS_BASE_DIR").expect("couldn't read STACKS_BASE_DIR");
        let bin_file = format!("{}/target/release/stacks-node", &base_dir);
        let toml_file = format!(
            "{}/testnet/stacks-node/conf/mocknet-miner-conf.toml",
            &base_dir
        );
        let toml_content = ConfigFile::from_path(&toml_file);
        let mut command = Command::new(&bin_file);
        command
            .stdout(Stdio::piped())
            .arg("start")
            .arg("--config=".to_owned() + &toml_file);

        eprintln!("stacks-node mainchain spawn: {:?}", command);

        let mut process = match command.spawn() {
            Ok(child) => child,
            Err(e) => return Err(SubprocessError::SpawnFailed(format!("{:?}", e))),
        };

        eprintln!("stacks-node mainchain spawned, waiting for startup");
        let mut out_reader = BufReader::new(process.stdout.take().unwrap());

        let mut line = String::new();
        while let Ok(bytes_read) = out_reader.read_line(&mut line) {
            if bytes_read == 0 {
                return Err(SubprocessError::SpawnFailed(
                    "Bitcoind closed before spawning network".into(),
                ));
            }
            info!("{:?}", &line);
            break;
        }

        eprintln!("bitcoind startup finished");

        self.sub_process = Some(process);
        self.out_reader = Some(out_reader);

        Ok(())
    }

    pub fn kill_process(&mut self) {
        if let Some(mut sub_process) = self.sub_process.take() {
            sub_process.kill().unwrap();
        }
    }
}

impl Drop for BitcoinCoreController {
    fn drop(&mut self) {
        self.kill_process();
    }
}

impl Drop for StacksMainchainController {
    fn drop(&mut self) {
        self.kill_process();
    }
}

const BITCOIND_INT_TEST_COMMITS: u64 = 11000;

#[test]
fn start_two_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let base_dir = env::var("STACKS_BASE_DIR").expect("couldn't read STACKS_BASE_DIR");
    let bin_file = format!("{}/target/release/stacks-node", &base_dir);
    let toml_file = format!(
        "{}/testnet/stacks-node/conf/mocknet-miner-conf.toml",
        &base_dir
    );

    let toml_content = ConfigFile::from_path(&toml_file);

    let conf = Config::from_config_file(toml_content);

    info!("conf {:#?}", &conf);

    // Setup up a bitcoind controller
    let mut bitcoin_controller = BitcoinCoreController::new(conf.clone());
    // Start bitcoind
    let _bitcoin_res = bitcoin_controller.start_process().expect("didn't start");
    info!("done _bitcoin_res");

    let mut stacks_controller = StacksMainchainController::new(conf.clone());
    // Start stacksd
    let _stacks_res = stacks_controller.start_process().expect("didn't start");

    //    thread::sleep(time::Duration::from_millis(10000));
    {
        let mut conf = super::new_test_conf();
        let mut run_loop = RunLoop::new(conf);
        run_loop.start(None, 20);
    }

    bitcoin_controller.kill_process();
    stacks_controller.kill_process();
}
