use clap::Parser;
use hashbrown::HashSet;
use slog::slog_info;

use stacks_common::info;
use stacks_signer::config::Config;
use stacks_signer::net::{HttpNet, HttpNetError, HttpNetListen, Message, NetListen};
use stacks_signer::signing_round::{DkgBegin, MessageTypes, NonceRequest};

const DEVNET_COORDINATOR_ID: usize = 0;
const DEVNET_COORDINATOR_DKG_ID: u64 = 0; //TODO: Remove, this is a correlation id

fn main() {
    let cli = Cli::parse();
    let config = Config::from_file("conf/stacker.toml").unwrap();

    let net: HttpNet = HttpNet::new(config.common.stacks_node_url.clone());
    let net_listen: HttpNetListen = HttpNetListen::new(net, vec![]);
    let mut coordinator = Coordinator::new(
        DEVNET_COORDINATOR_ID,
        DEVNET_COORDINATOR_DKG_ID,
        config.common.total_signers,
        net_listen,
    );

    coordinator
        .run(&cli.command)
        .expect("Failed to execute command");
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    Dkg,
    Sign { msg: String },
    GetAggregatePublicKey,
}

#[derive(Debug)]
struct Coordinator<Network: NetListen> {
    id: u64, // Used for relay coordination
    current_dkg_id: u64,
    total_signers: usize, // Assuming the signers cover all id:s in {1, 2, ..., total_signers}
    network: Network,
}

impl<Network: NetListen> Coordinator<Network> {
    fn new(id: usize, dkg_id: u64, total_signers: usize, network: Network) -> Self {
        Self {
            id: id as u64,
            current_dkg_id: dkg_id,
            total_signers,
            network,
        }
    }
}

impl<Network: NetListen> Coordinator<Network>
where
    Error: From<Network::Error>,
{
    pub fn run(&mut self, command: &Command) -> Result<(), Error> {
        match command {
            Command::Dkg => self.run_distributed_key_generation(),
            Command::Sign { msg } => self.sign_message(msg),
            Command::GetAggregatePublicKey => self.get_aggregate_public_key(),
        }
    }

    pub fn run_distributed_key_generation(&mut self) -> Result<(), Error> {
        self.current_dkg_id += 1;
        info!("Starting DKG round #{}", self.current_dkg_id);
        let dkg_begin_message = Message {
            msg: MessageTypes::DkgBegin(DkgBegin {
                dkg_id: self.current_dkg_id,
            }),
            sig: [0; 32],
        };

        self.network.send_message(dkg_begin_message)?;

        let result = self.wait_for_dkg_end();
        info!("DKG round #{} finished", self.current_dkg_id);
        result
    }

    pub fn sign_message(&mut self, _msg: &str) -> Result<(), Error> {
        let nonce_request_message = Message {
            msg: MessageTypes::NonceRequest(NonceRequest { dkg_id: 0 }),
            sig: [0; 32],
        };

        self.network.send_message(nonce_request_message)?;

        todo!();
    }

    pub fn get_aggregate_public_key(&mut self) -> Result<(), Error> {
        todo!();
    }

    fn wait_for_dkg_end(&mut self) -> Result<(), Error> {
        let mut ids_to_await: HashSet<usize> = (1..=self.total_signers).collect();
        info!(
            "DKG round #{} started. Waiting for DkgEnd from signers {:?}",
            self.current_dkg_id, ids_to_await
        );
        loop {
            match (ids_to_await.len(), self.wait_for_next_message()?.msg) {
                (0, _) => return Ok(()),
                (_, MessageTypes::DkgEnd(dkg_end_msg)) => {
                    ids_to_await.remove(&dkg_end_msg.signer_id);
                    info!(
                        "DKG_End round #{} from signer #{}. Waiting on {:?}",
                        dkg_end_msg.dkg_id, dkg_end_msg.signer_id, ids_to_await
                    );
                }
                (_, _) => {
                    info!("wait for dkg catchall");
                    ()},
            }
            info!("wait for dkg bottom loop")
        }
    }

    fn wait_for_next_message(&mut self) -> Result<Message, Error> {
        let get_next_message = || {
            self.network.poll(self.id);
            self.network
                .next_message()
                .ok_or("No message yet".to_owned())
                .map_err(backoff::Error::transient)
        };

        let notify = |_err, dur| {
            info!("No message. Next poll in {:?}", dur);
        };

        backoff::retry_notify(
            backoff::ExponentialBackoff::default(),
            get_next_message,
            notify,
        )
        .map_err(|_| Error::Timeout)
    }
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("Http network error: {0}")]
    NetworkError(#[from] HttpNetError),

    #[error("Operation timed out")]
    Timeout,
}
