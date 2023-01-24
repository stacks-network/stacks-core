use clap::Parser;

use stacks_signer::config::Config;
use stacks_signer::net::{HttpNet, Message, Net};

fn main() {
    let cli = Cli::parse();
    let config = Config::from_file("conf/stacker.toml").unwrap();

    let mut net: HttpNet = HttpNet::new(config.common.stacks_node_url.clone(), vec![]);

    cli.command
        .run(&mut net)
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

impl Command {
    fn run<N: Net>(&self, network: &mut N) -> Result<(), Error> {
        match self {
            Self::Dkg => self.run_distributed_key_generation(network),
            Self::Sign { msg } => self.sign_message(network, msg),
            Self::GetAggregatePublicKey => self.get_aggregate_public_key(network),
        }
    }

    fn run_distributed_key_generation<N: Net>(&self, network: &mut N) -> Result<(), Error> {
        todo!();
    }

    fn sign_message<N: Net>(&self, network: &mut N, msg: &str) -> Result<(), Error> {
        todo!();
    }

    fn get_aggregate_public_key<N: Net>(&self, network: &mut N) -> Result<(), Error> {
        todo!();
    }
}

#[derive(thiserror::Error, Debug)]
enum Error {}
