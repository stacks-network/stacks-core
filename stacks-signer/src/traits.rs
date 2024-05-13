use std::fmt::{Debug, Display};
use std::sync::mpsc::Sender;

use clarity::codec::StacksMessageCodec;
use libsigner::SignerEvent;
use wsts::state_machine::OperationResult;

use crate::client::StacksClient;
use crate::config::SignerConfig;
use crate::runloop::RunLoopCommand;

/// A trait which provides a common `Signer` interface for `v1` and `v2`
pub trait Signer<T: StacksMessageCodec + Clone + Debug>: Debug + Display {
    /// Create a new `Signer` instance
    fn new(config: SignerConfig) -> Self;
    /// Update the `Signer` instance's next reward cycle data with the latest `SignerConfig`
    fn update_next_signer_data(&mut self, next_signer_config: &SignerConfig);
    /// Get the reward cycle of the signer
    fn reward_cycle(&self) -> u64;
    /// Process an event
    fn process_event(
        &mut self,
        stacks_client: &StacksClient,
        event: Option<&SignerEvent<T>>,
        res: Sender<Vec<OperationResult>>,
        current_reward_cycle: u64,
    );
    /// Process a command
    fn process_command(
        &mut self,
        stacks_client: &StacksClient,
        current_reward_cycle: u64,
        command: Option<RunLoopCommand>,
    );
}
