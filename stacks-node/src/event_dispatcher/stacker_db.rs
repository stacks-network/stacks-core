use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

use clarity::vm::types::QualifiedContractIdentifier;
use stacks::chainstate::stacks::boot::SIGNERS_NAME;
use stacks::chainstate::stacks::events::StackerDBChunksEvent;

/// This struct receives StackerDB event callbacks without registering
/// over the JSON/RPC interface.
pub struct StackerDBChannel {
    sender_info: Mutex<Option<InnerStackerDBChannel>>,
}

#[derive(Clone)]
struct InnerStackerDBChannel {
    /// A channel for sending the chunk events to the listener
    sender: Sender<StackerDBChunksEvent>,
    /// Does the listener want to receive `.signers` chunks?
    interested_in_signers: bool,
    /// Which StackerDB contracts is the listener interested in?
    other_interests: Vec<QualifiedContractIdentifier>,
}

impl InnerStackerDBChannel {
    pub fn new_miner_receiver() -> (Receiver<StackerDBChunksEvent>, Self) {
        let (sender, recv) = channel();
        let sender_info = Self {
            sender,
            interested_in_signers: true,
            other_interests: vec![],
        };

        (recv, sender_info)
    }
}

impl Default for StackerDBChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl StackerDBChannel {
    pub const fn new() -> Self {
        Self {
            sender_info: Mutex::new(None),
        }
    }

    /// Consume the receiver for the StackerDBChannel and drop the senders. This should be done
    /// before another interested thread can subscribe to events, but it is not absolutely necessary
    /// to do so (it would just result in temporary over-use of memory while the prior channel is still
    /// open).
    ///
    /// The StackerDBChnnel's receiver is guarded with a Mutex, so that ownership can
    /// be taken by different threads without unsafety.
    pub fn replace_receiver(&self, receiver: Receiver<StackerDBChunksEvent>) {
        // not strictly necessary, but do this rather than mark the `receiver` argument as unused
        // so that we're explicit about the fact that `replace_receiver` consumes.
        drop(receiver);
        let mut guard = self
            .sender_info
            .lock()
            .expect("FATAL: poisoned StackerDBChannel lock");
        guard.take();
    }

    /// Create a new event receiver channel for receiving events relevant to the miner coordinator,
    /// dropping the old StackerDB event sender channels if they are still registered.
    ///  Returns the new receiver channel and a bool indicating whether or not sender channels were
    ///   still in place.
    ///
    /// The StackerDBChannel senders are guarded by mutexes so that they can be replaced
    /// by different threads without unsafety.
    pub fn register_miner_coordinator(&self) -> (Receiver<StackerDBChunksEvent>, bool) {
        let mut sender_info = self
            .sender_info
            .lock()
            .expect("FATAL: poisoned StackerDBChannel lock");
        let (recv, new_sender) = InnerStackerDBChannel::new_miner_receiver();
        let replaced_receiver = sender_info.replace(new_sender).is_some();

        (recv, replaced_receiver)
    }

    /// Is there a thread holding the receiver, and is it interested in chunks events from `stackerdb`?
    /// Returns the a sending channel to broadcast the event to if so, and `None` if not.
    pub fn is_active(
        &self,
        stackerdb: &QualifiedContractIdentifier,
    ) -> Option<Sender<StackerDBChunksEvent>> {
        // if the receiver field is empty (i.e., None), then there is no listening thread, return None
        let guard = self
            .sender_info
            .lock()
            .expect("FATAL: poisoned StackerDBChannel lock");
        let sender_info = guard.as_ref()?;
        if sender_info.interested_in_signers
            && stackerdb.is_boot()
            && stackerdb.name.starts_with(SIGNERS_NAME)
        {
            return Some(sender_info.sender.clone());
        }
        if sender_info.other_interests.contains(stackerdb) {
            return Some(sender_info.sender.clone());
        }
        None
    }
}
