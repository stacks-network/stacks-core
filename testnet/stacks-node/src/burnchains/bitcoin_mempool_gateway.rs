

enum OngoingOperationState {

}

enum BitcoinMempoolGatewayError {
    OperationInProgress,
    OperationOutdated,
}

struct OngoingOperation {
    operation_type: BlockstackOperationType,
    state: OngoingOperationState,
    attempt: u64,
}

impl OngoingOperation {
    fn new(operation: BlockstackOperationType) -> OngoingOperation {
        OngoingOperation {
            operation_type,
            state: OngoingOperationState::Preparing,
            attempt: 0,        
        }
    }
}

struct BitcoinMempoolGateway {
    ongoing_operation: Option<OngoingOperation>
}

impl BitcoinMempoolGateway {

    fn submit_operation(operation: BlockstackOperationType) -> Result<bool, BitcoinMempoolGatewayError> {
        // Before going further, let's sync the burnchain
        self.sync();

        // Was the operation built with knowledge of the burnchain chain tip
        if operation.consensus_hash != self.burnchain_chain_tip.consensus_hash {
            return Err(BitcoinMempoolGatewayError::OperationOutdated)
        }

        // Are we currently tracking an operation?
        let ongoing_operation = match self.ongoing_operation.take() {
            Some(op) => op,
            None => {
                let operation = OngoingOperation::new(operation);
                let res = self.process_operation(operation);
                return res;
            }
        };

        // An ongoing operation is still inflight, the desired behaviour is the following:
        // If the ongoing and the incoming operation are **strictly** identical, we will be idempotent and discard the incoming.
        // If the 2 operations are different, we will try to avoid wasting UTXOs, and attempt to RBF the outgoing transaction:
        // -> If UTXOs initially used are sufficient for paying for a fee bump, then RBF.
        // -> If UTXOs are insufficient,
        //   -> If we have some other available UTXO, drop the ongoing operation, and track the new one. 
        //   -> Else, we'll have to wait on that ongoing operation to be mined before resuming operation.


    }

    fn sync() {

    }

    fn process_operation(operation: OngoingOperation) -> Result<bool, BitcoinMempoolGatewayError> {
        
    }
}

// fn submit_operation(
//     &mut self,
//     operation: BlockstackOperationType,
//     op_signer: &mut BurnchainOpSigner,
//     attempt: u64,
// ) -> bool {


// BitcoinOperationState 