use burnchains::BurnchainHeaderHash;
use chainstate::burn::BlockHeaderHash;
use chainstate::stacks::{
    StacksTransaction,
    db::StacksChainState,
    db::blocks::MemPoolRejection
};
use std::io::Read;

pub struct MempoolAdmitter {
    // mempool admission should have its own chain state view.
    //   the mempool admitter interacts with the chain state
    //   exclusively in read-only fashion, however, it should have
    //   its own instance of things like the MARF index, because otherwise
    //   mempool admission tests would block with chain processing.
    chainstate: StacksChainState,
    cur_block: BlockHeaderHash,
    cur_burn_block: BurnchainHeaderHash,
}

impl MempoolAdmitter {
    pub fn new(chainstate: StacksChainState, cur_block: BlockHeaderHash, cur_burn_block: BurnchainHeaderHash) -> MempoolAdmitter {
        MempoolAdmitter { chainstate, cur_block, cur_burn_block }
    }

    pub fn set_block(&mut self, cur_block: &BlockHeaderHash, cur_burn_block: &BurnchainHeaderHash) {
        self.cur_burn_block = cur_burn_block.clone();
        self.cur_block = cur_block.clone();
    }

    pub fn will_admit_tx<R: Read>(&mut self, tx: &mut R) -> Result<StacksTransaction, MemPoolRejection> {
        self.chainstate.will_admit_mempool_tx(&self.cur_burn_block, &self.cur_block, tx)
    }
}

#[cfg(test)]
mod tests {
    use vm::tests::integrations::*;
    use vm::{
        database::HeadersDB,
        types::QualifiedContractIdentifier,
        Value, ClarityName, ContractName, errors::RuntimeErrorType, errors::Error as ClarityError };
    use chainstate::burn::{VRFSeed, BlockHeaderHash};
    use burnchains::Address;
    use address::AddressHashMode;
    use net::{Error as NetError, StacksMessageCodec};
    use util::{log, secp256k1::MessageSignature, strings::StacksString, hash::hex_bytes, hash::to_hex, hash::Sha512Trunc256Sum};

    use chainstate::stacks::{
        Error as ChainstateError,
        db::blocks::MemPoolRejection, db::StacksChainState, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        StacksMicroblockHeader, StacksPrivateKey, TransactionSpendingCondition, TransactionAuth, TransactionVersion,
        StacksPublicKey, TransactionPayload, StacksTransactionSigner,
        TokenTransferMemo, CoinbasePayload,
        StacksTransaction, TransactionSmartContract, TransactionContractCall, StacksAddress };

    use util::db::{DBConn, FromRow};
    use testnet;
    use testnet::mem_pool::MemPool;

    const FOO_CONTRACT: &'static str = "(define-public (foo) (ok 1))
                                        (define-public (bar (x uint)) (ok x))";
    const SK_1: &'static str = "a1289f6438855da7decf9b61b852c882c398cff1446b2a0f823538aa2ebef92e01";
    const SK_2: &'static str = "4ce9a8f7539ea93753a36405b16e8b57e15a552430410709c2b6d65dca5c02e201";
    const SK_3: &'static str = "cb95ddd0fe18ec57f4f3533b95ae564b3f1ae063dbf75b46334bd86245aef78501";

    pub fn make_bad_stacks_transfer(sender: &StacksPrivateKey, nonce: u64, fee_rate: u64,
                                    recipient: &StacksAddress, amount: u64) -> Vec<u8> {
        let payload = TransactionPayload::TokenTransfer(recipient.clone(), amount, TokenTransferMemo([0; 34]));

        let mut spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(StacksPublicKey::from_private(sender))
            .expect("Failed to create p2pkh spending condition from public key.");
        spending_condition.set_nonce(nonce);
        spending_condition.set_fee_rate(fee_rate);
        let auth = TransactionAuth::Standard(spending_condition);
        let unsigned_tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);
        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);

        tx_signer.sign_origin(&StacksPrivateKey::new()).unwrap();

        let mut buf = vec![];
        tx_signer.get_tx().unwrap().consensus_serialize(&mut buf).unwrap();
        buf
    }


    #[test]
    fn mempool_setup_chainstate() {
        let mut conf = testnet::tests::new_test_conf();

        conf.burnchain_block_time = 1500;

        let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
        let contract_addr = to_addr(&contract_sk);

        let num_rounds = 4;

        let mut run_loop = testnet::RunLoop::new_with_boot_exec(conf, |clarity_tx| {
            // lets dole out some stacks.
            clarity_tx.connection().with_clarity_db(|db| {
                db.set_account_stx_balance(&contract_addr.clone().into(), 100000);
                Ok(())
            }).unwrap();
        });

        run_loop.apply_on_new_tenures(|round, tenure| {
            let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
            if round == 0 { // block-height = 2
                let publish_tx = make_contract_publish(&contract_sk, 0, 100, "foo_contract", FOO_CONTRACT);
                eprintln!("Tenure in 1 started!");
                tenure.mem_pool.submit(publish_tx);
            }
        });

        run_loop.apply_on_new_chain_states(|round, ref mut chainstate, bhh| {
            let contract_sk = StacksPrivateKey::from_hex(SK_1).unwrap();
            let contract_addr = to_addr(&contract_sk);

            let other_sk =  StacksPrivateKey::from_hex(SK_2).unwrap();
            let other_addr = to_addr(&other_sk);

            if round == 3 {
                let block_header = StacksChainState::get_stacks_block_header_info_by_index_block_hash(
                    &mut chainstate.headers_db, bhh)
                    .unwrap().unwrap();
                let burn_hash = &block_header.burn_header_hash;
                let block_hash = &block_header.anchored_header.block_hash();

                // let's throw some transactions at it.
                // first a couple valid ones:
                let tx = make_contract_publish(&contract_sk, 1, 1000, "bar_contract", FOO_CONTRACT);
                chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap();

                let tx = make_contract_call(&contract_sk, 1, 200, &contract_addr, "foo_contract", "bar", &[Value::UInt(1)]);
                chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap();

                let tx = make_stacks_transfer(&contract_sk, 1, 200, &other_addr, 1000);
                chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap();

                // now invalid ones.
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut vec![0u8, 0u8, 0u8, 0u8].as_slice()).unwrap_err();
                assert!(if let MemPoolRejection::DeserializationFailure(_) = e { true } else { false });

                // bad signature
                let tx = make_bad_stacks_transfer(&contract_sk, 1, 200, &other_addr, 1000);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err();
                eprintln!("Err: {:?}", e);
                assert!(if let
                        MemPoolRejection::FailedToValidate(
                            ChainstateError::NetError(NetError::VerifyingError(_))) = e { true } else { false });

                // bad fees
                let tx = make_stacks_transfer(&contract_sk, 1, 0, &other_addr, 1000);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::FeeTooLow(0, _) = e { true } else { false });

                // bad nonce
                let tx = make_stacks_transfer(&contract_sk, 0, 200, &other_addr, 1000);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::BadNonces(_) = e { true } else { false });

                // not enough funds
                let tx = make_stacks_transfer(&contract_sk, 1, 110000, &other_addr, 1000);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NotEnoughFunds(110000, 99900) = e { true } else { false });

                let tx = make_stacks_transfer(&contract_sk, 1, 99900, &other_addr, 1000);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NotEnoughFunds(100900, 99900) = e { true } else { false });

                let tx = make_contract_call(&contract_sk, 1, 200, &contract_addr, "bar_contract", "bar", &[Value::UInt(1)]);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NoSuchContract = e { true } else { false });

                let tx = make_contract_call(&contract_sk, 1, 200, &contract_addr, "foo_contract", "foobar", &[Value::UInt(1)]);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NoSuchPublicFunction = e { true } else { false });

                let tx = make_contract_call(&contract_sk, 1, 200, &contract_addr, "foo_contract", "bar", &[Value::UInt(1), Value::Int(2)]);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::BadFunctionArgument(_) = e { true } else { false });

                let tx = make_contract_publish(&contract_sk, 1, 1000, "foo_contract", FOO_CONTRACT);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::ContractAlreadyExists(_) = e { true } else { false });

                let microblock_1 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                    signature: MessageSignature([0; 65])
                };

                let microblock_2 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 1,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                    signature: MessageSignature([0; 65])
                };

                let tx = make_poison(&contract_sk, 1, 1000, microblock_1, microblock_2);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::PoisonMicroblocksDoNotConflict = e { true } else { false });

                let microblock_1 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                    signature: MessageSignature([0; 65])
                };

                let microblock_2 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: BlockHeaderHash([0; 32]),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[1,2,3]),
                    signature: MessageSignature([0; 65])
                };

                let tx = make_poison(&contract_sk, 1, 1000, microblock_1, microblock_2);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NoSuchAnchoredBlock(_) = e { true } else { false });

                let microblock_1 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: block_hash.clone(),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[]),
                    signature: MessageSignature([0; 65])
                };

                let microblock_2 = StacksMicroblockHeader {
                    version: 0,
                    sequence: 0,
                    prev_block: block_hash.clone(),
                    tx_merkle_root: Sha512Trunc256Sum::from_data(&[1,2,3]),
                    signature: MessageSignature([0; 65])
                };

                let tx = make_poison(&contract_sk, 1, 1000, microblock_1, microblock_2);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::InvalidMicroblocks = e { true } else { false });


                let tx = make_coinbase(&contract_sk, 1, 1000);
                let e = chainstate.will_admit_mempool_tx(burn_hash, block_hash, &mut tx.as_slice()).unwrap_err(); 
                eprintln!("Err: {:?}", e);
                assert!(if let MemPoolRejection::NoCoinbaseViaMempool = e { true } else { false });

            }
        });

        run_loop.start(num_rounds);
    }
}
