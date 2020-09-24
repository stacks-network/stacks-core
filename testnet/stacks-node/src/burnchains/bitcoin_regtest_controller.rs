use std::io::Cursor;
use async_std::io::ReadExt;
use std::time::Instant;

use async_h1::{client};
use async_std::net::{TcpStream};
use http_types::{Method, Request, Url};
use base64::{encode};

use serde::{Serialize};
use serde_json::value::RawValue;

use super::{BurnchainController, BurnchainTip, Error as BurnchainControllerError};
use super::super::operations::BurnchainOpSigner;
use super::super::Config;

use stacks::burnchains::BurnchainStateTransitionOps;
use stacks::burnchains::Burnchain;
use stacks::burnchains::db::BurnchainDB;
use stacks::burnchains::Error as burnchain_error;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::bitcoin::address::{BitcoinAddress, BitcoinAddressType};
use stacks::burnchains::bitcoin::indexer::{BitcoinIndexer, BitcoinIndexerRuntime, BitcoinIndexerConfig};
use stacks::burnchains::bitcoin::spv::SpvClient; 
use stacks::burnchains::PublicKey;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::{
    LeaderBlockCommitOp,
    LeaderKeyRegisterOp,
    UserBurnSupportOp,
    BlockstackOperationType,
    leader_block_commit::OUTPUTS_PER_COMMIT,
};
use stacks::deps::bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut, OutPoint};
use stacks::deps::bitcoin::blockdata::opcodes;
use stacks::deps::bitcoin::blockdata::script::{Script, Builder};
use stacks::deps::bitcoin::network::encodable::ConsensusEncodable;
use stacks::deps::bitcoin::network::serialize::RawEncoder;
use stacks::deps::bitcoin::util::hash::Sha256dHash;
use stacks::net::StacksMessageCodec;
use stacks::util::hash::{Hash160, hex_bytes};
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::util::sleep_ms;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;

use stacks::monitoring::{
    increment_btc_blocks_received_counter, 
    increment_btc_ops_sent_counter
};

pub struct BitcoinRegtestController {
    config: Config,
    indexer_config: BitcoinIndexerConfig,
    db: Option<SortitionDB>,
    burnchain_db: Option<BurnchainDB>,
    chain_tip: Option<BurnchainTip>,
    use_coordinator: Option<CoordinatorChannels>,
}

const DUST_UTXO_LIMIT: u64 = 5500;

impl BitcoinRegtestController {
    pub fn new(config: Config, coordinator_channel: Option<CoordinatorChannels>) -> Self {
        std::fs::create_dir_all(&config.node.get_burnchain_path())
            .expect("Unable to create workdir");
    
        let res = SpvClient::new(&config.burnchain.spv_headers_path, 0, None, config.burnchain.get_bitcoin_network().1, true, false);
        if let Err(err) = res {
            error!("Unable to init block headers: {}", err);
            panic!()
        }

        let indexer_config = {
            let burnchain_config = config.burnchain.clone();
            BitcoinIndexerConfig {
                peer_host: burnchain_config.peer_host,
                peer_port: burnchain_config.peer_port,
                rpc_port: burnchain_config.rpc_port,
                rpc_ssl: burnchain_config.rpc_ssl,
                username: burnchain_config.username,
                password: burnchain_config.password,
                timeout: burnchain_config.timeout,
                spv_headers_path: burnchain_config.spv_headers_path,
                first_block: burnchain_config.first_block,
                magic_bytes: burnchain_config.magic_bytes
            }
        };
                
        Self {
            use_coordinator: coordinator_channel,
            config: config,
            indexer_config,
            db: None,
            burnchain_db: None,
            chain_tip: None,
        }
    }

    /// create a dummy bitcoin regtest controller.
    ///   used just for submitting bitcoin ops.
    pub fn new_dummy(config: Config) -> Self {
        let indexer_config = {
            let burnchain_config = config.burnchain.clone();
            BitcoinIndexerConfig {
                peer_host: burnchain_config.peer_host,
                peer_port: burnchain_config.peer_port,
                rpc_port: burnchain_config.rpc_port,
                rpc_ssl: burnchain_config.rpc_ssl,
                username: burnchain_config.username,
                password: burnchain_config.password,
                timeout: burnchain_config.timeout,
                spv_headers_path: burnchain_config.spv_headers_path,
                first_block: burnchain_config.first_block,
                magic_bytes: burnchain_config.magic_bytes
            }
        };
                
        Self {
            use_coordinator: None,
            config: config,
            indexer_config,
            db: None,
            burnchain_db: None,
            chain_tip: None,
        }        
    }

    fn setup_burnchain(&self) -> (Burnchain, BitcoinNetworkType) {
        let (network_name, network_type) = self.config.burnchain.get_bitcoin_network();
        let working_dir = self.config.get_burn_db_path();
        match Burnchain::new(&working_dir, &self.config.burnchain.chain, &network_name) {
            Ok(burnchain) => (burnchain, network_type),
            Err(e) => {
                error!("Failed to instantiate burnchain: {}", e);
                panic!()    
            }
        }
    }

    fn setup_indexer_runtime(&mut self) -> (Burnchain, BitcoinIndexer) {
        let (burnchain, network_type) = self.setup_burnchain();

        let indexer_runtime = BitcoinIndexerRuntime::new(network_type);
        let burnchain_indexer = BitcoinIndexer {
            config: self.indexer_config.clone(),
            runtime: indexer_runtime
        };
        (burnchain, burnchain_indexer)
    }

    fn receive_blocks_helium(&mut self) -> BurnchainTip {
        let (mut burnchain, mut burnchain_indexer) = self.setup_indexer_runtime();

        let (block_snapshot, state_transition) = loop {
            match burnchain.sync_with_indexer_deprecated(&mut burnchain_indexer) {
                Ok(x) => {
                    break x;
                }
                Err(e) => {
                    // keep trying
                    error!("Unable to sync with burnchain: {}", e);
                    match e {
                        burnchain_error::TrySyncAgain => {
                            // try again immediately
                            continue;
                        },
                        burnchain_error::BurnchainPeerBroken => {
                            // remote burnchain peer broke, and produced a shorter blockchain fork.
                            // just keep trying
                            sleep_ms(5000);
                            continue;
                        },
                        _ => {
                            // delay and try again
                            sleep_ms(5000);
                            continue;
                        }
                    }
                }
            }
        };

        let rest = match (state_transition, &self.chain_tip) {
            (None, Some(chain_tip)) => chain_tip.clone(),
            (Some(state_transition), _) => {
                let burnchain_tip = BurnchainTip {
                    block_snapshot: block_snapshot,
                    state_transition: BurnchainStateTransitionOps::from(state_transition),
                    received_at: Instant::now()
                };
                self.chain_tip = Some(burnchain_tip.clone());
                burnchain_tip
            },
            (None, None) => {
                // can happen at genesis
                let burnchain_tip = BurnchainTip {
                    block_snapshot: block_snapshot,
                    state_transition: BurnchainStateTransitionOps::noop(),
                    received_at: Instant::now()
                };
                self.chain_tip = Some(burnchain_tip.clone());
                burnchain_tip
            }
        };

        debug!("Done receiving blocks");
        rest
    }

    fn receive_blocks(&mut self, sync: bool) -> Result<BurnchainTip, BurnchainControllerError> {
        let coordinator_comms = match self.use_coordinator.as_ref() {
            Some(x) => x.clone(),
            None => return Ok(self.receive_blocks_helium())
        };

        let (mut burnchain, mut burnchain_indexer) = self.setup_indexer_runtime();
        let (block_snapshot, state_transition) = loop {
            match burnchain.sync_with_indexer(&mut burnchain_indexer, coordinator_comms.clone()) {
                Ok(x) => {
                    increment_btc_blocks_received_counter();
                    // initialize the dbs...
                    self.sortdb_mut();
                    if sync {
                        self.wait_for_sortitions(Some(x.block_height));
                    }
                    let sort_tip = SortitionDB::get_canonical_sortition_tip(self.sortdb_ref().conn())
                        .expect("Sortition DB error.");
                    let x = self.sortdb_ref().get_sortition_result(&sort_tip)
                        .expect("Sortition DB error.")
                        .expect("BUG: no data for the canonical chain tip");
                    break x;
                }
                Err(e) => {
                    // keep trying
                    error!("Unable to sync with burnchain: {}", e);
                    match e {
                        burnchain_error::CoordinatorClosed => {
                            return Err(BurnchainControllerError::CoordinatorClosed)
                        },
                        burnchain_error::TrySyncAgain => {
                            // try again immediately
                            continue;
                        },
                        burnchain_error::BurnchainPeerBroken => {
                            // remote burnchain peer broke, and produced a shorter blockchain fork.
                            // just keep trying
                            sleep_ms(5000);
                            continue;
                        },
                        _ => {
                            // delay and try again
                            sleep_ms(5000);
                            continue;
                        }
                    }
                }
            }
        };

        let burnchain_tip = BurnchainTip {
            block_snapshot: block_snapshot,
            state_transition: state_transition,
            received_at: Instant::now()
        };

        self.chain_tip = Some(burnchain_tip.clone());
        debug!("Done receiving blocks");

        Ok(burnchain_tip)
    }

    pub fn get_utxos(&self, public_key: &Secp256k1PublicKey, amount_required: u64) -> Option<Vec<UTXO>> {
        // Configure UTXO filter
        let pkh = Hash160::from_data(&public_key.to_bytes()).to_bytes().to_vec();
        let (_, network_id) = self.config.burnchain.get_bitcoin_network();
        let address = BitcoinAddress::from_bytes(
            network_id,
            BitcoinAddressType::PublicKeyHash,
            &pkh)
            .expect("Public key incorrect");        
        let filter_addresses = vec![address.to_b58()];

        let mut utxos = loop {
            let result = BitcoinRPCRequest::list_unspent(
                &self.config,
                filter_addresses.clone(), 
                false, 
                amount_required);

            // Perform request
            match result {
                    Ok(utxos) => {
                        break utxos;
                    }
                    Err(e) => {
                        error!("Bitcoin RPC failure: error listing utxos {:?}", e);
                        sleep_ms(5000);
                        continue;
                    }
            };
        };

        let utxos = 
            if utxos.len() == 0 {
                loop {
                    let _result = BitcoinRPCRequest::import_public_key(
                        &self.config,
                        &public_key);

                    sleep_ms(1000);

                    let result = BitcoinRPCRequest::list_unspent(
                        &self.config,
                        filter_addresses.clone(), 
                        false, 
                        amount_required);

                    utxos = match result {
                            Ok(utxos) => utxos,
                            Err(e) => {
                                error!("Bitcoin RPC failure: error listing utxos {:?}", e);
                                sleep_ms(5000);
                                continue;
                            }
                    };

                    if utxos.len() == 0 {
                        return None;
                    }
                    else {
                        break utxos;
                    }
                }
            }
            else {
                utxos
            };

        let total_unspent: u64 = utxos.iter().map(|o| o.amount).sum();
        if total_unspent < amount_required {
            debug!("Total unspent {} < {} for {:?}", total_unspent, amount_required, &public_key.to_hex());
            return None
        }

        Some(utxos)
    }

    fn build_leader_key_register_tx(&mut self, payload: LeaderKeyRegisterOp, signer: &mut BurnchainOpSigner) -> Option<Transaction> {
        
        let public_key = signer.get_public_key();

        let (mut tx, utxos) = self.prepare_tx(&public_key, DUST_UTXO_LIMIT)?;

        // Serialize the payload
        let op_bytes = {
            let mut buffer= vec![];
            let mut magic_bytes = self.config.burnchain.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            payload.consensus_serialize(&mut buffer).expect("FATAL: invalid operation");
            buffer
        };

        let consensus_output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        };

        tx.output = vec![consensus_output];

        let address_hash = Hash160::from_data(&public_key.to_bytes());
        let identifier_output = BitcoinAddress::to_p2pkh_tx_out(&address_hash, DUST_UTXO_LIMIT);

        tx.output.push(identifier_output);

        self.finalize_tx(
            &mut tx, 
            DUST_UTXO_LIMIT,
            utxos,
            signer)?;

        increment_btc_ops_sent_counter();
    
        info!("Miner node: submitting leader_key_register op - {}", public_key.to_hex());

        Some(tx)
    }

    fn build_leader_block_commit_tx(&mut self, payload: LeaderBlockCommitOp, signer: &mut BurnchainOpSigner) -> Option<Transaction> {

        let public_key = signer.get_public_key();

        let (mut tx, utxos) = self.prepare_tx(&public_key, payload.burn_fee)?;

        // Serialize the payload
        let op_bytes = {
            let mut buffer= vec![];
            let mut magic_bytes = self.config.burnchain.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            payload.consensus_serialize(&mut buffer).expect("FATAL: invalid operation");
            buffer
        };

        let consensus_output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_RETURN)
                .push_slice(&op_bytes)
                .into_script(),
        };

        tx.output = vec![consensus_output];

        if OUTPUTS_PER_COMMIT < payload.commit_outs.len() {
            error!("Generated block commit with more commit outputs than OUTPUTS_PER_COMMIT");
            return None;
        }

        let burned = if payload.commit_outs.len() > 0 {
            let pox_transfers = payload.commit_outs.len() as u64;
            let burn_remainder = (OUTPUTS_PER_COMMIT as u64) - pox_transfers;
            let value_per_transfer = payload.burn_fee / (OUTPUTS_PER_COMMIT as u64);
            if value_per_transfer < 5500 {
                error!("Total burn fee not enough for number of outputs");
                return None;
            }
            for commit_to in payload.commit_outs.iter() {
                tx.output.push(commit_to.to_bitcoin_tx_out(value_per_transfer));
            }
            value_per_transfer * burn_remainder
        } else {
            payload.burn_fee
        };

        if burned > 0 {
            let burn_address_hash = Hash160([0u8; 20]);
            let burn_output = BitcoinAddress::to_p2pkh_tx_out(&burn_address_hash, burned);
            tx.output.push(burn_output);
        }


        self.finalize_tx(
            &mut tx,
            payload.burn_fee,
            utxos,
            signer)?;

        increment_btc_ops_sent_counter();

        info!("Miner node: submitting leader_block_commit op - {}", public_key.to_hex());

        Some(tx)
    }

    fn prepare_tx(&self, public_key: &Secp256k1PublicKey, ops_fee: u64) -> Option<(Transaction, Vec<UTXO>)> {
        
        let tx_fee = self.config.burnchain.burnchain_op_tx_fee;
        let amount_required = tx_fee + ops_fee;

        // Fetch some UTXOs
        let utxos = match self.get_utxos(&public_key, amount_required) {
            Some(utxos) => utxos,
            None => {
                debug!("No UTXOs for {}", &public_key.to_hex());
                return None;
            }
        };
        
        let mut inputs = vec![];

        for utxo in utxos.iter() {
            let previous_output = OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            };
    
            let input = TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: 0xFFFFFFFF,
                witness: vec![],
            };

            inputs.push(input);
        }

        // Prepare a backbone for the tx
        let transaction = Transaction {
            input: inputs,
            output: vec![],
            version: 1,
            lock_time: 0,
        };

        Some((transaction, utxos))
    }

    fn finalize_tx(&self, tx: &mut Transaction, total_spent: u64, utxos: Vec<UTXO>, signer: &mut BurnchainOpSigner) -> Option<()> {

        let tx_fee = self.config.burnchain.burnchain_op_tx_fee;

        // Append the change output
        let total_unspent: u64 = utxos.iter().map(|o| o.amount).sum();
        let public_key = signer.get_public_key();
        let change_address_hash = Hash160::from_data(&public_key.to_bytes());
        if total_unspent < total_spent + tx_fee {
            warn!("Unspent total {} is less than intended spend: {}",
                  total_unspent, total_spent + tx_fee);
            return None
        }
        let value = total_unspent - total_spent - tx_fee;
        if value >= DUST_UTXO_LIMIT {
            let change_output = BitcoinAddress::to_p2pkh_tx_out(&change_address_hash, value);
            tx.output.push(change_output);
        } else {
            debug!("Not enough change to clear dust limit. Not adding change address.");
        }

        // Sign the UTXOs
        for (i, utxo) in utxos.iter().enumerate() {
            let script_pub_key = utxo.script_pub_key.clone();
            let sig_hash_all = 0x01;
            let sig_hash = tx.signature_hash(i, &script_pub_key, sig_hash_all);   
    
            let sig1_der = {
                let message = signer.sign_message(sig_hash.as_bytes())
                    .expect("Unable to sign message");
                message.to_secp256k1_recoverable()
                    .expect("Unable to get recoverable signature")
                    .to_standard()
                    .serialize_der()
            };
    
            tx.input[i].script_sig = Builder::new()
                .push_slice(&[&*sig1_der, &[sig_hash_all as u8][..]].concat())
                .push_slice(&public_key.to_bytes())
                .into_script();   
        }
        signer.dispose();

        Some(())
    }
 
    fn build_user_burn_support_tx(&mut self, _payload: UserBurnSupportOp, _signer: &mut BurnchainOpSigner) -> Option<Transaction> {
        unimplemented!()
    }

    fn send_transaction(&self, transaction: SerializedTx) -> bool {
        let result = BitcoinRPCRequest::send_raw_transaction(
            &self.config,
            transaction.to_hex());
        match result {
            Ok(_) => {
                true
            },
            Err(e) =>  {
                error!("Bitcoin RPC failure: transaction submission failed - {:?}", e);
                false
            } 
        }
    }

    /// wait until the ChainsCoordinator has processed sortitions up to the
    ///   canonical chain tip, or has processed up to height_to_wait
    pub fn wait_for_sortitions(&self, height_to_wait: Option<u64>) -> BurnchainTip {
        loop {
            let canonical_burnchain_tip = self.burnchain_db.as_ref()
                .expect("BurnchainDB not opened")
                .get_canonical_chain_tip().unwrap();
            let canonical_sortition_tip = SortitionDB::get_canonical_burn_chain_tip(
                self.sortdb_ref().conn()).unwrap();
            if canonical_burnchain_tip.block_height == canonical_sortition_tip.block_height {
                let (_, state_transition) = self.sortdb_ref().get_sortition_result(&canonical_sortition_tip.sortition_id)
                        .expect("Sortition DB error.")
                        .expect("BUG: no data for the canonical chain tip");

                return BurnchainTip {
                    block_snapshot: canonical_sortition_tip,
                    received_at: Instant::now(),
                    state_transition
                }
            } else if let Some(height_to_wait) = height_to_wait {
                if canonical_sortition_tip.block_height >= height_to_wait {
                    let (_, state_transition) = self.sortdb_ref().get_sortition_result(&canonical_sortition_tip.sortition_id)
                        .expect("Sortition DB error.")
                        .expect("BUG: no data for the canonical chain tip");

                    return BurnchainTip {
                        block_snapshot: canonical_sortition_tip,
                        received_at: Instant::now(),
                        state_transition
                    }
                }
            }
        }
    }

    pub fn build_next_block(&self, num_blocks: u64) {
        debug!("Generate {} block(s)", num_blocks);
        let public_key = match &self.config.burnchain.local_mining_public_key {
            Some(public_key) => hex_bytes(public_key).expect("Invalid byte sequence"),
            None => panic!("Unable to make new block, mining public key"),
        };
        
        let pkh = Hash160::from_data(&public_key).to_bytes().to_vec();
        let (_, network_id) = self.config.burnchain.get_bitcoin_network();
        let address = BitcoinAddress::from_bytes(
            network_id,
            BitcoinAddressType::PublicKeyHash,
            &pkh)
            .expect("Public key incorrect");

        let result = BitcoinRPCRequest::generate_to_address(
            &self.config,
            num_blocks,
            address.to_b58());

        match result {
            Ok(_) => {},
            Err(e) => {
                error!("Bitcoin RPC failure: error generating block {:?}", e);
                panic!();
            }
        }
    }
}

impl BurnchainController for BitcoinRegtestController {
    
    fn sortdb_ref(&self) -> &SortitionDB {
        self.db.as_ref().expect("BUG: did not instantiate the burn DB")
    }

    fn sortdb_mut(&mut self) -> &mut SortitionDB {
        let network = "regtest".to_string();
        let working_dir = self.config.get_burn_db_path();
        let burnchain = match Burnchain::new(&working_dir,  &self.config.burnchain.chain, &network) {
            Ok(burnchain) => burnchain,
            Err(e) => {
                error!("Failed to instantiate burnchain: {}", e);
                panic!()    
            }
        };

        let (db, burnchain_db) = burnchain.open_db(true).unwrap();
        self.db = Some(db);
        self.burnchain_db = Some(burnchain_db);

        match self.db {
            Some(ref mut sortdb) => sortdb,
            None => {
                unreachable!()
            }
        }
    }
    
    fn get_chain_tip(&mut self) -> BurnchainTip {
        match &self.chain_tip {
            Some(chain_tip) => chain_tip.clone(),
            None => {
                unreachable!();
            }
        }
    }


    fn start(&mut self) -> Result<BurnchainTip, BurnchainControllerError> {
        self.receive_blocks(false)
    }

    fn sync(&mut self) -> Result<BurnchainTip, BurnchainControllerError> {
        let burnchain_tip = if self.config.burnchain.mode == "helium" {
            // Helium: this node is responsible for mining new burnchain blocks
            self.build_next_block(1);
            self.receive_blocks(true)?
        } else {
            // Neon: this node is waiting on a block to be produced
            let current_height = self.get_chain_tip().block_snapshot.block_height;
            loop {
                let burnchain_tip = self.receive_blocks(true)?;
                if burnchain_tip.block_snapshot.block_height > current_height {
                    break burnchain_tip;
                }
                sleep_ms(5000);
            }
        };

        // Evaluate process_exit_at_block_height setting
        if let Some(cap) = self.config.burnchain.process_exit_at_block_height {
            if burnchain_tip.block_snapshot.block_height >= cap {
                info!("Node succesfully reached the end of the ongoing {} blocks epoch!", cap);
                info!("This process will automatically terminate in 30s, restart your node for participating in the next epoch.");
                sleep_ms(30000);
                std::process::exit(0);
            }
        }
        Ok(burnchain_tip)
    }

    // returns true if the operation was submitted successfully, false otherwise 
    fn submit_operation(&mut self, operation: BlockstackOperationType, op_signer: &mut BurnchainOpSigner) -> bool {
        let transaction = match operation {
            BlockstackOperationType::LeaderBlockCommit(payload) 
                => self.build_leader_block_commit_tx(payload, op_signer),
                BlockstackOperationType::LeaderKeyRegister(payload) 
                => self.build_leader_key_register_tx(payload, op_signer),
                BlockstackOperationType::UserBurnSupport(payload) 
                => self.build_user_burn_support_tx(payload, op_signer)
        };

        let transaction = match transaction {
            Some(tx) => SerializedTx::new(tx),
            _ => {
                return false
            }
        };

        self.send_transaction(transaction)
    }
    
    #[cfg(test)]
    fn bootstrap_chain(&mut self, num_blocks: u64) {

        if let Some(local_mining_pubkey) = &self.config.burnchain.local_mining_public_key {

            let pk = hex_bytes(&local_mining_pubkey).expect("Invalid byte sequence");
            let pkh = Hash160::from_data(&pk).to_bytes().to_vec();
            let (_, network_id) = self.config.burnchain.get_bitcoin_network();
            let address = BitcoinAddress::from_bytes(
                network_id,
                BitcoinAddressType::PublicKeyHash,
                &pkh)
                .expect("Public key incorrect");

            let _result = BitcoinRPCRequest::import_public_key(
                &self.config, &Secp256k1PublicKey::from_hex(local_mining_pubkey).unwrap());
    
            let result = BitcoinRPCRequest::generate_to_address(
                &self.config, 
                num_blocks,
                address.to_b58());

            match result {
                Ok(_) => {},
                Err(e) => {
                    error!("Bitcoin RPC failure: error generating block {:?}", e);
                    panic!();
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct SerializedTx {
    bytes: Vec<u8>
}

impl SerializedTx {
    pub fn new(tx: Transaction) -> SerializedTx {
        let mut encoder = RawEncoder::new(Cursor::new(vec![]));
        tx.consensus_encode(&mut encoder).expect("BUG: failed to serialize to a vec");
        let bytes: Vec<u8> = encoder.into_inner().into_inner(); 
        SerializedTx {
            bytes
        }
    }

    fn to_hex(self) -> String {
        let formatted_bytes: Vec<String> = self.bytes.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}", formatted_bytes.join(""))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedUTXO {
    txid: String,
    vout: u32,
    script_pub_key: String,
    amount: Box<RawValue>,
    confirmations: u32,
    spendable: bool,
    solvable: bool,
    desc: Option<String>,
    safe: bool,
}

pub struct UTXO {
    txid: Sha256dHash,
    vout: u32,
    script_pub_key: Script,
    amount: u64,
}

impl ParsedUTXO {

    pub fn get_txid(&self) -> Option<Sha256dHash> {
        match hex_bytes(&self.txid) {
            Ok(ref mut txid) => {
                txid.reverse();
                Some(Sha256dHash::from(&txid[..]))
            }
            Err(err) => {
                warn!("Unable to get txid from UTXO {}", err);
                None
            }
        }
    }

    pub fn get_sat_amount(&self) -> Option<u64> {
        ParsedUTXO::serialized_btc_to_sat(self.amount.get())
    }

    pub fn serialized_btc_to_sat(amount: &str) -> Option<u64> {
        let comps: Vec<&str> = amount.split(".").collect();
        match comps[..] {
            [lhs, rhs] => {
                if rhs.len() > 8 {
                    warn!("Unexpected amount of decimals");
                    return None;
                }

                match (lhs.parse::<u64>(), rhs.parse::<u64>()) {
                    (Ok(btc), Ok(frac_part)) => {        
                        let base: u64 = 10;
                        let btc_to_sat = base.pow(8);
                        let mut amount = btc * btc_to_sat;
                        let sat = frac_part * base.pow(8 - rhs.len() as u32);
                        amount += sat;
                        Some(amount)
                    },
                    (lhs, rhs) => {
                        warn!("Error while converting BTC to sat {:?} - {:?}", lhs, rhs);
                        return None;
                    }
                }
            },
            _ => None
        }    
    } 

    pub fn sat_to_serialized_btc(amount: u64) -> String {
        let base: u64 = 10;
        let int_part = amount / base.pow(8);
        let frac_part = amount % base.pow(8);
        let amount = format!("{}.{:08}", int_part, frac_part);
        amount
    } 

    pub fn get_script_pub_key(&self) -> Option<Script> {
        match hex_bytes(&self.script_pub_key) {
            Ok(bytes) => Some(bytes.into()),
            Err(_) => {
                warn!("Unable to get script pub key");
                None
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BitcoinRPCRequest {
    /// The name of the RPC call
    pub method: String,
    /// Parameters to the RPC call
    pub params: Vec<serde_json::Value>,
    /// Identifier for this Request, which should appear in the response
    pub id: String,
    /// jsonrpc field, MUST be "2.0"
    pub jsonrpc: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
enum RPCError {
    Network(String),
    Parsing(String),
    Bitcoind(String),
}

type RPCResult<T> = Result<T, RPCError>;

impl BitcoinRPCRequest {

    fn build_rpc_request(config: &Config) -> Request {
        let url = {
            let url = config.burnchain.get_rpc_url();
            Url::parse(&url).expect(&format!("Unable to parse {} as a URL", url))
        };
        debug!("BitcoinRPC builder: {:?}:{:?}@{}", 
            &config.burnchain.username, 
            &config.burnchain.password,
            &url);

        let mut req = Request::new(Method::Post, url);

        match (&config.burnchain.username, &config.burnchain.password) {
            (Some(username), Some(password)) => {
                let auth_token = format!("Basic {}", encode(format!("{}:{}", username, password)));
                req.append_header("Authorization", auth_token).expect("Unable to set header");
            },
            (_, _) => {}
        };
        req
    }

    pub fn generate_to_address(config: &Config, num_blocks: u64, address: String) -> RPCResult<()> {
        debug!("Generate {} blocks to {}", num_blocks, address);
        let payload = BitcoinRPCRequest {
            method: "generatetoaddress".to_string(),
            params: vec![num_blocks.into(), address.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        BitcoinRPCRequest::send(&config, payload)?;
        Ok(())
    }

    pub fn list_unspent(config: &Config, addresses: Vec<String>, include_unsafe: bool, minimum_sum_amount: u64) -> RPCResult<Vec<UTXO>> {
        let min_conf = 0;
        let max_conf = 9999999;
        let minimum_amount = ParsedUTXO::sat_to_serialized_btc(minimum_sum_amount);

        let payload = BitcoinRPCRequest {
            method: "listunspent".to_string(),
            params: vec![
                min_conf.into(), 
                max_conf.into(), 
                addresses.into(), 
                include_unsafe.into(),
                json!({
                    "minimumAmount": minimum_amount
                })],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let mut res = BitcoinRPCRequest::send(&config, payload)?;

        match res.as_object_mut() {
            Some(ref mut object) => {
                match object.get_mut("result") {
                    Some(serde_json::Value::Array(entries)) => {
                        while let Some(entry) = entries.pop() {
                            let parsed_utxo: ParsedUTXO = match serde_json::from_value(entry) {
                                Ok(utxo) => utxo,
                                Err(err) => {
                                    warn!("Failed parsing UTXO: {}", err);
                                    continue
                                }
                            };
                            let amount = match parsed_utxo.get_sat_amount() {
                                Some(amount) => amount,
                                None => continue
                            };
                                    
                            if amount < minimum_sum_amount {
                                continue;
                            }

                            let script_pub_key = match parsed_utxo.get_script_pub_key() {
                                Some(script_pub_key) => script_pub_key,
                                None => {
                                    continue;
                                }
                            };
 
                            let txid = match parsed_utxo.get_txid() {
                                Some(amount) => amount,
                                None => continue
                            };
                                    
                            return Ok(vec![UTXO {
                                txid,
                                vout: parsed_utxo.vout,
                                script_pub_key,
                                amount,
                            }]);
                        }
                    },
                    _ => { warn!("Failed to get UTXOs"); }
                }
            },
            _ => { warn!("Failed to get UTXOs"); }
        };

        Ok(vec![])
    }

    pub fn send_raw_transaction(config: &Config, tx: String) -> RPCResult<()> {
        let payload = BitcoinRPCRequest {
            method: "sendrawtransaction".to_string(),
            params: vec![tx.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let json_resp = BitcoinRPCRequest::send(&config, payload)?;

        if let Some(e) = json_resp.get("error") {
            if !e.is_null() {
                error!("Error submitting transaction: {}", json_resp);
                return Err(RPCError::Bitcoind(json_resp.to_string()))
            }
        }
        Ok(())
    }

    pub fn import_public_key(config: &Config, public_key: &Secp256k1PublicKey) -> RPCResult<()> {
        let rescan = true;
        let label = "";

        let pkh = Hash160::from_data(&public_key.to_bytes()).to_bytes().to_vec();
        let (_, network_id) = config.burnchain.get_bitcoin_network();
        let address = BitcoinAddress::from_bytes(
            network_id,
            BitcoinAddressType::PublicKeyHash,
            &pkh)
            .expect("Public key incorrect");        

        let payload = BitcoinRPCRequest {
            method: "importaddress".to_string(),
            params: vec![address.to_b58().into(), label.into(), rescan.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        BitcoinRPCRequest::send(&config, payload)?;
        Ok(())
    }

    fn send(config: &Config, payload: BitcoinRPCRequest) -> RPCResult<serde_json::Value> {
        let mut request = BitcoinRPCRequest::build_rpc_request(&config);

        let body = match serde_json::to_vec(&json!(payload)) {
            Ok(body) => body,
            Err(err) => {
                return Err(RPCError::Network(format!("RPC Error: {}", err)));
            }
        };
        request.append_header("Content-Type", "application/json").expect("Unable to set header");
        request.set_body(body);

        let mut response = async_std::task::block_on(async move {
            let stream = match TcpStream::connect(config.burnchain.get_rpc_socket_addr()).await {
                Ok(stream) => stream,
                Err(err) => {
                    return Err(RPCError::Network(
                        format!("Bitcoin RPC: connection failed - {:?}", err)))    
                }
            };    

            match client::connect(stream, request).await {
                Ok(response) => Ok(response),
                Err(err) => {
                    return Err(RPCError::Network(
                        format!("Bitcoin RPC: invoking procedure failed - {:?}", err)))    
                }
            }
        })?;

        if !response.status().is_success() {
            return Err(RPCError::Network(
                format!("Bitcoin RPC: status({}) != success, {:?}", response.status(), response)))
        }
        
        let (res, buffer) = async_std::task::block_on(async move {
            let mut buffer = Vec::new();
            let mut body = response.take_body();
            let res = body.read_to_end(&mut buffer).await;
            (res, buffer)
        });

        if res.is_err() {
            return Err(RPCError::Network(
                format!("Bitcoin RPC: unable to read body - {:?}", res)))
        }
        
        let payload = serde_json::from_slice::<serde_json::Value>(&buffer[..])
            .map_err(|e| RPCError::Parsing(format!("Bitcoin RPC: {}", e)))?;
        Ok(payload)
    }
}
