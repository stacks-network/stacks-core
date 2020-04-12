use std::io::Cursor;
use std::time::Instant;

use reqwest::blocking::{Client, RequestBuilder};
use serde::Serialize;

use secp256k1::{Secp256k1};

use super::{BurnchainController, BurnchainTip};
use super::super::operations::{BurnchainOperationType, LeaderKeyRegisterPayload, LeaderBlockCommitPayload, UserBurnSupportPayload, BurnchainOpSigner};
use super::super::Config;

use stacks::burnchains::Burnchain;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::bitcoin::address::{BitcoinAddress, BitcoinAddressType};
use stacks::burnchains::bitcoin::indexer::{BitcoinIndexer, BitcoinIndexerRuntime, BitcoinIndexerConfig};
use stacks::burnchains::bitcoin::spv::SpvClient; 
use stacks::burnchains::PublicKey;
use stacks::chainstate::burn::db::burndb::BurnDB;
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

pub struct BitcoinRegtestController {
    config: Config,
    indexer_config: BitcoinIndexerConfig,
    db: Option<BurnDB>,
    chain_tip: Option<BurnchainTip>,
}

impl BitcoinRegtestController {

    pub fn generic(config: Config) -> Box<dyn BurnchainController> {
        Box::new(Self::new(config))
    }

    pub fn new(config: Config) -> Self {
        
        std::fs::create_dir_all(&config.node.get_burnchain_path()).unwrap();
        SpvClient::init_block_headers(&config.burnchain.spv_headers_path, BitcoinNetworkType::Regtest).unwrap();

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
            config: config,
            indexer_config,
            db: None,
            chain_tip: None,
        }
    }

    fn setup_indexer_runtime(&mut self) -> (Burnchain, BitcoinIndexer) {
        let network = "regtest".to_string();
        let working_dir = self.config.get_burn_db_path();
        let burnchain = Burnchain::new(
            &working_dir,
            &self.config.burnchain.chain, 
            &network)
        .map_err(|e| {
            error!("Failed to instantiate burn chain driver for {}: {:?}", network, e);
            e
        }).unwrap();

        let indexer_runtime = BitcoinIndexerRuntime::new(BitcoinNetworkType::Regtest);
        let burnchain_indexer = BitcoinIndexer {
            config: self.indexer_config.clone(),
            runtime: indexer_runtime
        };
        (burnchain, burnchain_indexer)
    }

    fn receive_blocks(&mut self) -> BurnchainTip {
        let (mut burnchain, mut burnchain_indexer) = self.setup_indexer_runtime();

        let (block_snapshot, state_transition) = burnchain.sync_with_indexer(&mut burnchain_indexer).unwrap();

        let rest = match (&state_transition, &self.chain_tip) {
            (None, Some(chain_tip)) => chain_tip.clone(),
            (Some(state_transition), _) => {
                let burnchain_tip = BurnchainTip {
                    block_snapshot: block_snapshot,
                    state_transition: state_transition.clone(),
                    received_at: Instant::now()
                };
                self.chain_tip = Some(burnchain_tip.clone());
                burnchain_tip
            },
            (None, None) => {
                error!("Unable to sync burnchain");
                panic!()
            }
        };
        rest
    }

    fn get_rpc_request_builder(&self) -> RequestBuilder {
        let url = self.config.burnchain.get_rpc_url();
        let client = Client::new();
        let builder = client.post(&url);
        
        match (&self.config.burnchain.username, &self.config.burnchain.password) {
            (Some(username), Some(password)) => builder.basic_auth(username, Some(password)),
            (_, _) => builder
        }
    }

    fn get_utxos(&self, public_key: &Secp256k1PublicKey, amount_required: u64) -> Option<Vec<UTXO>> {
        // todo(ludo): reuse the same client.

        // Configure UTXO filter
        let pkh = Hash160::from_data(&public_key.to_bytes()).to_bytes().to_vec();
        let address = BitcoinAddress::from_bytes(
            BitcoinNetworkType::Regtest,
            BitcoinAddressType::PublicKeyHash,
            &pkh)
            .expect("Public key incorrect");        
        let filter_addresses = vec![address.to_b58()];

        let request_builder = self.get_rpc_request_builder();
        let result = BitcoinRPCRequest::list_unspent(
            request_builder,
            filter_addresses.clone(), 
            false, 
            amount_required);

        // Perform request
        let mut utxos = match result {
                Ok(utxos) => utxos,
                Err(e) => {
                    error!("Bitcoin RPC failure: error listing utxos {:?}", e);
                    panic!();    
                }
        };

        if utxos.len() == 0 {
            let request_builder = self.get_rpc_request_builder();
            let _result = BitcoinRPCRequest::import_public_key(
                request_builder,
                &public_key.to_hex());

            // todo(ludo): rescan can take time. we should probably add a few retries, with exp backoff.
            sleep_ms(1000);

            let request_builder = self.get_rpc_request_builder();
            let result = BitcoinRPCRequest::list_unspent(
                request_builder,
                filter_addresses, 
                false, 
                amount_required);

            utxos = match result {
                    Ok(utxos) => utxos,
                    Err(e) => {
                        error!("Bitcoin RPC failure: error listing utxos {:?}", e);
                        panic!();    
                    }
            };

            if utxos.len() == 0 {
                return None
            }
        }

        Some(utxos)
    }

    fn build_leader_key_register_tx(&mut self, payload: LeaderKeyRegisterPayload, signer: &mut BurnchainOpSigner) -> Option<Transaction> {
        
        let public_key = signer.get_public_key();

        let (mut tx, utxos) = self.prepare_tx(&public_key, 0).unwrap();

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

        self.finalize_tx(
            &mut tx, 
            0, 
            utxos,
            signer);

        Some(tx)   
    }

    fn build_leader_block_commit_tx(&mut self, payload: LeaderBlockCommitPayload, signer: &mut BurnchainOpSigner) -> Option<Transaction> {

        let public_key = signer.get_public_key();

        let (mut tx, utxos) = self.prepare_tx(&public_key, payload.burn_fee).unwrap();

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

        let burn_address_hash = Hash160([0u8; 20]).as_bytes();
        let burn_output = TxOut {
            value: payload.burn_fee,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_DUP)
                .push_opcode(opcodes::All::OP_HASH160)
                .push_slice(burn_address_hash)
                .push_opcode(opcodes::All::OP_EQUALVERIFY)
                .push_opcode(opcodes::All::OP_CHECKSIG)
                .into_script()
        };

        tx.output = vec![consensus_output, burn_output];

        self.finalize_tx(
            &mut tx, 
            payload.burn_fee, 
            utxos,
            signer);

        Some(tx)    
    }

    fn prepare_tx(&self, public_key: &Secp256k1PublicKey, ops_fee: u64) -> Option<(Transaction, Vec<UTXO>)> {
        
        let tx_fee = self.config.burnchain.burnchain_op_tx_fee;
        let amount_required = tx_fee + ops_fee;

        // Fetch some UTXOs
        let utxos = match self.get_utxos(&public_key, amount_required) {
            Some(utxos) => utxos,
            None => return None
        };
        
        let mut inputs = vec![];

        for utxo in utxos.iter() {
            let previous_output = OutPoint {
                txid: utxo.get_txid(),
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

    fn finalize_tx(&self, tx: &mut Transaction, total_spent: u64, utxos: Vec<UTXO>, signer: &mut BurnchainOpSigner) {

        let tx_fee = self.config.burnchain.burnchain_op_tx_fee;

        // Append the change output
        let total_unspent: u64 = utxos.iter().map(|o| o.get_sat_amount()).sum();
        let public_key = signer.get_public_key();
        let change_address_hash = Hash160::from_data(&public_key.to_bytes()).to_bytes();
        let change_output = TxOut {
            value: total_unspent - total_spent - tx_fee,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_DUP)
                .push_opcode(opcodes::All::OP_HASH160)
                .push_slice(&change_address_hash)
                .push_opcode(opcodes::All::OP_EQUALVERIFY)
                .push_opcode(opcodes::All::OP_CHECKSIG)
                .into_script()
        };
        tx.output.push(change_output);

        // Sign the UTXOs
        for (i, utxo) in utxos.iter().enumerate() {
            let script_pub_key = utxo.get_script_pub_key();
            let sig_hash_all = 0x01;
            let sig_hash = tx.signature_hash(i, &script_pub_key, sig_hash_all);   
    
            let mut sig1_der = {
                let secp = Secp256k1::new();
                let message = signer.sign_message(sig_hash.as_bytes()).unwrap();
                let der = message.to_secp256k1_recoverable().unwrap().to_standard(&secp).serialize_der(&secp);
                der
            };
            sig1_der.push(sig_hash_all as u8);
    
            tx.input[i].script_sig = Builder::new()
                .push_slice(&sig1_der[..])
                .push_slice(&public_key.to_bytes())
                .into_script();   
        }
        signer.dispose();
    }
 
    fn build_user_burn_support_tx(&mut self, _payload: UserBurnSupportPayload, _signer: &mut BurnchainOpSigner) -> Option<Transaction> {
        unimplemented!()
    }

    fn send_transaction(&self, transaction: SerializedTx) -> bool {
        let request_builder = self.get_rpc_request_builder();
        let result = BitcoinRPCRequest::send_raw_transaction(
            request_builder, 
            transaction.to_hex());
        match result {
            Ok(_) => true,
            Err(e) =>  {
                error!("Bitcoin RPC failure: transaction submission failed - {:?}", e);
                false
            } 
        }
    }

    fn build_next_block(&self, public_key: &String, num_blocks: u64) {
        let pk = hex_bytes(&public_key).expect("Invalid byte sequence");
        let pkh = Hash160::from_data(&pk).to_bytes().to_vec();
        let address = BitcoinAddress::from_bytes(
            BitcoinNetworkType::Regtest,
            BitcoinAddressType::PublicKeyHash,
            &pkh)
            .expect("Public key incorrect");

        let request_builder = self.get_rpc_request_builder();
        let result = BitcoinRPCRequest::generate_to_address(
            request_builder, 
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

    fn burndb_mut(&mut self) -> &mut BurnDB {

        let network = self.config.burnchain.network.clone();
        let working_dir = self.config.get_burn_db_path();
        let burnchain = Burnchain::new(
            &working_dir,
            &self.config.burnchain.chain, 
            "regtest")
        .map_err(|e| {
            error!("Failed to instantiate burn chain driver for {}: {:?}", network, e);
            e
        }).unwrap();

        let db = burnchain.open_db(true).unwrap();
        self.db = Some(db);

        match self.db {
            Some(ref mut burndb) => burndb,
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


    fn start(&mut self) -> BurnchainTip {
        self.receive_blocks()
    }

    fn sync(&mut self) -> BurnchainTip {        
        if let Some(local_mining_pk) = &self.config.burnchain.local_mining_public_key {
            // Burnchain is mined by a solo miner / local setup
            self.build_next_block(local_mining_pk, 1);
            self.receive_blocks()
        } else {
            // Burnchain is mined by another miner (neon like)
            let current_height = self.get_chain_tip().block_snapshot.block_height;
            loop {
                let burnchain_tip = self.receive_blocks();
                if burnchain_tip.block_snapshot.block_height > current_height {
                    break burnchain_tip;
                }
                sleep_ms(500);
            }
        }
    }

    fn submit_operation(&mut self, operation: BurnchainOperationType, op_signer: &mut BurnchainOpSigner) {

        let transaction = match operation {
            BurnchainOperationType::LeaderBlockCommit(payload) 
                => self.build_leader_block_commit_tx(payload, op_signer),
            BurnchainOperationType::LeaderKeyRegister(payload) 
                => self.build_leader_key_register_tx(payload, op_signer),
            BurnchainOperationType::UserBurnSupport(payload) 
                => self.build_user_burn_support_tx(payload, op_signer)
        };

        let transaction = match transaction {
            Some(tx) => SerializedTx::new(tx),
            _ => return
        };

        self.send_transaction(transaction);
    }
    
    #[cfg(test)]
    fn bootstrap_chain(&mut self) {

        if let Some(local_mining_pubkey) = &self.config.burnchain.local_mining_public_key {

            let pk = hex_bytes(&local_mining_pubkey).expect("Invalid byte sequence");
            let pkh = Hash160::from_data(&pk).to_bytes().to_vec();
            let address = BitcoinAddress::from_bytes(
                BitcoinNetworkType::Regtest,
                BitcoinAddressType::PublicKeyHash,
                &pkh)
                .expect("Public key incorrect");

            let request_builder = self.get_rpc_request_builder();

            let _result = BitcoinRPCRequest::import_public_key(
                request_builder, 
                local_mining_pubkey);
    
            let request_builder = self.get_rpc_request_builder();
            let result = BitcoinRPCRequest::generate_to_address(
                request_builder, 
                201,
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
pub struct UTXO {
    pub txid: String,
    pub vout: u32,
    pub script_pub_key: String,
    pub amount: f64,
    pub confirmations: u32,
    pub spendable: bool,
    pub solvable: bool,
    pub desc: Option<String>,
    pub safe: bool,
}

impl UTXO {

    pub fn get_txid(&self) -> Sha256dHash {
        let mut txid = hex_bytes(&self.txid).expect("Invalid byte sequence");
        txid.reverse();
        Sha256dHash::from(&txid[..])
    }

    pub fn get_sat_amount(&self) -> u64 {
        let res = self.amount * 10e7;
        res as u64
    }

    pub fn get_script_pub_key(&self) -> Script {
        let bytes = hex_bytes(&self.script_pub_key).expect("Invalid byte sequence");
        bytes.into()
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
    RPCError(String),
}

type RPCResult<T> = Result<T, RPCError>;

impl BitcoinRPCRequest {

    pub fn generate_to_address(request_builder: RequestBuilder, num_blocks: u64, address: String) -> RPCResult<()> {
        let payload = BitcoinRPCRequest {
            method: "generatetoaddress".to_string(),
            params: vec![num_blocks.into(), address.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let body = json!(payload);
        let res = request_builder.json(&body).send().unwrap().json::<serde_json::Value>().unwrap();
        Ok(())
    }

    pub fn list_unspent(request_builder: RequestBuilder, addresses: Vec<String>, include_unsafe: bool, minimum_sum_amount: u64) -> RPCResult<Vec<UTXO>> {
        let sat_decimals = 8;
        let real = format!("{:0width$}", minimum_sum_amount, width = sat_decimals);
        let conv = if real.len() == sat_decimals {
            format!("0.{}", &real[real.len() - sat_decimals..])
        } else {
            format!("{}.{}", &real[0..(real.len() - sat_decimals)], &real[real.len() - sat_decimals..])
        };

        let payload = BitcoinRPCRequest {
            method: "listunspent".to_string(),
            params: vec![
                0.into(), 
                9999999.into(), 
                addresses.into(), 
                include_unsafe.into(),
                json!({
                    "minimumSumAmount": conv
                })],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let body = json!(payload);
        let mut res = request_builder.json(&body).send().unwrap().json::<serde_json::Value>().unwrap();
        let mut utxos = vec![];

        match res.as_object_mut() {
            Some(ref mut object) => {
                match object.get_mut("result") {
                    Some(serde_json::Value::Array(entries)) => {
                        while let Some(entry) = entries.pop() {     
                            let utxo: UTXO = serde_json::from_value(entry).unwrap();
                            utxos.push(utxo);
                        }
                    },
                    _ => {}
                }
            },
            _ => {}
        };

        Ok(utxos)
    }

    pub fn send_raw_transaction(request_builder: RequestBuilder, tx: String) -> RPCResult<()> {
        let payload = BitcoinRPCRequest {
            method: "sendrawtransaction".to_string(),
            params: vec![tx.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let body = json!(payload);
        let res = request_builder.json(&body).send().unwrap().json::<serde_json::Value>().unwrap();
        Ok(())
    }

    pub fn import_public_key(request_builder: RequestBuilder, public_key: &str) -> RPCResult<()> {
        let payload = BitcoinRPCRequest {
            method: "importpubkey".to_string(),
            params: vec![public_key.into(), "".into(), true.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let body = json!(payload);
        let res = request_builder.json(&body).send().unwrap().json::<serde_json::Value>().unwrap();
        Ok(())
    }
}
