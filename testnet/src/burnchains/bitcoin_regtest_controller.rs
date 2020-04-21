use std::io::Cursor;
use std::time::Instant;

use reqwest::blocking::{Client, RequestBuilder};
use serde::Serialize;

use secp256k1::{Secp256k1};

use super::{BurnchainController, BurnchainTip};
use super::super::operations::BurnchainOpSigner;
use super::super::Config;

use stacks::burnchains::Burnchain;
use stacks::burnchains::BurnchainStateTransition;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::bitcoin::address::{BitcoinAddress, BitcoinAddressType};
use stacks::burnchains::bitcoin::indexer::{BitcoinIndexer, BitcoinIndexerRuntime, BitcoinIndexerConfig};
use stacks::burnchains::bitcoin::spv::SpvClient; 
use stacks::burnchains::PublicKey;
use stacks::chainstate::burn::db::burndb::BurnDB;
use stacks::chainstate::burn::operations::{
    LeaderBlockCommitOp,
    LeaderKeyRegisterOp,
    UserBurnSupportOp,
    BlockstackOperationType,
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
        
        std::fs::create_dir_all(&config.node.get_burnchain_path())
            .expect("Unable to create workdir");
        
        let res = SpvClient::init_block_headers(&config.burnchain.spv_headers_path, BitcoinNetworkType::Regtest);
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
            config: config,
            indexer_config,
            db: None,
            chain_tip: None,
        }
    }

    fn setup_indexer_runtime(&mut self) -> (Burnchain, BitcoinIndexer) {
        let network = "regtest".to_string();
        let working_dir = self.config.get_burn_db_path();
        let burnchain = match Burnchain::new(&working_dir,  &self.config.burnchain.chain, &network) {
            Ok(burnchain) => burnchain,
            Err(e) => {
                error!("Failed to instantiate burnchain: {}", e);
                panic!()    
            }
        };

        let indexer_runtime = BitcoinIndexerRuntime::new(BitcoinNetworkType::Regtest);
        let burnchain_indexer = BitcoinIndexer {
            config: self.indexer_config.clone(),
            runtime: indexer_runtime
        };
        (burnchain, burnchain_indexer)
    }

    fn receive_blocks(&mut self) -> BurnchainTip {
        let (mut burnchain, mut burnchain_indexer) = self.setup_indexer_runtime();

        let (block_snapshot, state_transition) = match burnchain.sync_with_indexer(&mut burnchain_indexer) {
            Ok(res) => res,
            Err(e) => {
                error!("Unable to sync burnchain: {}", e);
                panic!()
            }
        };

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
                // can happen at genesis
                let burnchain_tip = BurnchainTip {
                    block_snapshot: block_snapshot,
                    state_transition: BurnchainStateTransition::noop(),
                    received_at: Instant::now()
                };
                self.chain_tip = Some(burnchain_tip.clone());
                burnchain_tip
            }
        };

        debug!("Done receiving blocks");
        rest
    }

    fn get_rpc_request_builder(&self) -> RequestBuilder {
        let url = self.config.burnchain.get_rpc_url();
        let client = Client::new();
        let builder = client.post(&url);

        debug!("BitcoinRPC builder: {:?}:{:?}@{}", &self.config.burnchain.username, &self.config.burnchain.password,
               &url);
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

        info!("Get UTXOs for {}", address.to_b58());

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
                &public_key);

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

        let total_unspent: u64 = utxos.iter().map(|o| o.get_sat_amount()).sum();
        if total_unspent < amount_required {
            debug!("Total unspent {} < {} for {:?}", total_unspent, amount_required, &public_key.to_hex());
            return None
        }

        Some(utxos)
    }

    fn build_leader_key_register_tx(&mut self, payload: LeaderKeyRegisterOp, signer: &mut BurnchainOpSigner) -> Option<Transaction> {
        
        let public_key = signer.get_public_key();

        let (mut tx, utxos) = self.prepare_tx(&public_key, 0)?;

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
            None => {
                info!("No UTXOs for {}", &public_key.to_hex());
                return None;
            }
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
                let message = signer.sign_message(sig_hash.as_bytes())
                    .expect("Unable to sign message");
                let der = message.to_secp256k1_recoverable()
                    .expect("Unable to get recoverable signature")
                    .to_standard(&secp)
                    .serialize_der(&secp);
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
 
    fn build_user_burn_support_tx(&mut self, _payload: UserBurnSupportOp, _signer: &mut BurnchainOpSigner) -> Option<Transaction> {
        unimplemented!()
    }

    fn send_transaction(&self, transaction: SerializedTx) -> bool {
        let request_builder = self.get_rpc_request_builder();
        info!("Submitting TX");

        let result = BitcoinRPCRequest::send_raw_transaction(
            request_builder, 
            transaction.to_hex());
        match result {
            Ok(x) => {
                info!("Submitted TX, response = {:?}", x);
                true
            },
            Err(e) =>  {
                error!("Bitcoin RPC failure: transaction submission failed - {:?}", e);
                false
            } 
        }
    }

    fn build_next_block(&self, num_blocks: u64) {
        debug!("Generate {} block(s)", num_blocks);
        let public_key = match &self.config.burnchain.local_mining_public_key {
            Some(public_key) => hex_bytes(public_key).expect("Invalid byte sequence"),
            None => panic!("Unable to make new block, mining public key"),
        };
        
        let pkh = Hash160::from_data(&public_key).to_bytes().to_vec();
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
        let network = "regtest".to_string();
        let working_dir = self.config.get_burn_db_path();
        let burnchain = match Burnchain::new(&working_dir,  &self.config.burnchain.chain, &network) {
            Ok(burnchain) => burnchain,
            Err(e) => {
                error!("Failed to instantiate burnchain: {}", e);
                panic!()    
            }
        };

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
        if self.config.burnchain.mode == "helium" {
            // Helium: this node is responsible for mining new burnchain blocks
            self.build_next_block(1);
            self.receive_blocks()
        } else {
            // Neon: this node is waiting on a block to be produced
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

    fn submit_operation(&mut self, operation: BlockstackOperationType, op_signer: &mut BurnchainOpSigner) {
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
                panic!("Failed to assemble transaction");
            }
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
    txid: String,
    vout: u32,
    script_pub_key: String,
    amount: serde_json::Number,
    confirmations: u32,
    spendable: bool,
    solvable: bool,
    desc: Option<String>,
    safe: bool,
}

impl UTXO {

    pub fn get_txid(&self) -> Sha256dHash {
        let mut txid = hex_bytes(&self.txid).expect("Invalid byte sequence");
        txid.reverse();
        Sha256dHash::from(&txid[..])
    }

    pub fn get_sat_amount(&self) -> u64 {
        UTXO::serialized_btc_to_sat(&self.amount.to_string())
    }

    pub fn serialized_btc_to_sat(amount: &str) -> u64 {
        let comps: Vec<&str> = amount.split(".").collect();
        match comps[..] {
            [lhs, rhs] => {
                let base: u64 = 10;
                let sat_decimals = 8;
                let btc_to_sat = base.pow(8);
                let btc = lhs.parse::<u64>().expect("Invalid amount");
                let mut amount = btc * btc_to_sat;
                if rhs.len() > sat_decimals { 
                    panic!("Unexpected amount of decimals");
                }
                let rhs = format!("{:0<width$}", rhs, width = sat_decimals);
                let sat = rhs.parse::<u64>().expect("Invalid amount");
                amount += sat;
                amount
            },
            _ => panic!("Invalid amount")
        }    
    } 

    pub fn sat_to_serialized_btc(amount: u64) -> String {
        let sat_decimals = 8;
        let fmt = format!("{:0width$}", amount, width = sat_decimals);
        let amount = if fmt.len() == sat_decimals {
            format!("0.{}", &fmt[fmt.len() - sat_decimals..])
        } else {
            format!("{}.{}", &fmt[0..(fmt.len() - sat_decimals)], &fmt[fmt.len() - sat_decimals..])
        };
        amount
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
    Network(String),
    Parsing(String)
}

type RPCResult<T> = Result<T, RPCError>;

impl BitcoinRPCRequest {

    pub fn generate_to_address(request_builder: RequestBuilder, num_blocks: u64, address: String) -> RPCResult<()> {
        debug!("Generate {} blocks to {}", num_blocks, address);
        let payload = BitcoinRPCRequest {
            method: "generatetoaddress".to_string(),
            params: vec![num_blocks.into(), address.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        BitcoinRPCRequest::send(request_builder, payload)?;
        Ok(())
    }

    pub fn list_unspent(request_builder: RequestBuilder, addresses: Vec<String>, include_unsafe: bool, minimum_sum_amount: u64) -> RPCResult<Vec<UTXO>> {
        let min_conf = 0;
        let max_conf = 9999999;
        let min_sum_amount = UTXO::sat_to_serialized_btc(minimum_sum_amount);

        let payload = BitcoinRPCRequest {
            method: "listunspent".to_string(),
            params: vec![
                min_conf.into(), 
                max_conf.into(), 
                addresses.into(), 
                include_unsafe.into(),
                json!({
                    "minimumSumAmount": min_sum_amount
                })],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let mut res = BitcoinRPCRequest::send(request_builder, payload)?;
        let mut utxos = vec![];

        match res.as_object_mut() {
            Some(ref mut object) => {
                match object.get_mut("result") {
                    Some(serde_json::Value::Array(entries)) => {
                        info!("Response: {:?}", entries); 
                        while let Some(entry) = entries.pop() { 
                            match serde_json::from_value(entry) {
                                Ok(utxo) => { utxos.push(utxo); },
                                Err(e) => {
                                    warn!("Failed to parse: {}", e);
                                }
                            }
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

        BitcoinRPCRequest::send(request_builder, payload)?;
        Ok(())
    }

    pub fn import_public_key(request_builder: RequestBuilder, public_key: &Secp256k1PublicKey) -> RPCResult<()> {
        let rescan = true;
        let label = "";

        let pkh = Hash160::from_data(&public_key.to_bytes()).to_bytes().to_vec();
        let address = BitcoinAddress::from_bytes(
            BitcoinNetworkType::Regtest,
            BitcoinAddressType::PublicKeyHash,
            &pkh)
            .expect("Public key incorrect");        

        let payload = BitcoinRPCRequest {
            method: "importaddress".to_string(),
            params: vec![address.to_b58().into(), label.into(), rescan.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        BitcoinRPCRequest::send(request_builder, payload)?;
        Ok(())
    }

    fn send(request_builder: RequestBuilder, payload: BitcoinRPCRequest) -> RPCResult<serde_json::Value> {
        let body = json!(payload);
        let result = request_builder.json(&body).send();
        let response = result
            .map_err(|e| RPCError::Network(format!("RPC Error: {}", e)))?;
        let payload = response.json::<serde_json::Value>()
            .map_err(|e| RPCError::Parsing(format!("RPC Error: {}", e)))?;
        Ok(payload)
    }
}
