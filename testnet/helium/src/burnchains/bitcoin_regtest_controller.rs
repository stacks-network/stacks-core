use std::io::Cursor;

use bitcoincore_rpc::{Auth, Client, RpcApi, RawTx};

use secp256k1::{Secp256k1};

use super::{BurnchainController, BurnchainTip};
use super::super::operations::{BurnchainOperationType, LeaderKeyRegisterPayload, LeaderBlockCommitPayload, UserBurnSupportPayload, BurnchainOpSigner};
use super::super::Config;

use stacks::burnchains::Burnchain;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::bitcoin::indexer::{BitcoinIndexer, BitcoinIndexerRuntime, BitcoinIndexerConfig};
use stacks::burnchains::bitcoin::spv::SpvClient; 
use stacks::burnchains::PublicKey;
use stacks::chainstate::burn::db::burndb::{BurnDB};
use stacks::deps::bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut, OutPoint};
use stacks::deps::bitcoin::blockdata::opcodes;
use stacks::deps::bitcoin::blockdata::script::{Script, Builder};
use stacks::deps::bitcoin::network::encodable::ConsensusEncodable;
use stacks::deps::bitcoin::network::serialize::RawEncoder;
use stacks::deps::bitcoin::util::hash::Sha256dHash;
use stacks::net::StacksMessageCodec;
use stacks::util::hash::{Hash160, hex_bytes};
use stacks::util::secp256k1::{Secp256k1PublicKey};
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
        let network = self.config.burnchain.network.clone();
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

        // todo(ludo): revisit this implementation
        let rest = match &state_transition {
            None => self.chain_tip.clone().unwrap(),
            Some(state_transition) => {
                let burnchain_tip = BurnchainTip {
                    block_snapshot: block_snapshot,
                    state_transition: state_transition.clone()
                };
                self.chain_tip = Some(burnchain_tip.clone());
                burnchain_tip
            }
        };
        rest
    }

    fn get_rpc_client(&self) -> Client {
        let auth = match (&self.config.burnchain.username, &self.config.burnchain.password) {
            (Some(username), Some(password)) => Auth::UserPass(username.clone(), password.clone()),
            (_, _) => Auth::None
        };

        let rpc = Client::new(
            self.config.burnchain.get_rpc_url(),
            auth
        ).expect("Bitcoin RPC failure: server unreachable");
        rpc
    }

    fn get_utxo(&self, public_key: &Secp256k1PublicKey, amount_required: u64) -> Option<UTXO> {

        use super::super::bitcoincore_rpc::bitcoin::{PublicKey, Address, Network};

        // Init RPC Client
        let rpc = self.get_rpc_client();

        // Configure UTXO filter
        let public_key = PublicKey::from_slice(&public_key.to_bytes()).unwrap();
        let address = Address::p2pkh(&public_key, Network::Regtest);
        let filter_addresses = [address];

        // Perform request
        let mut utxos = match rpc.list_unspent(
            None, 
            None,         
            Some(&filter_addresses[..]), 
            Some(false), 
            None) {
                Ok(utxos) => utxos,
                Err(e) => {
                    error!("Bitcoin RPC failure: error listing utxos {:?}", e);
                    panic!();    
                }
        };

        if utxos.len() == 0 {
            println!("Got 0 UTXO. Importing address {}", public_key);

            let _res = rpc.import_public_key(&public_key, None, Some(true));
            
            // todo(ludo): rescan can take time. Find a better approach
            sleep_ms(1000);

            utxos = match rpc.list_unspent(
                None, 
                None,         
                Some(&filter_addresses[..]), 
                Some(false), 
                None) {
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

        // todo(ludo): select the correct utxo (amount)
        let mut result = utxos[0].clone();
        
        let txid = match Sha256dHash::from_hex(&format!("{}", result.txid)) {
            Ok(txid) => txid,
            _ => return None
        };

        let redeem_script: Option<Script> = match result.redeem_script.take() {
            Some(script) => Some(script.to_bytes().into()),
            None => None,
        };
        
        let witness_script: Option<Script> = match result.witness_script.take() {
            Some(script) => Some(script.to_bytes().into()),
            None => None,
        };

        let script_pub_key = result.script_pub_key.to_bytes().into();

        let utxo = UTXO {
            txid: txid,
            vout: result.vout,
            redeem_script: redeem_script,
            witness_script: witness_script,
            script_pub_key: script_pub_key,
            amount: result.amount.as_sat(),
            confirmations: result.confirmations,
            spendable: result.spendable,
            solvable: result.solvable,
            descriptor: result.descriptor,
            safe: result.safe,
        };

        Some(utxo)
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
        let utxo = match self.get_utxo(&public_key, amount_required) {
            Some(utxo) => utxo,
            None => return None
        };

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

        // Prepare a backbone for the tx
        let transaction = Transaction {
            input: vec![input],
            output: vec![],
            version: 1,
            lock_time: 0,
        };

        Some((transaction, vec![utxo]))
    }

    fn finalize_tx(&self, tx: &mut Transaction, total_spent: u64, utxos: Vec<UTXO>, signer: &mut BurnchainOpSigner) {

        let tx_fee = self.config.burnchain.burnchain_op_tx_fee;

        // Append the change output
        let total_unspent: u64 = utxos.iter().map(|o| o.amount).sum();
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
            let script_pub_key = utxo.script_pub_key.clone().to_bytes().into();
    
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
        let rpc = self.get_rpc_client();

        match rpc.send_raw_transaction(transaction) {
            Ok(_) => true,
            Err(e) =>  {
                error!("Bitcoin RPC failure: transaction submission failed - {:?}", e);
                false
            } 
        }
    }

    fn build_next_block(&self, public_key_str: &String, num_blocks: u64) {

        use super::super::bitcoincore_rpc::bitcoin::{PublicKey, Address, Network};

        let public_key = hex_bytes(public_key_str).expect("Mining public key byte sequence invalid");
        let coinbase_public_key = PublicKey::from_slice(&public_key).expect("Mining public key invalid");
        let address = Address::p2pkh(&coinbase_public_key, Network::Regtest);

        let rpc = self.get_rpc_client();
        match rpc.generate_to_address(num_blocks, &address) {
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

        // todo(ludo): revisit this approach

        let network = self.config.burnchain.network.clone();
        let working_dir = self.config.get_burn_db_path();
        let burnchain = Burnchain::new(
            &working_dir,
            &self.config.burnchain.chain, 
            &network)
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
            sleep_ms(self.config.burnchain.block_time);
            self.build_next_block(local_mining_pk, 1);
        }

        self.receive_blocks()
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
        use super::super::bitcoincore_rpc::bitcoin::{PublicKey, Address, Network};

        if let Some(local_mining_pubkey) = &self.config.burnchain.local_mining_public_key {

            let public_key = hex_bytes(local_mining_pubkey).expect("Mining public key byte sequence invalid");
            let coinbase_public_key = PublicKey::from_slice(&public_key).expect("Mining public key invalid");
            let address = Address::p2pkh(&coinbase_public_key, Network::Regtest);
    
            let rpc = self.get_rpc_client();

            let _res = rpc.import_public_key(
                &coinbase_public_key, 
                None, 
                Some(true));

            let res = rpc.generate_to_address(
                201, 
                &address);

            match res {
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
}

impl RawTx for SerializedTx {
    fn raw_hex(self) -> String {
        let formatted_bytes: Vec<String> = self.bytes.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}", formatted_bytes.join(""))
    }
}


#[derive(Debug, Clone)]
pub struct UTXO {
    pub txid: Sha256dHash,
    pub vout: u32,
    pub redeem_script: Option<Script>,
    pub witness_script: Option<Script>,
    pub script_pub_key: Script,
    pub amount: u64,
    pub confirmations: u32,
    pub spendable: bool,
    pub solvable: bool,
    pub descriptor: Option<String>,
    pub safe: bool,
}
