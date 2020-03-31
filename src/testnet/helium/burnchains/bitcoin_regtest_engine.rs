use std::collections::VecDeque;
use std::sync::mpsc;
use std::thread;
use std::time;
use std::sync::{Arc, Mutex};
use std::io::Cursor;

use super::super::bitcoincore_rpc::{Auth, Client, RpcApi, RawTx};
use super::super::bitcoincore_rpc::bitcoincore_rpc_json::ListUnspentResultEntry;


use super::{Config, BurnchainEngine, BurnchainState, BurnchainOperationSigningDelegate};
use super::super::operations::{BurnchainOperationType, LeaderKeyRegisterPayload, LeaderBlockCommitPayload, UserBurnSupportPayload};

use burnchains::{Burnchain, BurnchainBlockHeader, BurnchainHeaderHash, BurnchainBlock, Txid, BurnchainSigner};
use burnchains::bitcoin::{BitcoinBlock, BitcoinNetworkType};
use burnchains::bitcoin::indexer::{BitcoinIndexer, BitcoinIndexerRuntime, BitcoinIndexerConfig};
use burnchains::indexer::BurnchainIndexer;
use burnchains::{PrivateKey, PublicKey};
use chainstate::burn::db::burndb::{BurnDB};
use chainstate::burn::{BlockSnapshot};
use chainstate::burn::operations::{BlockstackOperationType};
use deps::bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut, OutPoint, SigHashType};
use deps::bitcoin::blockdata::opcodes;
use deps::bitcoin::blockdata::script::{Script, Builder};
use deps::bitcoin::network::message::NetworkMessage;
use deps::bitcoin::network::encodable::ConsensusEncodable;
use deps::bitcoin::network::serialize::RawEncoder;
use deps::bitcoin::util::hash::Sha256dHash;
use util::hash::{Sha256Sum, Hash160};
use util::get_epoch_time_secs;

/// BurnchainSimulatorEngine is simulating a simplistic burnchain.
pub struct BitcoinRegtestEngine {
    config: Config,
    indexer_config: BitcoinIndexerConfig,
    db: Option<BurnDB>,
    chain_tip: Option<BlockSnapshot>,
}

impl RawTx for Transaction {
    fn raw_hex(self) -> String {
        let mut encoder = RawEncoder::new(Cursor::new(vec![]));
        self.consensus_encode(&mut encoder).expect("BUG: failed to serialize to a vec");
        let bytes: Vec<u8> = encoder.into_inner().into_inner(); 
        let formatted_bytes: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}", formatted_bytes.join(""))
    }
}

impl BurnchainEngine for BitcoinRegtestEngine {

    fn new(config: Config) -> Self {
        
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

    fn burndb_mut(&mut self) -> &mut BurnDB {
        match self.db {
            Some(ref mut burndb) => burndb,
            None => {
                unreachable!();
            }
        }
    }
    
    fn get_chain_tip(&mut self) -> BlockSnapshot {
        match &self.chain_tip {
            Some(chain_tip) => chain_tip.clone(),
            None => {
                unreachable!();
            }
        }
    }


    fn start(&mut self) -> BurnchainState {
        self.sync()
    }

    fn sync(&mut self) -> BurnchainState {

        let network_name = self.config.burnchain.mode.clone();
        let working_dir = self.config.get_burn_db_path();
        let mut burnchain = Burnchain::new(
            &working_dir,
            &self.config.burnchain.chain, 
            &network_name) // todo(ludo): rename to network
        .map_err(|e| {
            error!("Failed to instantiate burn chain driver for {}: {:?}", network_name, e);
            e
        }).unwrap();

        let indexer_runtime = BitcoinIndexerRuntime::new(BitcoinNetworkType::Regtest);
        let mut burnchain_indexer = BitcoinIndexer {
            config: self.indexer_config.clone(),
            runtime: indexer_runtime
        };

        let chain_tip = burnchain.sync_with_indexer(&mut burnchain_indexer).unwrap();
        self.chain_tip = Some(chain_tip.clone());

        BurnchainState {
            chain_tip, 
            ops: vec![]
        }
    }

    fn submit_operation<T: BurnchainOperationSigningDelegate>(&mut self, operation: BurnchainOperationType, signer: &mut T) {

        // Path                 m/0'/0'/0'
        // Mnemonic             velvet life opinion obvious depart swarm butter seven sibling before dry hint
        // Extended Private Key tprv8hCYUJ7fULoMQoKd8J5WMs8Hjg1j56MFx1ynnYaiHdC9pbxzQrTf7iyigPYT3veswZTYRm115tQorbCKgwPCpft3QzfLUXW1iPwtkrdh2H1
        // Extended Public Key  tpubDDtaci9uciV2JGMR1wk6mGnQJhXfERYAXKaa54d1htzYf6Dm3FHFJDbarVk15QfjgtjQyrNy6VgUJo6Aur542BJaa7CRNxkGsDDor6DodZ7
        // Private Key          cNzWH1eDJFRdwdLVmTjsiMKUGX5bwxkg63ivT7vemrJrFsFjQAw8
        //                      2A154248F5BA1927750104FFEF791AEC863E34ED8AF69D5299D23CD07AD38F3601
        // Public Key           032fd788a3571255ff03839a0f859073d96fc34c4e247699ab3cc18cdd892e9540
        // Address              mwCjju3UZ99HBDwqgDGPa5bGD4W6qZCcPQ
        // Format               p2sh_p2wpkh
        // Network              testnet
        // Compressed           true

        // todo: we should be testing the address: bech32 vs legacy vs segwit
        // p2pkh
        // p2spkh

        let transaction = match operation {
            BurnchainOperationType::LeaderBlockCommit(payload) => self.build_leader_block_commit_tx(payload, signer),
            BurnchainOperationType::LeaderKeyRegister(payload) => self.build_leader_key_register_tx(payload, signer),
            BurnchainOperationType::UserBurnSupport(payload) => self.build_user_burn_support_tx(payload, signer)
        };

        let transaction = match transaction {
            Some(tx) => tx,
            _ => return
        };

        self.send_transaction(transaction);
    }
}

impl BitcoinRegtestEngine {

    fn get_rpc_client(&self) -> Client {
        let rpc = Client::new(
            "http://127.0.0.1:18443".to_string(),
            Auth::UserPass(
                "helium-node".to_string(),
                "secret".to_string()
            )
        ).unwrap(); //todo(ludo): safe unwrap
        rpc
    }

    fn get_utxo(&self) -> Option<UnspentOutput> {
        // Init RPC Client
        let rpc = self.get_rpc_client();

        // todo(ludo): filter unspent outputs - fine for now, we only have one miner / address
        let utxos = rpc.list_unspent(None, None, None, Some(false), None).unwrap();

        println!("{:?}", utxos);
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

        let utxo = UnspentOutput {
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

    // LeaderKeyRegisterPayload, LeaderBlockCommitPayload, UserBurnSupportPayload}
    fn build_leader_key_register_tx<T: BurnchainOperationSigningDelegate>(&mut self, payload: LeaderKeyRegisterPayload, signer: &mut T) -> Option<Transaction> {

        let utxo = match self.get_utxo() {
            Some(utxo) => utxo,
            None => return None
        };

        let previous_output = OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        };
        let previous_output_amount = utxo.amount;

        let session_id = signer.create_session();
        // todo(ludo): safe unwrap
        let public_key = signer.get_public_key(&session_id).unwrap();

        let hashed_pubk = Hash160::from_data(&public_key.to_bytes_compressed());

        let script_sig = Builder::new()
            .push_opcode(opcodes::All::OP_PUSHBYTES_22)
            .push_scriptint(0)
            .push_slice(&hashed_pubk[..])
            .into_script();

        let input = TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: 0xFFFFFFFF,
            witness: vec![],
        };

        let op = b"Hello world";
        let output_script = Builder::new()
            .push_opcode(opcodes::All::OP_RETURN)
            .push_slice(op)
            .into_script(); 
        let consensus_output = TxOut {
            value: 0,
            script_pubkey: output_script,
        };

        let hashed_pubk = Hash160::from_data(&public_key.to_bytes_compressed());
        let next_output = TxOut {
            value: 4999990000, //previous_output_amount - pob_fee - tx_fee,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::All::OP_DUP)
                .push_opcode(opcodes::All::OP_HASH160)
                .push_slice(&hex_bytes("E867B2C4DE8E972A1BFC621FCDB86801F59F4E2F").unwrap())//&hashed_pubk[..])
                .push_opcode(opcodes::All::OP_EQUALVERIFY)
                .push_opcode(opcodes::All::OP_CHECKSIG)
                .into_script()
        };

        let mut transaction = Transaction {
            input: vec![input],
            output: vec![consensus_output, next_output],
            version: 1,
            lock_time: 0,
        };

        let script_pub_key = utxo.script_pub_key.clone().to_bytes().into();

        use util::hash::hex_bytes;
        let sig_hash_all = 0x01;
        let sig_hash = transaction.signature_hash(0, &script_pub_key, sig_hash_all);   

        use secp256k1::{Secp256k1};

        let mut sig1_der = {
            let secp = Secp256k1::new();
            let message = signer.sign_message(&session_id, sig_hash.as_bytes()).unwrap();
            let der = message.to_secp256k1_recoverable().unwrap().to_standard(&secp).serialize_der(&secp);
            der
        };
        sig1_der.push(0x01);

        transaction.input[0].script_sig = Builder::new()
            .push_slice(&sig1_der[..])
            .push_slice(&public_key.to_bytes_compressed())
            .into_script(); 

        signer.close_session(&session_id);
        
        Some(transaction)
    }

    fn build_leader_block_commit_tx<T: BurnchainOperationSigningDelegate>(&mut self, payload: LeaderBlockCommitPayload, signer: &mut T) -> Option<Transaction> {
        None
    }

    fn build_user_burn_support_tx<T: BurnchainOperationSigningDelegate>(&mut self, payload: UserBurnSupportPayload, signer: &mut T) -> Option<Transaction> {
        unimplemented!()
    }

    fn send_transaction(&self, transaction: Transaction) -> bool {
        let rpc = self.get_rpc_client();

        match rpc.send_raw_transaction(transaction) {
            Ok(_) => true,
            _ => false
        }
    }

    // pub fn submit_block_commit_op(&mut self, pob_fee: u64, tx_fee: u64) {

    //     use util::secp256k1::{Secp256k1PublicKey, Secp256k1PrivateKey};
    //     use util::hash::Hash160;

    //     // Path                 m/0'/0'/0'
    //     // Mnemonic             velvet life opinion obvious depart swarm butter seven sibling before dry hint
    //     // Extended Private Key tprv8hCYUJ7fULoMQoKd8J5WMs8Hjg1j56MFx1ynnYaiHdC9pbxzQrTf7iyigPYT3veswZTYRm115tQorbCKgwPCpft3QzfLUXW1iPwtkrdh2H1
    //     // Extended Public Key  tpubDDtaci9uciV2JGMR1wk6mGnQJhXfERYAXKaa54d1htzYf6Dm3FHFJDbarVk15QfjgtjQyrNy6VgUJo6Aur542BJaa7CRNxkGsDDor6DodZ7
    //     // Private Key          cNzWH1eDJFRdwdLVmTjsiMKUGX5bwxkg63ivT7vemrJrFsFjQAw8
    //     //                      2A154248F5BA1927750104FFEF791AEC863E34ED8AF69D5299D23CD07AD38F3601
    //     // Public Key           032fd788a3571255ff03839a0f859073d96fc34c4e247699ab3cc18cdd892e9540
    //     // Address              mwCjju3UZ99HBDwqgDGPa5bGD4W6qZCcPQ
    //     // Format               p2sh_p2wpkh
    //     // Network              testnet
    //     // Compressed           true

    //     // todo: we should be testing the address: bech32 vs legacy vs segwit
    //     // p2pkh
    //     // p2spkh

    //     let pubk = Secp256k1PublicKey::from_hex("032fd788a3571255ff03839a0f859073d96fc34c4e247699ab3cc18cdd892e9540").unwrap();
    //     let seck = Secp256k1PrivateKey::from_hex("2A154248F5BA1927750104FFEF791AEC863E34ED8AF69D5299D23CD07AD38F3601").unwrap();

    //     // Init RPC Client
    //     let rpc = Client::new("http://127.0.0.1:18443".to_string(),
    //     Auth::UserPass(
    //         "helium-node".to_string(),
    //         "secret".to_string())).unwrap();

    //     // todo(ludo): filter unspent outputs - fine for now, we only have one miner / address
    //     let utxos = rpc.list_unspent(None, None, None, Some(false), None).unwrap();
        
    //     println!("{:?}", utxos);

    //     // todo(ludo): select the correct utxo (amount)
    //     let utxo = utxos[0].clone();

    //     let previous_output = OutPoint {
    //         txid: Sha256dHash::from_hex(&format!("{}", utxo.txid)).unwrap(),
    //         vout: utxo.vout,
    //     };
    //     let previous_output_amount = utxo.amount.as_sat();

    //     let hashed_pubk = Hash160::from_data(&pubk.to_bytes_compressed());

    //     let script_sig = Builder::new()
    //         .push_opcode(opcodes::All::OP_PUSHBYTES_22)
    //         .push_scriptint(0)
    //         .push_slice(&hashed_pubk[..])
    //         .into_script();

    //     let input = TxIn {
    //         previous_output,
    //         script_sig: Script::new(),
    //         sequence: 0xFFFFFFFF,
    //         witness: vec![],
    //     };

    //     let op = b"Hello world";
    //     let output_script = Builder::new()
    //         .push_opcode(opcodes::All::OP_RETURN)
    //         .push_slice(op)
    //         .into_script(); 
    //     let consensus_output = TxOut {
    //         value: pob_fee,
    //         script_pubkey: output_script,
    //     };

    //     let hashed_pubk = Hash160::from_data(&pubk.to_bytes_compressed());
    //     let next_output = TxOut {
    //         value: 4999990000, //previous_output_amount - pob_fee - tx_fee,
    //         script_pubkey: Builder::new()
    //             .push_opcode(opcodes::All::OP_DUP)
    //             .push_opcode(opcodes::All::OP_HASH160)
    //             .push_slice(&hex_bytes("E867B2C4DE8E972A1BFC621FCDB86801F59F4E2F").unwrap())//&hashed_pubk[..])
    //             .push_opcode(opcodes::All::OP_EQUALVERIFY)
    //             .push_opcode(opcodes::All::OP_CHECKSIG)
    //             .into_script()
    //     };

    //     let mut transaction = Transaction {
    //         input: vec![input],
    //         output: vec![consensus_output, next_output],
    //         version: 1,
    //         lock_time: 0,
    //     };

    //     let script_pub_key = utxo.script_pub_key.clone().to_bytes().into();

    //     use util::hash::hex_bytes;
    //     let sig_hash_all = 0x01;
    //     let sig_hash = transaction.signature_hash(0, &script_pub_key, sig_hash_all);   

    //     use secp256k1::{Secp256k1};

    //     let mut sig1_der = {
    //         let secp = Secp256k1::new();
    //         let message = seck.sign(sig_hash.as_bytes()).unwrap();
    //         let der = message.to_secp256k1_recoverable().unwrap().to_standard(&secp).serialize_der(&secp);
    //         der
    //     };
    //     sig1_der.push(0x01);

    //     transaction.input[0].script_sig = Builder::new()
    //         .push_slice(&sig1_der[..])
    //         .push_slice(&pubk.to_bytes_compressed())
    //         .into_script(); 
        
    //     let txid = rpc.send_raw_transaction(transaction).unwrap();
    // }

    // pub fn submit_block_commit_op(&mut self, pob_fee: u64, tx_fee: u64) {

    //     use util::secp256k1::{Secp256k1PublicKey, Secp256k1PrivateKey};
    //     use util::hash::Hash160;

    //     // Path                 m/0'/0'/0'
    //     // Mnemonic             velvet life opinion obvious depart swarm butter seven sibling before dry hint
    //     // Extended Private Key tprv8hCYUJ7fULoMQoKd8J5WMs8Hjg1j56MFx1ynnYaiHdC9pbxzQrTf7iyigPYT3veswZTYRm115tQorbCKgwPCpft3QzfLUXW1iPwtkrdh2H1
    //     // Extended Public Key  tpubDDtaci9uciV2JGMR1wk6mGnQJhXfERYAXKaa54d1htzYf6Dm3FHFJDbarVk15QfjgtjQyrNy6VgUJo6Aur542BJaa7CRNxkGsDDor6DodZ7
    //     // Private Key          cVbfSfoDGR15u8JYwFpdUbPsnHLUUbjUCaridhWY8qBrX3LsRRpA
    //     //                      EF31AD580B8EF544BABC07A0F012CAA14FD2D19B2FB3DCAACC19C286C4605AEA01
    //     // Public Key           028cc6ddf7ed5465ccf98fcf19ebe130a49dfee229be45fbb3bffd2a9cb9a88792
    //     // Address              2NES4yseEMYqoSFE9sGR3EjvUZyE2RSb42A        
    //     // Format               p2sh_p2wpkh
    //     // Network              testnet
    //     // Compressed           true

    //     // todo: we should be testing the address: bech32 vs legacy vs segwit
    //     // p2pkh
    //     // p2spkh

    //     let pubk = Secp256k1PublicKey::from_hex("032fd788a3571255ff03839a0f859073d96fc34c4e247699ab3cc18cdd892e9540").unwrap();
    //     let seck = Secp256k1PrivateKey::from_hex("2A154248F5BA1927750104FFEF791AEC863E34ED8AF69D5299D23CD07AD38F3601").unwrap();

    //     // Init RPC Client
    //     let rpc = Client::new("http://127.0.0.1:18443".to_string(),
    //     Auth::UserPass(
    //         "helium-node".to_string(),
    //         "secret".to_string())).unwrap();

    //     // todo(ludo): filter unspent outputs - fine for now, we only have one miner / address
    //     let utxos = rpc.list_unspent(None, None, None, Some(false), None).unwrap();
        
    //     // todo(ludo): select the correct utxo (amount)
    //     let utxo = utxos[0].clone();

    //     let previous_output = OutPoint {
    //         txid: Sha256dHash::from_hex(&format!("{}", utxo.txid)).unwrap(),
    //         vout: utxo.vout,
    //     };

    //     let script_pub_key: Script = utxo.redeem_script.clone().unwrap().to_bytes().into();
    //     let script_pub_key = script_pub_key.to_p2sh();

    //     let hashed_pubk = Hash160::from_data(&pubk.to_bytes_compressed());

    //     let input = TxIn {
    //         previous_output,
    //         script_sig: Script::new(),
    //         sequence: 0xFFFFFFFF,
    //         witness: vec![],
    //     };

    //     let op = b"Hello world";
    //     let output_script = Builder::new()
    //         .push_opcode(opcodes::All::OP_RETURN)
    //         .push_slice(op)
    //         .into_script(); 
    //     let consensus_output = TxOut {
    //         value: pob_fee,
    //         script_pubkey: output_script,
    //     };

    //     let hashed_pubk = Hash160::from_data(&pubk.to_bytes_compressed());
    //     let next_output = TxOut {
    //         value: 4999990000, //previous_output_amount - pob_fee - tx_fee,
    //         script_pubkey: Builder::new()
    //             .push_opcode(opcodes::All::OP_HASH160)
    //             .push_slice(&hex_bytes("E867B2C4DE8E972A1BFC621FCDB86801F59F4E2F").unwrap())//&hashed_pubk[..])
    //             .push_opcode(opcodes::All::OP_EQUAL)
    //             .into_script()
    //     };

    //     let mut transaction = Transaction {
    //         input: vec![input],
    //         output: vec![next_output],
    //         version: 2,
    //         lock_time: 0,
    //     };

    //     use util::hash::hex_bytes;
    //     let sig_hash_all = 0x01;
    //     let message_template = transaction.signature_hash(0, &script_pub_key, sig_hash_all);   
    //     let sig_hash = Sha256dHash::from_data(&message_template);

    //     use secp256k1::{Secp256k1};

    //     let mut sig1_der = {
    //         let secp = Secp256k1::new();
    //         let message = seck.sign(sig_hash.as_bytes()).unwrap();
    //         let der = message.to_secp256k1_recoverable().unwrap().to_standard(&secp).serialize_der(&secp);
    //         der
    //     };
    //     sig1_der.push(0x01);

    //     transaction.input[0].witness = vec![sig1_der, pubk.to_bytes_compressed()];
    //     transaction.input[0].script_sig = script_pub_key;

    //     println!("{:?}", transaction.clone().raw_hex());

    //     let txid = rpc.send_raw_transaction(transaction).unwrap();
    // }


    // pub fn submit_block_commit_op(&mut self, pob_fee: u64, tx_fee: u64) {

    //     use util::secp256k1::{Secp256k1PublicKey, Secp256k1PrivateKey};
    //     use util::hash::Hash160;

    //     // Path                 m/0'/0'/0'
    //     // Mnemonic             velvet life opinion obvious depart swarm butter seven sibling before dry hint
    //     // Extended Private Key tprv8hCYUJ7fULoMQoKd8J5WMs8Hjg1j56MFx1ynnYaiHdC9pbxzQrTf7iyigPYT3veswZTYRm115tQorbCKgwPCpft3QzfLUXW1iPwtkrdh2H1
    //     // Extended Public Key  tpubDDtaci9uciV2JGMR1wk6mGnQJhXfERYAXKaa54d1htzYf6Dm3FHFJDbarVk15QfjgtjQyrNy6VgUJo6Aur542BJaa7CRNxkGsDDor6DodZ7
    //     // Private Key          cVbfSfoDGR15u8JYwFpdUbPsnHLUUbjUCaridhWY8qBrX3LsRRpA
    //                             // EF31AD580B8EF544BABC07A0F012CAA14FD2D19B2FB3DCAACC19C286C4605AEA01  
    //     //                      EF31AD580B8EF544BABC07A0F012CAA14FD2D19B2FB3DCAACC19C286C4605AEA01
    //     // Public Key           028cc6ddf7ed5465ccf98fcf19ebe130a49dfee229be45fbb3bffd2a9cb9a88792
    //     // Address              2NES4yseEMYqoSFE9sGR3EjvUZyE2RSb42A
    //     // Format               p2sh_p2wpkh
    //     // Network              testnet
    //     // Compressed           true

    //     // todo: we should be testing the address: bech32 vs legacy vs segwit
    //     // p2pkh
    //     // p2spkh

    //     let pubk = Secp256k1PublicKey::from_hex("028cc6ddf7ed5465ccf98fcf19ebe130a49dfee229be45fbb3bffd2a9cb9a88792").unwrap();
    //     let seck = Secp256k1PrivateKey::from_hex("EF31AD580B8EF544BABC07A0F012CAA14FD2D19B2FB3DCAACC19C286C4605AEA01").unwrap();

    //     // Init RPC Client
    //     let rpc = Client::new("http://127.0.0.1:18443".to_string(),
    //     Auth::UserPass(
    //         "helium-node".to_string(),
    //         "secret".to_string())).unwrap();

    //     // todo(ludo): filter unspent outputs - fine for now, we only have one miner / address
    //     let utxos = rpc.list_unspent(None, None, None, Some(false), None).unwrap();
        
    //     // todo(ludo): select the correct utxo (amount)
    //     let utxo = utxos[0].clone();
    //     println!("UTXO: {:?}", utxo);

    //     let previous_output = OutPoint {
    //         txid: Sha256dHash::from_hex(&format!("{}", utxo.txid)).unwrap(),
    //         vout: utxo.vout,
    //     };
    //     let previous_output_amount = utxo.amount.as_sat();

    //     // transaction.input[0].script_sig
    //     let hashed_pubk = Hash160::from_data(&pubk.to_bytes_compressed());

    //     let script_sig = Builder::new()
    //         .push_opcode(opcodes::All::OP_PUSHBYTES_22)
    //         .push_scriptint(0)
    //         .push_slice(&hashed_pubk[..])
    //         .into_script();

    //     let input = TxIn {
    //         previous_output,
    //         script_sig: script_sig.clone(),
    //         sequence: 0xFFFFFFFF,
    //         witness: vec![vec![]],
    //     };

    //     let op = b"Hello world";
    //     let output_script = Builder::new()
    //         .push_opcode(opcodes::All::OP_RETURN)
    //         .push_slice(op)
    //         .into_script(); 
    //     let consensus_output = TxOut {
    //         value: pob_fee,
    //         script_pubkey: output_script,
    //     };

    //     let hashed_pubk = Hash160::from_data(&pubk.to_bytes_compressed());
    //     let next_output = TxOut {
    //         value: 4999990000, //previous_output_amount - pob_fee - tx_fee,
    //         script_pubkey: Builder::new()
    //             .push_opcode(opcodes::All::OP_HASH160)
    //             .push_slice(&hex_bytes("E867B2C4DE8E972A1BFC621FCDB86801F59F4E2F").unwrap())//&hashed_pubk[..])
    //             .push_opcode(opcodes::All::OP_EQUAL)
    //             .into_script()
    //     };

    //     let mut transaction = Transaction {
    //         input: vec![input],
    //         output: vec![next_output],
    //         // output: vec![consensus_output, next_output],
    //         version: 2,
    //         lock_time: 0,
    //     };

    //     let script_pub_key = script_sig.clone(); // utxo.redeem_script.clone().unwrap().to_bytes().into();

    //     // From BITCOIN-CLI
    //     // 020000000162c300ad1c85a26f9702a2eeb0f94d11ab43b2558c887bd16f97d59e7445a0a60000000000ffffffff01f0ca052a0100000017a914e867b2c4de8e972a1bfc621fcdb86801f59f4e2f8700000000";
    //     // 020000000162c300ad1c85a26f9702a2eeb0f94d11ab43b2558c887bd16f97d59e7445a0a60000000000ffffffff011fa107000000000017a9147df3dd3023c76b4223143d964de942d435d61a9b870000000000000000
    //     use util::hash::hex_bytes;
    //     let sig_hash_all = 0x01;
    //     let mut message_template = transaction.signature_hash(0, &script_pub_key, sig_hash_all);   
    //     message_template.push(0x01);
    //     let formatted_bytes: Vec<String> = message_template.iter().map(|b| format!("{:02x}", b)).collect();
    //     println!("UNSIGNED: {}", formatted_bytes.join(""));
        
    //     let sig_hash = Sha256dHash::from_data(&message_template);

    //     println!("HASH: {}", sig_hash.le_hex_string());
    //     // let sig_hash = Sha256dHash::from_data(&hex_bytes("30450221008183aaa8d7c695f87e1e7bc81a934fe9ec5e14cc378e01e691c7b9136e5dc7070220600d85be3e469542eb77a29d584aa3400b9ca94a2a02943b9913321a7a18756001").unwrap());
        
    //     // let sig1 = seck.sign(sig_hash.as_bytes()).unwrap();
    //     // use secp256k1::{Secp256k1, Signature};
    //     use secp256k1::{Secp256k1, Message, SecretKey, PublicKey, Signature};

    //     let mut sig1_der = {
    //         let secp = Secp256k1::new();
    //         let message = seck.sign(sig_hash.as_bytes()).unwrap();
    //         let der = message.to_secp256k1_recoverable().unwrap().to_standard(&secp).serialize_der(&secp);
    //         der
    //     };
    //     sig1_der.push(0x01);
    //     // transaction.input[0].script_sig = script_sig;

    //     // 0x81 0086f7705203aa102321220ab83853ae821ea6ada07d4b1266288b1a6a2c94f1b14a38538fc642cbf406c04069d0fd3778473b17ffdb2d3615262f29e561ec21f9
    //     // 0x01 00cad2c7d83988d75f802722c07bce9ec3b94d363f45cf8ca01e3ba11f40e2857573a8b2d985ccf39778f3e100c2fcf966c2bcf9e22992d1bed500e05533bf0720
    //     // 0x03 01957e562d18fb15476fc21b7c6d88821831f367600fc5f7eee4361303e8c4875918144963df4d4424971d9d68033c4e43eb165d1df325a2a68df8dcf9d2d8feb0
    //     // transaction.input[0].script_sig = Builder::new()
    //     //     .push_int(0)
    //     //     .push_slice(&hashed_pubk[..])
    //     //     .into_script()
    //     //     .to_p2sh(); 
        
    //     let formatted_bytes: Vec<String> = sig1_der.iter().map(|b| format!("{:02x}", b)).collect();
    //     println!("===> SIG1 {:?}", formatted_bytes);


    //     // sig2_der.write_u32::<LittleEndian>(sig_hash_all).unwrap();
    //     transaction.input[0].witness = vec![sig1_der, pubk.to_bytes_compressed()];

    //     println!("{:?}", transaction.clone().raw_hex());

    //     let txid = rpc.send_raw_transaction(transaction).unwrap();
    //     println!("===> {:?}", txid);
    // }
    // 028cc6ddf7ed5465ccf98fcf19ebe130a49dfee229be45fbb3bffd2a9cb9a88792
}

pub struct UnspentOutput {
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
