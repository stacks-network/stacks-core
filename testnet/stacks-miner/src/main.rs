extern crate libc;
extern crate serde;
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate stacks;
#[macro_use]
extern crate log;

// extern crate stacks_node;
pub mod keychain;
pub mod operations;

use backtrace::Backtrace;
use base64::encode;
use std::convert::{ TryFrom, TryInto };
use std::env;
// use std::error::Error;
use std::fs;
use std::io::Cursor;
use async_std::io::ReadExt;
use std::net::{ SocketAddr, ToSocketAddrs };
use std::panic;
use std::process;

use pico_args::Arguments;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use async_h1::client;
use async_std::net::TcpStream;
use http_types::{Method, Request, Url};

// use stacks::net::{ PeerAddress };
use stacks::net::StacksMessageCodec;
use stacks::util::sleep_ms;
use stacks::util::hash::{ Hash160, hex_bytes };
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks::util::vrf::{ VRFProof, VRFPublicKey, VRFPrivateKey };

use stacks::burnchains::{
    BurnchainParameters, BurnchainSigner, BLOCKSTACK_MAGIC_MAINNET, bitcoin::BitcoinNetworkType,
    bitcoin::address::{BitcoinAddress, BitcoinAddressType}, BurnchainHeaderHash, MagicBytes,
    PoxConstants, PublicKey, Txid };
use stacks::deps::bitcoin::blockdata::opcodes;
use stacks::deps::bitcoin::blockdata::script::{Builder, Script};
use stacks::deps::bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use stacks::deps::bitcoin::network::encodable::ConsensusEncodable;
use stacks::deps::bitcoin::network::serialize::RawEncoder;
use stacks::deps::bitcoin::util::hash::Sha256dHash;
use stacks::chainstate::burn::{ BlockHeaderHash, ConsensusHash, SortitionHash };
use stacks::chainstate::burn::operations::{
    leader_block_commit::{ BURN_BLOCK_MINED_AT_MODULUS, OUTPUTS_PER_COMMIT, RewardSetInfo },
    BlockstackOperationType,
    LeaderBlockCommitOp,
    LeaderKeyRegisterOp,
    // UserBurnSupportOp,
};
use stacks::chainstate::burn::VRFSeed;
use stacks::chainstate::stacks::{
	CoinbasePayload,
	StacksBlock, StacksPrivateKey, StacksPublicKey, StacksTransaction,
    StacksTransactionSigner, TransactionAnchorMode,
    TransactionPayload, TransactionVersion,
};
use stacks::net::PostBuildBlockTemplateRequestBody;

// use stacks_node::keychain::Keychain;
// use stacks_node::operations::BurnchainOpSigner;
pub use self::keychain::Keychain;
pub use self::operations::BurnchainOpSigner;


// gather config (use env variables first, conf file later?)
// send register key tx
// loop
//  get tip
//  generate microblock hash
//  generate proof
//  get block template
//  send commit tx
//  stacks node will know about the block and submit it to other node if block won sortition

// TODO(psq): is this really necessary to have to constants?
const MINIMUM_DUST_FEE: u64 = 5500;
const DUST_UTXO_LIMIT: u64 = 5500;
const TESTNET_CHAIN_ID: u32 = 0x80000000;

struct Args {
    help: bool,
    version: bool,
    miner_pk: Option<String>,
    stacks_node: Option<String>,
    btc_node: Option<String>,
    vrf_key_file: Option<String>,
}

struct Config {
	magic_bytes: MagicBytes,
	burnchain_op_tx_fee: u64,
	btc_rpc_sock_addr: SocketAddr,
    stx_rpc_sock_addr: SocketAddr,
	username: Option<String>,
	password: Option<String>,
	bitcoin_network: BitcoinNetworkType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredKey {
    pub block_height: u64,
    pub op_vtxindex: u32,
    pub vrf_public_key: VRFPublicKey,
    pub vrf_secret_key: VRFPrivateKey,
}

// pub struct TemplateError {

// }

fn main() {
	env_logger::init();

    panic::set_hook(Box::new(|_| {
        eprintln!("Process abort due to thread panic");
        let bt = Backtrace::new();
        eprintln!("{:?}", &bt);

        // force a core dump
        #[cfg(unix)]
        {
            let pid = process::id();
            eprintln!("Dumping core for pid {}", std::process::id());

            use libc::kill;
            use libc::SIGQUIT;

            // *should* trigger a core dump, if you run `ulimit -c unlimited` first!
            unsafe { kill(pid.try_into().unwrap(), SIGQUIT) };
        }

        // just in case
        process::exit(1);
    }));

    let mut args = Arguments::from_env();
    let args = Args {
    	help: args.contains(["-h", "--help"]),
    	version: args.contains(["-v", "--version"]),
    	miner_pk: args.opt_value_from_str("--miner-pk").unwrap(),
    	stacks_node: args.opt_value_from_str("--stacks-node").unwrap(),
    	btc_node: args.opt_value_from_str("--btc-node").unwrap(),
        vrf_key_file: args.opt_value_from_str("--vrf-key").unwrap(),
    };

    if args.help {
    	print_help();
    } else if args.version {
    	println!(
    	    "{}",
    	    &stacks::version_string(
    	        option_env!("CARGO_PKG_NAME").unwrap_or("stacks-node"),
    	        option_env!("CARGO_PKG_VERSION").unwrap_or("0.0.0.0")
    	    )
    	);
    } else if args.miner_pk.is_some() && args.stacks_node.is_some() && args.btc_node.is_some() {
    	start_miner(args.miner_pk.unwrap(), args.stacks_node.unwrap(), args.btc_node.unwrap(), args.vrf_key_file);
    } else {
    	print_help();
    }
}


#[derive(Debug)]
struct ChainTipInfo {
    burn_block_hash: BurnchainHeaderHash,
	consensus_hash: ConsensusHash,
	sortition_hash: SortitionHash,
	block_height: u64, 
}

impl ChainTipInfo {
    pub fn initial() -> ChainTipInfo {
        ChainTipInfo {
            burn_block_hash: BurnchainHeaderHash::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000000",
            ).unwrap(),
            consensus_hash: ConsensusHash::empty(),
            sortition_hash: SortitionHash::initial(),
            block_height: 0, 
        }
    }
}

struct MinerLoop {
	keychain: Keychain,
	config: Config,
	last_utxos: Vec<UTXO>,
	last_tx_len: u64,
	min_relay_fee: u64, // satoshis/byte
	// active_vrf_pk: Option<VRFPublicKey>,
    pox_constants: PoxConstants,
    first_block_height: u64,
    vrf_key_file: Option<String>,
}

#[derive(Debug, Clone)]
struct SerializedTx {
    bytes: Vec<u8>,
}

impl SerializedTx {
    pub fn new(tx: Transaction) -> SerializedTx {
        let mut encoder = RawEncoder::new(Cursor::new(vec![]));
        tx.consensus_encode(&mut encoder)
            .expect("BUG: failed to serialize to a vec");
        let bytes: Vec<u8> = encoder.into_inner().into_inner();
        SerializedTx { bytes }
    }

    fn to_hex(&self) -> String {
        let formatted_bytes: Vec<String> =
            self.bytes.iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}", formatted_bytes.join(""))
    }
}

impl MinerLoop {
    pub fn new(stx_rpc_sock_addr: SocketAddr, btc_rpc_sock_addr: SocketAddr, miner_pk: String, vrf_key_file: Option<String>) -> MinerLoop {
        // TODO(psq): make these parameters
        let chain_name = "bitcoin";
        let network_name = "regtest";
        let username = Some("helium-node".to_string());  // TODO(psq):  add as parameter or config file
        let password = Some("secret".to_string());
        // let username = Some("admin".to_string());
        // let password = Some("admin".to_string());

        let (params, pox_constants, bitcoin_network) = match (chain_name, network_name) {
            ("bitcoin", "mainnet") => (
                BurnchainParameters::bitcoin_mainnet(),
                PoxConstants::mainnet_default(),
                BitcoinNetworkType::Mainnet,
            ),
            ("bitcoin", "testnet") => (
                BurnchainParameters::bitcoin_testnet(),
                PoxConstants::testnet_default(),
                BitcoinNetworkType::Testnet,
            ),
            ("bitcoin", "regtest") => (
                BurnchainParameters::bitcoin_regtest(),
                PoxConstants::testnet_default(),
                BitcoinNetworkType::Testnet,
            ),
            (_, _) => (  // default to mainnet
                BurnchainParameters::bitcoin_mainnet(),
                PoxConstants::mainnet_default(),
                BitcoinNetworkType::Mainnet,
            )
        };

    	let config = Config {
    		magic_bytes: BLOCKSTACK_MAGIC_MAINNET.clone(),
    		burnchain_op_tx_fee: MINIMUM_DUST_FEE, // * (OUTPUTS_PER_COMMIT as u64),  // TODO(psq): check this is correct
    		btc_rpc_sock_addr: btc_rpc_sock_addr,
            stx_rpc_sock_addr: stx_rpc_sock_addr,
    		username,
    		password,
    		bitcoin_network,
    	};

        MinerLoop {
            keychain: Keychain::default(hex_bytes(&miner_pk).unwrap().clone()),
            config,
            last_utxos: vec![],
            last_tx_len: 0,
	        min_relay_fee: 1024, // TODO(psq): learn from bitcoind
	        // active_vrf_pk: None,
            pox_constants,
            first_block_height: params.first_block_height,
            vrf_key_file,
        }
    }

    // call /v2/info => { pox_consensus, sortition_hash, burn_block_height }
    fn get_burnchain_tip_info(&self) -> RPCResult<ChainTipInfo> {
    	// println!("  ===> get_burnchain_tip_info");

    	let payload = StacksRPCRequest {
    	    path: "/v2/info".to_string(),
    	    method: Method::Get,
    	    body: None,
    	};

    	let json_resp = StacksRPCRequest::send(&self.config, payload)?;
    	// println!("get_burnchain_tip_info.json_resp {:?}", json_resp);


    	return Ok(ChainTipInfo {
    		burn_block_hash: BurnchainHeaderHash::from_hex(json_resp.get("burn_block_hash").unwrap().as_str().unwrap()).unwrap(),
            consensus_hash: ConsensusHash::from_hex(json_resp.get("pox_consensus").unwrap().as_str().unwrap()).unwrap(),
    		sortition_hash: SortitionHash::from_hex(json_resp.get("sortition_hash").unwrap().as_str().unwrap()).unwrap(),
    		block_height: json_resp.get("burn_block_height").unwrap().as_u64().unwrap(),
    	});
    }

    // call /v2/accounts/{principal} => { nonce }
    fn get_account_nonce(&mut self) -> RPCResult<u64> {
        println!("===> get_account_nonce");

        let stacks_address = self.keychain.get_address();
        println!("stacks_address {:?}", stacks_address);

        let payload = StacksRPCRequest {
            path: format!("/v2/accounts/{}?proof=0", &stacks_address),
            method: Method::Get,
            body: None,
        };

        let json_resp = StacksRPCRequest::send(&self.config, payload)?;
        println!("get_account_nonce.json_resp {:?}", json_resp);

        Ok(json_resp.get("nonce").unwrap().as_u64().unwrap())
    }

    fn get_block_template(
    	&self,
    	microblock_public_hash: Hash160,
        microblock_secret_key: StacksPrivateKey,
    	vrf_proof: VRFProof,
    	coinbase_tx: StacksTransaction,
    	txids: Vec<Txid>,
    ) -> RPCResult<(StacksBlock, Option<RewardSetInfo>, u16, u32)> {  // TODO(psq): add needed params, and will probably return more than just a StacksBlock (need recipients for example)
    	println!("===> get_block_template (stubbed) mblock_pubkey_hash: {:?}, microblock_secret_key: {:?}, vrf_proof: {:?}, coinbase_tx: {:?}, txids: {:?}", microblock_public_hash, microblock_secret_key, vrf_proof, coinbase_tx, txids);
    	
        let body = PostBuildBlockTemplateRequestBody {
            txids,
            vrf_proof,
            microblock_public_hash,
            microblock_secret_key,
            coinbase_tx,
        };

        let payload = StacksRPCRequest {
            path: "/v2/miner/build-block".to_string(),
            method: Method::Post,
            body: Some(json!(body)),
        };

        let json_resp = StacksRPCRequest::send(&self.config, payload)?;
        println!("get_block_template.json_resp {:?}", json_resp);

    	// TODO(psq): need to add extra data to be returned besides the anchor block: parent_block_burn_height, parent_winning_vtxindex, recipients
    	let parent_block_burn_height = json_resp.get("parent-block-burn-height").unwrap().as_u64().unwrap() as u32;
    	let parent_winning_vtxindex = json_resp.get("parent-winning-vtxindex").unwrap().as_u64().unwrap() as u16;
    	let recipients = match json_resp.get("recipients") {
            Some(recipients) => {
                let recipients: RewardSetInfo = serde_json::from_value(recipients.clone()).unwrap();
                Some(recipients)
            },
            _ => None
        };
    	let anchored_block: StacksBlock = serde_json::from_value(json_resp.get("block").unwrap().clone()).unwrap();
    	Ok((anchored_block, recipients, parent_winning_vtxindex, parent_block_burn_height))
    }

    pub fn get_utxos(
        &self,
        public_key: &Secp256k1PublicKey,
        amount_required: u64,
    ) -> Option<Vec<UTXO>> {
        // Configure UTXO filter
        let pkh = Hash160::from_data(&public_key.to_bytes())
            .to_bytes()
            .to_vec();
        let network_id = self.config.bitcoin_network;
        let address =
            BitcoinAddress::from_bytes(network_id, BitcoinAddressType::PublicKeyHash, &pkh)
                .expect("Public key incorrect");
        let filter_addresses = vec![address.to_b58()];

        let mut utxos = loop {
            let result = BitcoinRPCRequest::list_unspent(
                &self.config,
                filter_addresses.clone(),
                false,
                amount_required,
            );

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

        let utxos = if utxos.len() == 0 {
            loop {
                let _result = BitcoinRPCRequest::import_public_key(&self.config, &public_key);

                sleep_ms(1000);

                let result = BitcoinRPCRequest::list_unspent(
                    &self.config,
                    filter_addresses.clone(),
                    false,
                    amount_required,
                );

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
                } else {
                    break utxos;
                }
            }
        } else {
            utxos
        };

        let total_unspent: u64 = utxos.iter().map(|o| o.amount).sum();
        if total_unspent < amount_required {
            warn!(
                "Total unspent {} < {} for {:?}",
                total_unspent,
                amount_required,
                &public_key.to_hex()
            );
            return None;
        }

        Some(utxos)
    }

    fn build_leader_key_register_tx(
        &mut self,
        payload: LeaderKeyRegisterOp,
        signer: &mut BurnchainOpSigner,
        attempt: u64,
    ) -> Option<Transaction> {
        let public_key = signer.get_public_key();

        let (mut tx, utxos) = self.prepare_tx(&public_key, DUST_UTXO_LIMIT, attempt)?;

        // Serialize the payload
        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = self.config.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            payload
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
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

        self.finalize_tx(&mut tx, DUST_UTXO_LIMIT, utxos, signer, attempt)?;

        // increment_btc_ops_sent_counter();

        info!(
            "Miner node: submitting leader_key_register op - {}",
            public_key.to_hex()
        );

        Some(tx)
    }

    fn build_leader_block_commit_tx(
        &mut self,
        payload: LeaderBlockCommitOp,
        signer: &mut BurnchainOpSigner,
        attempt: u64,
    ) -> Option<Transaction> {
        let public_key = signer.get_public_key();

        let (mut tx, utxos) = self.prepare_tx(&public_key, payload.burn_fee, attempt)?;

        // Serialize the payload
        let op_bytes = {
            let mut buffer = vec![];
            let mut magic_bytes = self.config.magic_bytes.as_bytes().to_vec();
            buffer.append(&mut magic_bytes);
            payload
                .consensus_serialize(&mut buffer)
                .expect("FATAL: invalid operation");
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

        if OUTPUTS_PER_COMMIT != payload.commit_outs.len() {
            error!("Generated block commit with wrong OUTPUTS_PER_COMMIT");
            return None;
        }
        let value_per_transfer = payload.burn_fee / (OUTPUTS_PER_COMMIT as u64);
        if value_per_transfer < 5500 {
            error!("Total burn fee not enough for number of outputs");
            return None;
        }
        for commit_to in payload.commit_outs.iter() {
            tx.output
                .push(commit_to.to_bitcoin_tx_out(value_per_transfer));
        }

        self.finalize_tx(&mut tx, payload.burn_fee, utxos, signer, attempt)?;

        // increment_btc_ops_sent_counter();

        info!(
            "Miner node: submitting leader_block_commit op - {}",
            public_key.to_hex()
        );

        Some(tx)
    }

    fn prepare_tx(
        &mut self,
        public_key: &Secp256k1PublicKey,
        ops_fee: u64,
        attempt: u64,
    ) -> Option<(Transaction, Vec<UTXO>)> {
        let tx_fee = self.config.burnchain_op_tx_fee;
        let amount_required = tx_fee + ops_fee;

        let utxos = if attempt > 1 && self.last_utxos.len() > 0 {
            // in RBF, you have to consume the same UTXOs
            self.last_utxos.clone()
        } else {
            // Fetch some UTXOs
            let new_utxos = match self.get_utxos(&public_key, amount_required) {
                Some(utxos) => utxos,
                None => {
                    debug!("No UTXOs for {}", &public_key.to_hex());
                    return None;
                }
            };
            self.last_utxos = new_utxos.clone();
            self.last_tx_len = 0;
            new_utxos
        };

        // Prepare a backbone for the tx
        let transaction = Transaction {
            input: vec![],
            output: vec![],
            version: 1,
            lock_time: 0,
        };

        Some((transaction, utxos))
    }

    fn finalize_tx(
        &mut self,
        tx: &mut Transaction,
        total_spent: u64,
        mut utxos: Vec<UTXO>,
        signer: &mut BurnchainOpSigner,
        attempt: u64,
    ) -> Option<()> {
        // spend UTXOs in decreasing order
        utxos.sort_by(|u1, u2| u1.amount.cmp(&u2.amount));
        utxos.reverse();

        // RBF
        let tx_fee = self.config.burnchain_op_tx_fee
            + (attempt * self.last_tx_len * self.min_relay_fee);

        let public_key = signer.get_public_key();
        let mut total_consumed = 0;

        // select UTXOs until we have enough to cover the cost
        let mut utxos_consumed = vec![];
        for utxo in utxos.into_iter() {
            total_consumed += utxo.amount;
            utxos_consumed.push(utxo);

            if total_consumed >= total_spent + tx_fee {
                break;
            }
        }

        // Append the change output
        let change_address_hash = Hash160::from_data(&public_key.to_bytes());
        if total_consumed < total_spent + tx_fee {
            warn!(
                "Consumed total {} is less than intended spend: {}",
                total_consumed,
                total_spent + tx_fee
            );
            return None;
        }
        let value = total_consumed - total_spent - tx_fee;
        if value >= DUST_UTXO_LIMIT {
            let change_output = BitcoinAddress::to_p2pkh_tx_out(&change_address_hash, value);
            tx.output.push(change_output);
        } else {
            debug!("Not enough change to clear dust limit. Not adding change address.");
        }

        for (i, utxo) in utxos_consumed.into_iter().enumerate() {
            let input = TxIn {
                previous_output: OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                script_sig: Script::new(),
                sequence: 0xFFFFFFFD, // allow RBF
                witness: vec![],
            };
            tx.input.push(input);

            let script_pub_key = utxo.script_pub_key.clone();
            let sig_hash_all = 0x01;
            let sig_hash = tx.signature_hash(i, &script_pub_key, sig_hash_all);

            let sig1_der = {
                let message = signer
                    .sign_message(sig_hash.as_bytes())
                    .expect("Unable to sign message");
                message
                    .to_secp256k1_recoverable()
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

        // remember how long the transaction is, in case we need to RBF
        let tx_bytes = SerializedTx::new(tx.clone());
        debug!("Send transaction: {:?}", tx_bytes.to_hex());

        self.last_tx_len = tx_bytes.bytes.len() as u64;

        Some(())
    }


    // fn send(config: &Config, payload: BitcoinRPCRequest) -> RPCResult<serde_json::Value> {
    //     let mut request = BitcoinRPCRequest::build_rpc_request(&config);

    //     let body = match serde_json::to_vec(&json!(payload)) {
    //         Ok(body) => body,
    //         Err(err) => {
    //             return Err(RPCError::Network(format!("RPC Error: {}", err)));
    //         }
    //     };
    //     request
    //         .append_header("Content-Type", "application/json")
    //         .expect("Unable to set header");
    //     request.set_body(body);

    //     let mut response = async_std::task::block_on(async move {
    //         let stream = match TcpStream::connect(config.rpc_socket_addr).await {
    //             Ok(stream) => stream,
    //             Err(err) => {
    //                 return Err(RPCError::Network(format!(
    //                     "Bitcoin RPC: connection failed - {:?}",
    //                     err
    //                 )))
    //             }
    //         };

    //         match client::connect(stream, request).await {
    //             Ok(response) => Ok(response),
    //             Err(err) => {
    //                 return Err(RPCError::Network(format!(
    //                     "Bitcoin RPC: invoking procedure failed - {:?}",
    //                     err
    //                 )))
    //             }
    //         }
    //     })?;

    //     let status = response.status();

    //     let (res, buffer) = async_std::task::block_on(async move {
    //         let mut buffer = Vec::new();
    //         let mut body = response.take_body();
    //         let res = body.read_to_end(&mut buffer).await;
    //         (res, buffer)
    //     });

    //     if !status.is_success() {
    //         return Err(RPCError::Network(format!(
    //             "Bitcoin RPC: status({}) != success, body is '{:?}'",
    //             status,
    //             match serde_json::from_slice::<serde_json::Value>(&buffer[..]) {
    //                 Ok(v) => v,
    //                 Err(_e) => serde_json::from_str("\"(unparseable)\"")
    //                     .expect("Failed to parse JSON literal"),
    //             }
    //         )));
    //     }

    //     if res.is_err() {
    //         return Err(RPCError::Network(format!(
    //             "Bitcoin RPC: unable to read body - {:?}",
    //             res
    //         )));
    //     }

    //     let payload = serde_json::from_slice::<serde_json::Value>(&buffer[..])
    //         .map_err(|e| RPCError::Parsing(format!("Bitcoin RPC: {}", e)))?;
    //     Ok(payload)
    // }


    fn send_transaction(&self, transaction: SerializedTx) -> Option<Sha256dHash> {
        let result = BitcoinRPCRequest::send_raw_transaction(&self.config, transaction.to_hex());
        match result {
            Ok(txid) => Some(txid),
            Err(e) => {
                error!(
                    "Bitcoin RPC failure: transaction submission failed - {:?}",
                    e
                );
                None
            }
        }
    }

    fn submit_operation(
        &mut self,
        operation: BlockstackOperationType,
        op_signer: &mut BurnchainOpSigner,
        attempt: u64,
    ) -> Option<Sha256dHash> {
        let transaction = match operation {
            BlockstackOperationType::LeaderBlockCommit(payload) => {
                self.build_leader_block_commit_tx(payload, op_signer, attempt)
            }
            BlockstackOperationType::LeaderKeyRegister(payload) => {
                self.build_leader_key_register_tx(payload, op_signer, attempt)
            }
            _ => None
        };

        let transaction = match transaction {
            Some(tx) => SerializedTx::new(tx),
            _ => return None,
        };

        self.send_transaction(transaction)
    }


    fn generate_leader_key_register_op(
        &mut self,
        vrf_public_key: VRFPublicKey,
        consensus_hash: &ConsensusHash,
    ) -> BlockstackOperationType {
        BlockstackOperationType::LeaderKeyRegister(LeaderKeyRegisterOp {
            public_key: vrf_public_key,
            memo: vec![],
            address: self.keychain.get_address(),
            consensus_hash: consensus_hash.clone(),
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        })
    }

    fn register_key(&mut self) -> RegisteredKey {
    	println!("  ===> register_key");
    	let chain_tip_info = self.get_burnchain_tip_info().unwrap();
        println!("  ===> register_key.chain_tip_info {:?}", &chain_tip_info);
    	let vrf_public_key = self
    	    .keychain
    	    .rotate_vrf_keypair(chain_tip_info.block_height);
        let vrf_secret_key: VRFPrivateKey = self.keychain.get_sk(&vrf_public_key).unwrap().clone();
    	let consensus_hash = chain_tip_info.consensus_hash;
    	let key_reg_op = self.generate_leader_key_register_op(vrf_public_key.clone(), &consensus_hash);
    	let mut op_signer = self.keychain.generate_op_signer();
    	let txid = self.submit_operation(key_reg_op, &mut op_signer, 1).unwrap();
    	println!("register_key.txid {:?}", txid);

    	// wait for the key to be on chain, and with maybe more than 1 confirmation before mining
    	let blockhash;
        loop {
    		if let Some(bh) = BitcoinRPCRequest::get_raw_transaction_blockhash(&self.config, txid).unwrap() {
                blockhash = bh;
    			break;
    		}
    		// TODO(psq): fail if not received after some time
    		sleep_ms(5_000);
    	}

        let (block_height, op_vtxindex) = BitcoinRPCRequest::find_transaction_location(&self.config, &blockhash, txid).unwrap();

    	// TODO(psq): persist key so it can be reused next time miner is started
    	// self.active_vrf_pk = Some(vrf_public_key.clone()); // TODO(psq): not used

    	// ask stacks-node or bitcoind?  we have the txid, so this should be retrievable from bitcoind but need blockhash unless priv key is added)
    	RegisteredKey {
    		block_height,
    		op_vtxindex,
    		vrf_public_key,
            vrf_secret_key,
    	}
    }

    pub fn reward_cycle_to_block_height(&self, reward_cycle: u64) -> u64 {
        // NOTE: the `+ 1` is because the height of the first block of a reward cycle is mod 1, not
        // mod 0.
        self.first_block_height + reward_cycle * (self.pox_constants.reward_cycle_length as u64) + 1
    }

    pub fn block_height_to_reward_cycle(&self, block_height: u64) -> Option<u64> {
        if block_height < self.first_block_height {
            return None;
        }
        Some(
            (block_height - self.first_block_height)
                / (self.pox_constants.reward_cycle_length as u64),
        )
    }

    pub fn expected_sunset_burn(&self, burn_height: u64, total_commit: u64) -> u64 {
        if burn_height < self.pox_constants.sunset_start
            || burn_height >= self.pox_constants.sunset_end
        {
            return 0;
        }

        let reward_cycle_height = self.reward_cycle_to_block_height(
            self.block_height_to_reward_cycle(burn_height)
                .expect("BUG: Sunset start is less than first_block_height"),
        );

        if reward_cycle_height <= self.pox_constants.sunset_start {
            return 0;
        }

        let sunset_duration =
            (self.pox_constants.sunset_end - self.pox_constants.sunset_start) as u128;
        let sunset_progress = (reward_cycle_height - self.pox_constants.sunset_start) as u128;

        // use u128 to avoid any possibilities of overflowing in the calculation here.
        let expected_u128 = (total_commit as u128) * (sunset_progress) / sunset_duration;
        u64::try_from(expected_u128)
            // should never be possible, because sunset_burn is <= total_commit, which is a u64
            .expect("Overflowed u64 in calculating expected sunset_burn")
    }

    pub fn run_loop(&mut self) {
    	println!("  ===> starting run loop");

        // TODO(psq): full logic should either generate a new random one, or generate one if file does not exist, or use if file exist
        let file = self.vrf_key_file.as_ref();
        let registered_key: RegisteredKey = match file {
            Some(vrf_key_file) => {
                let json = fs::read_to_string(vrf_key_file).expect("Unable to read file");
                let registered_key: RegisteredKey = serde_json::from_str(&json).unwrap();
                println!("registered_key {:?}", registered_key);
                self.keychain.add(&registered_key.vrf_public_key, &registered_key.vrf_secret_key);
                registered_key
            },
            None => {
                let registered_key = self.register_key();
                let registered_key_json = serde_json::to_string(&registered_key).unwrap();
                println!("vrf key json: {:?}", registered_key_json);
                fs::write("vrf_key.json", registered_key_json).expect("Unable to write file");                
                registered_key
            }
        };

    	println!("  ===> starting main loop");
        let mut previous_tip;
        let mut tip = ChainTipInfo::initial();
    	loop {
    		//  wait for a new tip 
            previous_tip = tip;
            loop {
                let new_tip = self.get_burnchain_tip_info().unwrap();
                if new_tip.block_height != previous_tip.block_height || new_tip.sortition_hash != previous_tip.sortition_hash {
                    tip = new_tip;
                    break;
                }
                sleep_ms(15_000)             
            }
            println!("==================================================================");
            println!("  ===> found new tip {:?}", tip);

            // check tip burnchain matches bitcoind height
            // recompute highest fork based on data derived from follower ??? TODO(psq)
            // start from possibly best tip (as parameter)
            // either new best tip is a child of that tip => use
            // otherwise, use our previously mined tip
            // ??? open sqlite db of follower?

            // either use known tip, or previous win (although most likely this will be the same...)
            // use 2 followers and use best available?


    		// generate proof
    		// Generates a proof out of the sortition hash provided in the params.
    		let vrf_proof = self
    		    .keychain
    		    .generate_proof(
    		        &registered_key.vrf_public_key,
    		        tip.sortition_hash.as_bytes(),
    		    )
    		    .unwrap();
            // println!("vrf_proof {:?}", vrf_proof);

    		// generate microblock hash
    		// Generates a new secret key for signing the trail of microblocks
    		// of the upcoming tenure.
    		let microblock_secret_key = self.keychain.rotate_microblock_keypair(tip.block_height);
    		let mblock_pubkey_hash =
    		    Hash160::from_node_public_key(&StacksPublicKey::from_private(&microblock_secret_key));

    		// generate (signed?) coinbase
    		let coinbase_nonce = self.get_account_nonce().unwrap_or(0);  // Failed to load Stacks chain tip
    		let coinbase_tx = inner_generate_coinbase_tx(&mut self.keychain, coinbase_nonce);

            // TODO(psq): gather pending txids from mempool by calling rpc endpoint
            // TODO(psq): will need to filter those with bad nonce, or maybe the api reports the txis that could not
            // be included, and the reason (makes for a lighter miner)
    		// get txids to include
    		let txids = vec![];

    		// get block template
            let (anchored_block, recipients, parent_winning_vtxindex, parent_block_burn_height) = self.get_block_template(
            	mblock_pubkey_hash,
                microblock_secret_key, // TODO(psq): the node requires this to mine microblocks, need a better solution, fortunately, this private key is only used for one block
            	vrf_proof.clone(),
            	coinbase_tx,
            	txids,
            ).unwrap();

            let sunset_burn = self.expected_sunset_burn(tip.block_height + 1, self.config.burnchain_op_tx_fee);

    		// send commit tx
    		let op = inner_generate_block_commit_op(
    		    self.keychain.get_burnchain_signer(),
    		    anchored_block.block_hash(),
    		    
                22_222,

    		    &registered_key,
    		    parent_block_burn_height,
    		    parent_winning_vtxindex,
    		    VRFSeed::from_proof(&vrf_proof),
    		    recipients,
                sunset_burn,
                tip.block_height,
    		);
    		let mut op_signer = self.keychain.generate_op_signer();
    		println!("  ===> send commit {:?}, parent {}, block hash {:?}", tip.block_height, parent_block_burn_height, anchored_block.block_hash());
            self.submit_operation(op, &mut op_signer, 0);  // TODO(psq): implement multiple attemp logic


            // TODO(psq): if block is winner, is stacks-node the one propagating the block
            // which means it should have kept a copy
    		// stacks node will know about the block and submit it to other node if block won sortition
    	}
    }

}

fn inner_generate_coinbase_tx(keychain: &mut Keychain, nonce: u64) -> StacksTransaction {
    let mut tx_auth = keychain.get_transaction_auth().unwrap();
    tx_auth.set_origin_nonce(nonce);

    let mut tx = StacksTransaction::new(
        TransactionVersion::Testnet,  // TODO(psq): remove hardcoded value
        tx_auth,
        TransactionPayload::Coinbase(CoinbasePayload([0u8; 32])),
    );
    tx.chain_id = TESTNET_CHAIN_ID;  // TODO(psq): remove hardcoded value
    tx.anchor_mode = TransactionAnchorMode::OnChainOnly;
    let mut tx_signer = StacksTransactionSigner::new(&tx);
    keychain.sign_as_origin(&mut tx_signer);

    tx_signer.get_tx().unwrap()
}

fn inner_generate_block_commit_op(
    apparent_sender: BurnchainSigner,
    block_header_hash: BlockHeaderHash,
    burn_fee: u64,
    key: &RegisteredKey,
    parent_burnchain_height: u32,
    parent_winning_vtx: u16,
    vrf_seed: VRFSeed,
    recipients: Option<RewardSetInfo>,
    sunset_burn: u64,
    current_burn_height: u64,
) -> BlockstackOperationType {
    let (parent_block_ptr, parent_vtxindex) = (parent_burnchain_height, parent_winning_vtx);

    let commit_outs = RewardSetInfo::into_commit_outs(recipients, false);
    let block_height = parent_burnchain_height as u64;
    let burn_parent_modulus = (current_burn_height % BURN_BLOCK_MINED_AT_MODULUS) as u8;

    BlockstackOperationType::LeaderBlockCommit(LeaderBlockCommitOp {
        block_header_hash,
        burn_fee,
        apparent_sender,
        key_block_ptr: key.block_height as u32,
        key_vtxindex: key.op_vtxindex as u16,
        memo: vec![],
        new_seed: vrf_seed,
        parent_block_ptr,
        parent_vtxindex,
        vtxindex: 0,
        txid: Txid([0u8; 32]),
        block_height,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        commit_outs,
        input: (Txid([0; 32]), 0),
        sunset_burn,
        burn_parent_modulus,
    })
}



fn start_miner(miner_pk: String, stacks_node: String, btc_node: String, vrf_file: Option<String>) {
	println!("  ===> start_miner {:?} {:?} {:?}", &miner_pk, &stacks_node, &btc_node);

	let stx_rpc_sock_addr = {
		let mut addrs_iter = stacks_node.to_socket_addrs().unwrap();
		addrs_iter.next().unwrap()
		// let sock_addr = addrs_iter.next().unwrap();
		// PeerHost::from_host_port(PeerAddress::from_socketaddr(&sock_addr), sock_addr.port())
	};
	let btc_rpc_sock_addr = {
		let mut addrs_iter = btc_node.to_socket_addrs().unwrap();
		addrs_iter.next().unwrap()
		// let sock_addr = addrs_iter.next().unwrap();
		// PeerHost::from_host_port(PeerAddress::from_socketaddr(&sock_addr), sock_addr.port())
	};

	println!("  ===> start_miner {:?} {:?}", stx_rpc_sock_addr, btc_rpc_sock_addr);

	let mut miner_loop = MinerLoop::new(stx_rpc_sock_addr, btc_rpc_sock_addr, miner_pk, vrf_file);
	miner_loop.run_loop();
}

fn print_help() {
    let argv: Vec<_> = env::args().collect();

    eprintln!(
        "\
{} <SUBCOMMAND>
Run a miner.

USAGE:
stacks-miner

--miner-pk\t\tEnvironment variable should contain miner seed
--stacks-node\t\tEnvironment variable with host:port of stacks-node to connect to
--btc-node\t\tEnvironment variable with host:port of bitcoind to connect to

--version\t\tDisplay informations about the current version and our release cycle.

--help\t\tDisplay this help.

", argv[0]);
}

#[derive(Debug, Clone)]
struct StacksRPCRequest {
    /// The path
    pub path: String,
    /// The method (GET/POST)
    pub method: Method,
    /// Parameters to the RPC call
    pub body: Option<serde_json::Value>,
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

#[derive(Clone)]
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
                    }
                    (lhs, rhs) => {
                        warn!("Error while converting BTC to sat {:?} - {:?}", lhs, rhs);
                        return None;
                    }
                }
            }
            _ => None,
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

impl StacksRPCRequest {
    fn build_rpc_request(config: &Config, payload: &StacksRPCRequest) -> Request {
        let url = {
            let url = format!("http://{}:{}{}", config.stx_rpc_sock_addr.ip(), config.stx_rpc_sock_addr.port(), payload.path);  // TODO(psq): support https as well
            // println!("build_rpc_request.url {:?}", url);
            Url::parse(&url).expect(&format!("Unable to parse {} as a URL", url))
        };
        // debug!(
        //     "StacksRPC builder: {:?}:{:?}@{}",
        //     &config.username, &config.password, &url
        // );

        Request::new(payload.method, url)
    }

    fn send(config: &Config, payload: StacksRPCRequest) -> RPCResult<serde_json::Value> {
        let mut request = StacksRPCRequest::build_rpc_request(&config, &payload);

        // println!("send.request {:?}", request);

        request
            .append_header("Content-Type", "application/json")
            .expect("Unable to set header");
        
        match payload.body {
            Some(body) => {
                println!("assembling body {:?}", &body);
                let body = match serde_json::to_vec(&json!(body)) {
                    Ok(body) => body,
                    Err(err) => {
                        return Err(RPCError::Network(format!("RPC Error: {}", err)));
                    }
                };
                println!("serialized body {:?}", &body);
                request.set_body(body);
            },
            _ => {}
        }

        let mut response = async_std::task::block_on(async move {
            let stream = match TcpStream::connect(config.stx_rpc_sock_addr).await {
                Ok(stream) => stream,
                Err(err) => {
                    return Err(RPCError::Network(format!(
                        "Stacks RPC: connection failed - {:?}",
                        err
                    )))
                }
            };

            match client::connect(stream, request).await {
                Ok(response) => Ok(response),
                Err(err) => {
                    return Err(RPCError::Network(format!(
                        "Stacks RPC: invoking procedure failed - {:?}",
                        err
                    )))
                }
            }
        })?;

        let status = response.status();
        // println!("status {:?}", status);

        let (res, buffer) = async_std::task::block_on(async move {
            let mut buffer = Vec::new();
            let mut body = response.take_body();
            let res = body.read_to_end(&mut buffer).await;
            (res, buffer)
        });

        if !status.is_success() {
            println!("!status.is_success() {:#?}", &buffer);
            return Err(RPCError::Network(format!(
                "Stacks RPC: status({}) != success, body is '{:?}'",
                status,
                match serde_json::from_slice::<serde_json::Value>(&buffer[..]) {
                    Ok(v) => v,
                    Err(_e) => serde_json::from_str("\"(unparseable)\"")
                        .expect("Failed to parse JSON literal"),
                }
            )));
        }

        if res.is_err() {
            println!("res.is_err() {:?}", &res);
            return Err(RPCError::Network(format!(
                "Stacks RPC: unable to read body - {:?}",
                res
            )));
        }

        let payload = serde_json::from_slice::<serde_json::Value>(&buffer[..])
            .map_err(|e| RPCError::Parsing(format!("Stacks RPC: {}", e)))?;
        println!("result payload{:?}", &payload);
        Ok(payload)
    }

}


impl BitcoinRPCRequest {
    fn build_rpc_request(config: &Config) -> Request {
        let url = {
            let url = format!("http://{}:{}", config.btc_rpc_sock_addr.ip(), config.btc_rpc_sock_addr.port());  // TODO(psq): support https as well
            // println!("build_rpc_request.url {:?}", url);
            Url::parse(&url).expect(&format!("Unable to parse {} as a URL", url))
        };
        debug!(
            "BitcoinRPC builder: {:?}:{:?}@{}",
            &config.username, &config.password, &url
        );

        let mut req = Request::new(Method::Post, url);

        match (&config.username, &config.password) {
            (Some(username), Some(password)) => {
                let auth_token = format!("Basic {}", encode(format!("{}:{}", username, password)));
                req.append_header("Authorization", auth_token)
                    .expect("Unable to set header");
            }
            (_, _) => {}
        };
        req
    }

// TODO(psq): useful only for regtest, but keep for testing?
    // pub fn generate_to_address(config: &Config, num_blocks: u64, address: String) -> RPCResult<()> {
    //     debug!("Generate {} blocks to {}", num_blocks, address);
    //     let payload = BitcoinRPCRequest {
    //         method: "generatetoaddress".to_string(),
    //         params: vec![num_blocks.into(), address.into()],
    //         id: "stacks".to_string(),
    //         jsonrpc: "2.0".to_string(),
    //     };

    //     BitcoinRPCRequest::send(&config, payload)?;
    //     Ok(())
    // }

    pub fn list_unspent(
        config: &Config,
        addresses: Vec<String>,
        include_unsafe: bool,
        minimum_sum_amount: u64,
    ) -> RPCResult<Vec<UTXO>> {
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
                json!({ "minimumAmount": minimum_amount }),
            ],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let mut res = BitcoinRPCRequest::send(&config, payload)?;

        match res.as_object_mut() {
            Some(ref mut object) => match object.get_mut("result") {
                Some(serde_json::Value::Array(entries)) => {
                    while let Some(entry) = entries.pop() {
                        let parsed_utxo: ParsedUTXO = match serde_json::from_value(entry) {
                            Ok(utxo) => utxo,
                            Err(err) => {
                                warn!("Failed parsing UTXO: {}", err);
                                continue;
                            }
                        };
                        let amount = match parsed_utxo.get_sat_amount() {
                            Some(amount) => amount,
                            None => continue,
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
                            None => continue,
                        };

                        return Ok(vec![UTXO {
                            txid,
                            vout: parsed_utxo.vout,
                            script_pub_key,
                            amount,
                        }]);
                    }
                }
                _ => {
                    warn!("Failed to get UTXOs");
                }
            },
            _ => {
                warn!("Failed to get UTXOs");
            }
        };

        Ok(vec![])
    }

    pub fn find_transaction_location(config: &Config, burnhash: &BurnchainHeaderHash, txid: Sha256dHash) -> RPCResult<(u64, u32)> {
        let burnhash_hex = burnhash.to_hex();
        let txid_hex = txid.be_hex_string();
        println!("find_transaction_location.burnhash_hex {:?} / {:?}", burnhash_hex, txid_hex);

        let payload = BitcoinRPCRequest {
            method: "getblock".to_string(),
            params: vec![
                serde_json::Value::String(burnhash_hex.clone()),
                json!(1), // TODO(psq): verbose useful?
            ],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let json_resp = BitcoinRPCRequest::send(&config, payload)?;
        println!("find_transaction_location.json_resp {:?}", json_resp);

        if let Some(e) = json_resp.get("error") {
            if !e.is_null() {
                error!("Error finding block for tx: {}", e);
                return Err(RPCError::Bitcoind(e.to_string()));
            }
        }
        // need height
        // need tx[]
        if let Some(result) = json_resp.get("result") {
            let txs: Vec<serde_json::Value> = result.get("tx").unwrap().as_array().unwrap().to_vec();
            println!("txs {:?}", txs);

            let height = result.get("height").unwrap().as_u64().unwrap();
            let vtindex: u32 = txs.iter().position(|v| v.as_str().unwrap() == txid_hex).unwrap() as u32;  // TODO(psq): in our case, it will be there, but for a more generic function, use Option<>
            return Ok((height, vtindex));
        }
        return Err(RPCError::Bitcoind("unexpected json received from getrawtransaction".to_string()));
    }

    // Mostly used to figure out whether a transaction has been added to a block or not
    pub fn get_raw_transaction_blockhash(
        config: &Config,
        txid: Sha256dHash,
    ) -> RPCResult<Option<BurnchainHeaderHash>> {
        let tx_hex = txid.be_hex_string();
        println!("get_raw_transaction_blockhash.tx_hex {:?}", tx_hex);

        let payload = BitcoinRPCRequest {
            method: "getrawtransaction".to_string(),
            params: vec![
            	serde_json::Value::String(tx_hex.clone()),
            	json!(1), // TODO(psq): verbose useful?
            ],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let json_resp = BitcoinRPCRequest::send(&config, payload)?;
        // println!("get_raw_transaction_blockhash.json_resp {:?}", json_resp);

        if let Some(e) = json_resp.get("error") {
            if !e.is_null() {
                error!("Error checking transaction: {}", e);
                return Err(RPCError::Bitcoind(e.to_string()));
            }
        }
        if let Some(result) = json_resp.get("result") {
        	match result.get("blockhash") {
        		Some(blockhash) => {
        			println!("txid found in {:?}", blockhash);
        			return Ok(Some(BurnchainHeaderHash::from_hex(blockhash.as_str().unwrap()).unwrap()));  // included in a block       			
        		}
        		_ => {
        			// warn!("txid {:?} is not confirmed yet", tx_hex);
        			return Ok(None);
        		}
        	}
        }
        return Err(RPCError::Bitcoind("unexpected json received from getrawtransaction".to_string()));
    }

    pub fn send_raw_transaction(config: &Config, tx: String) -> RPCResult<Sha256dHash> {
        let payload = BitcoinRPCRequest {
            method: "sendrawtransaction".to_string(),
            params: vec![tx.into()],
            id: "stacks".to_string(),
            jsonrpc: "2.0".to_string(),
        };

        let json_resp = BitcoinRPCRequest::send(&config, payload)?;

        println!("send_raw_transaction {:?}", json_resp);
        // TODO(psq): get transaction id from returned hex as Sha256dHash?


        if let Some(e) = json_resp.get("error") {
            if !e.is_null() {
                error!("Error submitting transaction: {}", json_resp);
                return Err(RPCError::Bitcoind(json_resp.to_string()));
            }
        }
        if let Some(serde_json::Value::String(hex)) = json_resp.get("result") {
        	println!("result {:?}", hex);
        	return Ok(Sha256dHash::from_hex(&hex).unwrap())
        }
        // if let serde_json::Value::String(hex) = json_resp {
        // }
        Err(RPCError::Bitcoind("no transaction id was returned".to_string()))

    }

    pub fn import_public_key(config: &Config, public_key: &Secp256k1PublicKey) -> RPCResult<()> {
        let rescan = true;
        let label = "";

        let pkh = Hash160::from_data(&public_key.to_bytes())
            .to_bytes()
            .to_vec();
        let network_id = config.bitcoin_network;
        let address =
            BitcoinAddress::from_bytes(network_id, BitcoinAddressType::PublicKeyHash, &pkh)
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
        request
            .append_header("Content-Type", "application/json")
            .expect("Unable to set header");
        request.set_body(body);

        let mut response = async_std::task::block_on(async move {
            let stream = match TcpStream::connect(config.btc_rpc_sock_addr).await {
                Ok(stream) => stream,
                Err(err) => {
                    return Err(RPCError::Network(format!(
                        "Bitcoin RPC: connection failed - {:?}",
                        err
                    )))
                }
            };

            match client::connect(stream, request).await {
                Ok(response) => Ok(response),
                Err(err) => {
                    return Err(RPCError::Network(format!(
                        "Bitcoin RPC: invoking procedure failed - {:?}",
                        err
                    )))
                }
            }
        })?;

        let status = response.status();

        let (res, buffer) = async_std::task::block_on(async move {
            let mut buffer = Vec::new();
            let mut body = response.take_body();
            let res = body.read_to_end(&mut buffer).await;
            (res, buffer)
        });

        if !status.is_success() {
            return Err(RPCError::Network(format!(
                "Bitcoin RPC: status({}) != success, body is '{:?}'",
                status,
                match serde_json::from_slice::<serde_json::Value>(&buffer[..]) {
                    Ok(v) => v,
                    Err(_e) => serde_json::from_str("\"(unparseable)\"")
                        .expect("Failed to parse JSON literal"),
                }
            )));
        }

        if res.is_err() {
            return Err(RPCError::Network(format!(
                "Bitcoin RPC: unable to read body - {:?}",
                res
            )));
        }

        let payload = serde_json::from_slice::<serde_json::Value>(&buffer[..])
            .map_err(|e| RPCError::Parsing(format!("Bitcoin RPC: {}", e)))?;
        Ok(payload)
    }
}


#[cfg(test)]
pub mod tests {
    // setup mocknet with faucet to fund miner and short block time
    // setup stacks node in follower mode, but used to propagate winning block (with a single miner, should be 100% of the time)

}






