// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2021 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// This module is concerned with the implementation of the BitcoinIndexer
// structure and its methods and traits.

use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::io;
use std::net::TcpStream;

use net::{
    Error as net_error, ExtendedStacksHeader, HttpResponseMetadata, PeerAddress, PeerHost,
    RPCPeerInfoData,
};

use burnchains::indexer::{
    BurnBlockIPC, BurnHeaderIPC, BurnchainBlockDownloader, BurnchainBlockParser, BurnchainIndexer,
};

use address::AddressHashMode;

use burnchains::BurnchainBlock;
use burnchains::BurnchainRecipient;
use burnchains::BurnchainSigner;
use burnchains::ConsensusHash;
use burnchains::Hash160;
use burnchains::IndexerError;
use burnchains::MagicBytes;
use burnchains::PoxConstants;
use burnchains::StacksPublicKey;
use burnchains::Txid;

use burnchains::Error as burnchain_error;

use codec::StacksMessageCodec;

use crate::types::chainstate::{
    BurnchainHeaderHash, StacksAddress, StacksBlockHeader, StacksBlockId,
};
use crate::types::proof::TrieHash;
use chainstate::burn::operations::*;
use chainstate::stacks::StacksBlock;
use chainstate::stacks::StacksPrivateKey;
use chainstate::stacks::TransactionSmartContract;
use chainstate::stacks::C32_ADDRESS_VERSION_MAINNET_SINGLESIG;
use chainstate::stacks::C32_ADDRESS_VERSION_TESTNET_SINGLESIG;
use core::{
    StacksEpoch, StacksEpochId, GENESIS_EPOCH, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05,
    STACKS_EPOCH_MAX,
};
use util::db::Error as db_error;
use util::hash::to_hex;
use util::hash::Sha512Trunc256Sum;
use util::strings::StacksString;
use vm::costs::ExecutionCost;
use vm::representations::UrlString;
use vm::types::ASCIIData;
use vm::types::CharType;
use vm::types::PrincipalData;
use vm::types::QualifiedContractIdentifier;
use vm::types::SequenceData;
use vm::types::TupleData;
use vm::types::Value;
use vm::ContractName;

pub mod client;
pub mod db;

use burnchains::stacks::db::LightClientDB;

#[derive(Debug)]
pub enum Error {
    HttpError(u16, String),
    ToSocketError(io::Error),
    ConnectError(io::Error),
    RequestError(io::Error),
    NetError(net_error),
    FilesystemError(io::Error),
    DBError(db_error),
    NotConnected,
    NoncontiguousHeader,
    BadPeer,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::HttpError(ref code, ref msg) => {
                write!(f, "{}", &format!("HttpError(code={}, msg={})", code, msg))
            }
            Error::ToSocketError(ref io_error) => fmt::Display::fmt(io_error, f),
            Error::ConnectError(ref io_error) => fmt::Display::fmt(io_error, f),
            Error::RequestError(ref io_error) => fmt::Display::fmt(io_error, f),
            Error::NetError(ref net_error) => fmt::Display::fmt(net_error, f),
            Error::FilesystemError(ref io_error) => fmt::Display::fmt(io_error, f),
            Error::DBError(ref db_error) => fmt::Display::fmt(db_error, f),
            Error::NotConnected => write!(f, "Not connected"),
            Error::NoncontiguousHeader => write!(f, "Non-contiguous header"),
            Error::BadPeer => write!(f, "Misbehaving or incorrect peer detected"),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::HttpError(ref _code, ref _msg) => None,
            Error::ToSocketError(ref io_error) => Some(io_error),
            Error::ConnectError(ref io_error) => Some(io_error),
            Error::RequestError(ref io_error) => Some(io_error),
            Error::NetError(ref net_error) => Some(net_error),
            Error::FilesystemError(ref io_error) => Some(io_error),
            Error::DBError(ref db_error) => Some(db_error),
            Error::NotConnected => None,
            Error::NoncontiguousHeader => None,
            Error::BadPeer => None,
        }
    }
}

impl From<db_error> for Error {
    fn from(e: db_error) -> Error {
        Error::DBError(e)
    }
}

impl From<net_error> for Error {
    fn from(e: net_error) -> Error {
        Error::NetError(e)
    }
}

/// Checked operations for Clarity value conversions
impl Value {
    pub fn checked_ascii(self) -> Option<String> {
        if let Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data }))) = self {
            match String::from_utf8(data) {
                Ok(s) => Some(s),
                Err(_) => None,
            }
        } else {
            None
        }
    }

    pub fn checked_u128(self) -> Option<u128> {
        if let Value::UInt(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    pub fn checked_i128(self) -> Option<i128> {
        if let Value::Int(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    pub fn checked_buff(self, sz: usize) -> Option<Vec<u8>> {
        if let Value::Sequence(SequenceData::Buffer(buffdata)) = self {
            if buffdata.data.len() <= sz {
                Some(buffdata.data)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn checked_buff_exact(self, sz: usize) -> Option<Vec<u8>> {
        if let Value::Sequence(SequenceData::Buffer(buffdata)) = self {
            if buffdata.data.len() == sz {
                Some(buffdata.data)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn checked_list(self) -> Option<Vec<Value>> {
        if let Value::Sequence(SequenceData::List(listdata)) = self {
            Some(listdata.data)
        } else {
            None
        }
    }

    pub fn checked_buff_padded(self, sz: usize, pad: u8) -> Option<Vec<u8>> {
        let mut data = self.checked_buff(sz)?;
        if sz > data.len() {
            for _ in data.len()..sz {
                data.push(pad)
            }
        }
        Some(data)
    }

    pub fn checked_bool(self) -> Option<bool> {
        if let Value::Bool(b) = self {
            Some(b)
        } else {
            None
        }
    }

    pub fn checked_tuple(self) -> Option<TupleData> {
        if let Value::Tuple(data) = self {
            Some(data)
        } else {
            None
        }
    }

    pub fn checked_optional(self) -> Option<Option<Value>> {
        if let Value::Optional(opt) = self {
            Some(match opt.data {
                Some(boxed_value) => Some(*boxed_value),
                None => None,
            })
        } else {
            None
        }
    }

    pub fn checked_principal(self) -> Option<PrincipalData> {
        if let Value::Principal(p) = self {
            Some(p)
        } else {
            None
        }
    }

    pub fn checked_result(self) -> Option<std::result::Result<Value, Value>> {
        if let Value::Response(res_data) = self {
            Some(if res_data.committed {
                Ok(*res_data.data)
            } else {
                Err(*res_data.data)
            })
        } else {
            None
        }
    }

    pub fn checked_result_ok(self) -> Option<Value> {
        if let Value::Response(res_data) = self {
            if res_data.committed {
                Some(*res_data.data)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn checked_result_err(self) -> Option<Value> {
        if let Value::Response(res_data) = self {
            if !res_data.committed {
                Some(*res_data.data)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// This is the global appchain config variable
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AppChainConfigV1 {
    /// Is this appchain a mainnet chain?
    pub mainnet: bool,
    /// Chain ID of this appchain's transactions and peer network messages
    pub chain_id: u32,
    /// What's the chain ID of the parent appchain?
    pub parent_chain_id: u32,
    /// What's the address of this appchain's mining contract on its parent chain?
    pub mining_contract_id: QualifiedContractIdentifier,
    /// Height in the parent chain when this appchain begins
    pub start_block: u64,
    /// Hash of the parent chain block at which this appchain begins
    pub start_block_hash: BurnchainHeaderHash,
    /// List of nodes to use as initial peers (a hint)
    /// (boot-node-p2p, boot-node-data), where boot-node-p2p = (pubkey, ip:port)
    pub boot_nodes: Vec<((StacksPublicKey, PeerHost), PeerHost)>,
    /// PoX constants to use
    pub pox_constants: PoxConstants,
    /// List of boot contracts to download and process from an initial peer
    pub boot_code_contract_names: Vec<ContractName>,
    /// Expected genesis root hash (authenticates the boot code and its state-changes)
    pub genesis_hash: TrieHash,
    /// Block execution limit
    pub block_limit: ExecutionCost,
    /// Initial balances
    pub initial_balances: Vec<(PrincipalData, u64)>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub enum AppChainConfig {
    V1(AppChainConfigV1),
}

/// This is parsed from entries in the `appchains` data-map
#[derive(Debug, Clone, PartialEq)]
pub struct MiningContractTransaction {
    /// On mainnet?
    pub mainnet: bool,
    /// Serialized burnchain operation
    pub data: Vec<u8>,
    /// Sender of this burnchain operation (can be a contract)
    pub sender: PrincipalData,
    /// Txid of the last transaction this sender mined, if the sender mined at all in the previous
    /// burn block.  Otherwise, this will be None, even if the sender mine at some point in the
    /// past
    pub last_sent_txid: (Txid, u32),
    /// Was this mined block chained to the last one?
    pub chained: bool,
    /// Recipients of parent chain tokens
    pub recipients: Vec<(StacksAddress, u64)>,
    /// Amount of tokens burnt
    pub burnt: u64,
    /// Parent chain block height in which this tx was mined.
    pub block_height: u32,
    /// Index into the list of block ops where this tx occurs
    pub vtxindex: u32,
}

impl AppChainConfigV1 {
    /// Instantiate an appchain config (v1) from a v1 Clarity value obtained from the mining
    /// contract.  If any fields are malformed or missing, returns None.
    pub fn from_value(
        mainnet: bool,
        parent_chain_id: u32,
        mining_contract_id: QualifiedContractIdentifier,
        genesis_hash: TrieHash,
        value: Value,
    ) -> Option<AppChainConfigV1> {
        let components = value.checked_tuple()?;
        let start_block = components
            .get("start-height")
            .ok()?
            .clone()
            .checked_u128()?;
        let chain_id = components.get("chain-id").ok()?.clone().checked_u128()?;
        let boot_node_tuples = components.get("boot-nodes").ok()?.clone().checked_list()?;
        let boot_nodes = boot_node_tuples
            .into_iter()
            .filter_map(|boot_node_tuple| {
                let components = boot_node_tuple.checked_tuple()?;
                let pubkey_bytes = components
                    .get("public-key")
                    .ok()?
                    .clone()
                    .checked_buff_exact(33)?;
                let host_bytes = components
                    .get("host")
                    .ok()?
                    .clone()
                    .checked_buff_exact(16)?;
                let port_bytes = components.get("port").ok()?.clone().checked_buff_exact(2)?;
                let data_host_bytes = components
                    .get("data-host")
                    .ok()?
                    .clone()
                    .checked_buff_exact(16)?;
                let data_port_bytes = components
                    .get("data-port")
                    .ok()?
                    .clone()
                    .checked_buff_exact(2)?;

                let pubkey = StacksPublicKey::from_slice(&pubkey_bytes).ok()?;
                let host = PeerAddress::from_slice(&host_bytes)?;
                let datahost = PeerAddress::from_slice(&data_host_bytes)?;

                // safe since checked_buff_exact(2) requires a buff of length 2
                let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
                let dataport = u16::from_be_bytes([data_port_bytes[0], data_port_bytes[1]]);
                Some((
                    (pubkey, PeerHost::IP(host, port)),
                    PeerHost::IP(datahost, dataport),
                ))
            })
            .collect();

        let pox_constants_tuple = components.get("pox").ok()?.clone().checked_tuple()?;
        let pox_constants = PoxConstants::new(
            pox_constants_tuple
                .get("reward-cycle-length")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            pox_constants_tuple
                .get("prepare-length")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            pox_constants_tuple
                .get("anchor-threshold")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            pox_constants_tuple
                .get("pox-rejection-fraction")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            pox_constants_tuple
                .get("pox-participation-threshold-pct")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            pox_constants_tuple
                .get("sunset-start")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            pox_constants_tuple
                .get("sunset-end")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
        );

        let boot_code_contract_names = components
            .get("boot-code")
            .ok()?
            .clone()
            .checked_list()?
            .into_iter()
            .filter_map(|boot_code_name| {
                let name = boot_code_name.checked_ascii()?;
                Some(ContractName::try_from(name).ok()?)
            })
            .collect();

        let block_limit_tuple = components
            .get("block-limit")
            .ok()?
            .clone()
            .checked_tuple()?;
        let block_limit = ExecutionCost {
            read_count: block_limit_tuple
                .get("read-count")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            read_length: block_limit_tuple
                .get("read-length")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            write_count: block_limit_tuple
                .get("write-count")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            write_length: block_limit_tuple
                .get("write-length")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
            runtime: block_limit_tuple
                .get("runtime")
                .ok()?
                .clone()
                .checked_u128()?
                .try_into()
                .ok()?,
        };

        let initial_balances_tuple = components
            .get("initial-balances")
            .ok()?
            .clone()
            .checked_list()?;
        let initial_balances = initial_balances_tuple
            .into_iter()
            .filter_map(|initial_balance_tuple| {
                let components = initial_balance_tuple.checked_tuple()?;
                let recipient = components
                    .get("recipient")
                    .ok()?
                    .clone()
                    .checked_principal()?;
                let amount = components
                    .get("amount")
                    .ok()?
                    .clone()
                    .checked_u128()?
                    .try_into()
                    .expect("FATAL: invalid config: initial balance must be a u64");
                Some((recipient, amount))
            })
            .collect();

        Some(AppChainConfigV1 {
            mainnet,
            chain_id: chain_id as u32,
            parent_chain_id,
            mining_contract_id,
            start_block: start_block as u64,
            start_block_hash: BurnchainHeaderHash([0u8; 32]), // to be filled in
            boot_nodes,
            pox_constants,
            boot_code_contract_names,
            genesis_hash,
            block_limit,
            initial_balances,
        })
    }
}

/// Wrapper around the various versions of appchain configs that might come into existence
impl AppChainConfig {
    pub fn from_value(
        mainnet: bool,
        parent_chain_id: u32,
        mining_contract_id: QualifiedContractIdentifier,
        version: u128,
        genesis_hash: TrieHash,
        value: Value,
    ) -> Option<AppChainConfig> {
        match version {
            1 => Some(AppChainConfig::V1(AppChainConfigV1::from_value(
                mainnet,
                parent_chain_id,
                mining_contract_id,
                genesis_hash,
                value,
            )?)),
            _ => None,
        }
    }

    pub fn set_first_block_hash(&mut self, bhh: BurnchainHeaderHash) {
        match *self {
            AppChainConfig::V1(ref mut config) => {
                config.start_block_hash = bhh;
            }
        }
    }

    pub fn mainnet(&self) -> bool {
        match *self {
            AppChainConfig::V1(ref config) => config.mainnet,
        }
    }

    pub fn parent_chain_id(&self) -> u32 {
        match *self {
            AppChainConfig::V1(ref config) => config.parent_chain_id,
        }
    }

    pub fn chain_id(&self) -> u32 {
        match *self {
            AppChainConfig::V1(ref config) => config.chain_id,
        }
    }

    pub fn mining_contract_id(&self) -> QualifiedContractIdentifier {
        match *self {
            AppChainConfig::V1(ref config) => config.mining_contract_id.clone(),
        }
    }

    pub fn start_block(&self) -> u64 {
        match *self {
            AppChainConfig::V1(ref config) => config.start_block,
        }
    }

    pub fn start_block_hash(&self) -> BurnchainHeaderHash {
        match *self {
            AppChainConfig::V1(ref config) => config.start_block_hash.clone(),
        }
    }

    pub fn pox_constants(&self) -> PoxConstants {
        match *self {
            AppChainConfig::V1(ref config) => config.pox_constants.clone(),
        }
    }

    pub fn block_limit(&self) -> ExecutionCost {
        match *self {
            AppChainConfig::V1(ref config) => config.block_limit.clone(),
        }
    }

    pub fn boot_nodes(&self) -> Vec<((StacksPublicKey, PeerHost), PeerHost)> {
        match *self {
            AppChainConfig::V1(ref config) => config.boot_nodes.clone(),
        }
    }

    pub fn genesis_hash(&self) -> TrieHash {
        match *self {
            AppChainConfig::V1(ref config) => config.genesis_hash.clone(),
        }
    }

    pub fn boot_code_contract_names(&self) -> Vec<ContractName> {
        match *self {
            AppChainConfig::V1(ref config) => config.boot_code_contract_names.clone(),
        }
    }

    pub fn initial_balances(&self) -> Vec<(PrincipalData, u64)> {
        match *self {
            AppChainConfig::V1(ref config) => config.initial_balances.clone(),
        }
    }
}

impl MiningContractTransaction {
    /// Instantiate a burnchain operation from an entry in the mining contract.  If any part of the
    /// given value is invalid, then return None.
    pub fn from_value(
        value: Value,
        mainnet: bool,
        block_height: u32,
        vtxindex: u32,
        last_sent_txid: Txid,
    ) -> Option<MiningContractTransaction> {
        // { sender: principal, chained?: bool, data: (buff 80), burnt: uint, transferred: uint, recipients: (list 2 principal) }
        let components = value.checked_tuple()?;
        let sender = components.get("sender").ok()?.clone().checked_principal()?;
        let chained = components.get("chained?").ok()?.clone().checked_bool()?;
        let data = components.get("data").ok()?.clone().checked_buff(80)?;
        let burnt = components.get("burnt").ok()?.clone().checked_u128()?;
        let total_transferred = components.get("transferred").ok()?.clone().checked_u128()?;
        let recipients = components.get("recipients").ok()?.clone().checked_list()?;

        if burnt > (u64::max_value() as u128) {
            return None;
        }

        if recipients.len() > 2 {
            return None;
        }

        let tokens_per_recipient = if recipients.len() > 0 {
            if total_transferred % (recipients.len() as u128) != 0 {
                // should divide evenly
                return None;
            }

            let tokens_per_recipient = total_transferred / (recipients.len() as u128);
            if tokens_per_recipient > (u64::max_value() as u128) {
                return None;
            }

            tokens_per_recipient
        } else {
            0
        };

        let mut decoded_recipients = vec![];
        for recipient in recipients.into_iter() {
            let principal = recipient.checked_principal()?;
            let addr = match principal {
                PrincipalData::Standard(data) => data.into(),
                _ => {
                    // can't transfer to contracts yet
                    return None;
                }
            };

            decoded_recipients.push((addr, tokens_per_recipient as u64));
        }

        let mut ret = MiningContractTransaction {
            mainnet,
            data,
            sender,
            last_sent_txid: (last_sent_txid, 1), // this is always 1 because StackStxOp and TransferStxOp expect it
            chained,
            recipients: decoded_recipients,
            burnt: burnt as u64,
            block_height,
            vtxindex,
        };

        if !ret.chained {
            // make it so that the last txid this miner sent won't correspond to any burnchain
            // transaction.
            ret.last_sent_txid = (ret.mock_txid(), 1);
        }
        Some(ret)
    }

    /// Create a burnchain operation out of a row from the mining contract, but such that the
    /// miner's last txid doesn't actually correspond to any burnchain operation.
    pub fn from_value_mock_txid(
        value: Value,
        mainnet: bool,
        block_height: u32,
        vtxindex: u32,
    ) -> Option<MiningContractTransaction> {
        let tmp = MiningContractTransaction::from_value(
            value.clone(),
            mainnet,
            block_height,
            vtxindex,
            Txid([0x00; 32]),
        )?;
        MiningContractTransaction::from_value(
            value,
            mainnet,
            block_height,
            vtxindex,
            tmp.mock_txid(),
        )
    }

    /// Convert the data in this struct into a Value.  But, represent *all* fields -- not just the
    /// ones from the mining contract.  The purpose of doing so is to generate a "burnchain txid"
    /// for this entry.
    fn to_extended_value(&self) -> Value {
        let mut total_transferred = 0;
        for (_, amt) in self.recipients.iter() {
            total_transferred += amt;
        }

        let mut mock_recipients: Vec<Value> = self
            .recipients
            .iter()
            .map(|(addr, _)| Value::Principal(addr.clone().into()))
            .collect();

        mock_recipients.push(Value::Principal(
            self.mock_change_recipient().address.into(),
        ));

        Value::Tuple(
            TupleData::from_data(vec![
                ("sender".into(), Value::Principal(self.sender.clone())),
                (
                    "last-sent-txid".into(),
                    Value::buff_from(self.last_sent_txid.0 .0.to_vec())
                        .expect("BUG: failed to represent txid as buff"),
                ),
                ("chained".into(), Value::Bool(self.chained)),
                (
                    "data".into(),
                    Value::buff_from(self.data.clone())
                        .expect("BUG: failed to rebuild buff from data"),
                ),
                ("burnt".into(), Value::UInt(self.burnt as u128)),
                ("transferred".into(), Value::UInt(total_transferred as u128)),
                (
                    "recipients".into(),
                    Value::list_from(mock_recipients)
                        .expect("BUG: failed to rebuild recipient list"),
                ),
                (
                    "block-height".into(),
                    Value::UInt(self.block_height as u128),
                ),
                ("vtxindex".into(), Value::UInt(self.vtxindex as u128)),
            ])
            .expect("BUG: failed to rebuild appchain tx tuple"),
        )
    }

    /// Deterministically generate a public key from a Clarity principal by hashing it to form a
    /// private key, and then taking that as the public key.  This is used to create a plausible
    /// entry for `apparent_sender` in block-commits, as well as representing BurnchainSigners.
    fn principal_to_mock_public_key(principal: &PrincipalData) -> StacksPublicKey {
        let mut privkey_buff_input = vec![];
        principal
            .consensus_serialize(&mut privkey_buff_input)
            .expect("BUG: failed to serialize principal to RAM");

        let pubkey = loop {
            let privkey_payload = Sha512Trunc256Sum::from_data(&privkey_buff_input).0;

            test_debug!("Try private key {}", &to_hex(&privkey_payload));
            match StacksPrivateKey::from_slice(&privkey_payload) {
                Ok(privk) => break StacksPublicKey::from_private(&privk),
                Err(_) => {
                    privkey_buff_input.clear();
                    privkey_buff_input.extend_from_slice(&privkey_payload);
                }
            }
        };

        pubkey
    }

    /// Create a plausible BurnchainSigner struct.  BurnchainSigners (i.e. tx inputs) don't really
    /// exist or have meaning in appchains, but we have to put something in if we're going to use
    /// burnchain operation structs intended for Bitcoin.
    pub fn mock_burnchain_signer(&self) -> BurnchainSigner {
        let mock_pubkey = MiningContractTransaction::principal_to_mock_public_key(&self.sender);
        BurnchainSigner {
            hash_mode: AddressHashMode::SerializeP2PKH,
            num_sigs: 1,
            public_keys: vec![mock_pubkey],
        }
    }

    /// Create a mocked txid that is globally unique but doesn't refer to any burnchain
    /// transaction.  This is used to simulate the presence of a previous transaction that is not a
    /// burnchain transaction for purposes of handling block-commit chaining and pairing PreSTX
    /// transactions to StackStx and TransferStx transactions.
    fn mock_txid(&self) -> Txid {
        Txid(Sha512Trunc256Sum::from_data(&self.txid().0).0)
    }

    /// Create a globally unique ID for the entry in the mining contract for this burnchain
    /// operation.  It doesn't correspond to an actual transaction anywhere, but it fills the
    /// purpose of a txid.  It is calculated by hashing all the state in this struct, as
    /// represented as an "extended Value" produced by `to_extended_value`.
    pub fn txid(&self) -> Txid {
        let mut value_bytes = vec![];
        self.to_extended_value()
            .serialize_write(&mut value_bytes)
            .expect("BUG: failed to serialize Value to bytes");

        let hash = Sha512Trunc256Sum::from_data(&value_bytes);
        Txid(hash.0)
    }

    /// Getter for vtxindex
    pub fn vtxindex(&self) -> u32 {
        self.vtxindex
    }

    /// Obtain the burnchain opcode used
    pub fn opcode(&self) -> u8 {
        *self.data.get(2).unwrap_or(&0)
    }

    /// Obtain the payload of the burnchain operation
    pub fn data(&self) -> Vec<u8> {
        self.data[3..].to_vec()
    }

    /// There is always one signer for each burnchain operation, as far as the burnchain DB is
    /// concerned.  While this is not true in practice, we do need to recreate enough of a mocked
    /// BurnchainSigner for this burnchain operation to be processible
    pub fn num_signers(&self) -> usize {
        1
    }

    /// Get the 1-item list that contains the mocked burnchain signer
    pub fn get_signers(&self) -> Vec<BurnchainSigner> {
        vec![self.mock_burnchain_signer()]
    }

    /// Get the fake signer of this transaction
    pub fn get_signer(&self, input: usize) -> Option<BurnchainSigner> {
        self.get_signers().get(input).cloned()
    }

    /// Get the transaction ID of the burnchain operation that was last sent by the principal that
    /// sent this burnchain operation (as well as its mocked vout)
    pub fn get_input_tx_ref(&self, input: usize) -> Option<&(Txid, u32)> {
        if input == 0 {
            Some(&self.last_sent_txid)
        } else {
            None
        }
    }

    /// Mock recipient.  Per our Bitcoin legacy, each burnchain operation needs a "change output"
    /// even though it doesn't make sense here.  Use the sender here, or if the sender is a
    /// contract, use the issuer.
    fn mock_change_recipient(&self) -> BurnchainRecipient {
        match self.sender {
            PrincipalData::Standard(ref data) => BurnchainRecipient {
                address: StacksAddress {
                    version: data.0,
                    bytes: Hash160(data.1.clone()),
                },
                amount: 1,
            },
            PrincipalData::Contract(ref data) => BurnchainRecipient {
                address: StacksAddress {
                    version: data.issuer.0,
                    bytes: Hash160(data.issuer.1.clone()),
                },
                amount: 1,
            },
        }
    }

    /// Get the list of fake recipients
    pub fn get_recipients(&self) -> Vec<BurnchainRecipient> {
        // mock a "change output" so there's always at least one recipient.
        // This is the legacy we inherit from Bitcoin.
        let mut recipients: Vec<BurnchainRecipient> = self
            .recipients
            .iter()
            .map(|(addr, amount)| BurnchainRecipient {
                address: addr.clone(),
                amount: *amount,
            })
            .collect();

        recipients.push(self.mock_change_recipient());
        recipients
    }

    /// Get the total amount of tokens burnt or transferred
    pub fn get_burn_amount(&self) -> u64 {
        self.burnt
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MiningContractBlock {
    pub header: ExtendedStacksHeader,
    pub txs: Vec<MiningContractTransaction>,
}

pub struct AppChainClient {
    /// Mainnet or testnet appchain
    pub mainnet: bool,
    /// Our appchain chain ID
    pub chain_id: u32,
    /// Parent chain ID
    pub parent_chain_id: u32,
    /// Parent chain peer to boot from
    pub peer: (String, u16),
    /// Path to the headers DB
    pub headers_path: String,
    /// TCP connection timeout to parent chain peer
    pub connect_timeout: u64,
    /// Request duration timeout to appchain peer
    pub duration_timeout: u64,
    /// Mining contract on the parent chain
    pub contract_id: QualifiedContractIdentifier,
    /// Magic bytes for mining contract payloads
    pub magic_bytes: MagicBytes,
    /// Mapping between the parent chain's state index root hashes and block IDs
    pub root_to_block: HashMap<TrieHash, StacksBlockId>,
    /// Parent chain tip (set at runtime)
    pub tip: Option<StacksBlockId>,
    /// App chain config (learned from mining contract at runtime)
    pub config: Option<AppChainConfig>, // loaded from the parent chain
    /// Runtime session
    pub session: Option<(TcpStream, RPCPeerInfoData)>,
    /// Genesis state root hash
    pub genesis_hash: TrieHash,
    /// Boot code fetched
    pub boot_code: HashMap<ContractName, StacksString>,
}

impl BurnHeaderIPC for ExtendedStacksHeader {
    type H = ExtendedStacksHeader;

    fn height(&self) -> u64 {
        self.header.total_work.work
    }

    fn header(&self) -> ExtendedStacksHeader {
        self.clone()
    }

    fn header_hash(&self) -> [u8; 32] {
        StacksBlockHeader::make_index_block_hash(&self.consensus_hash, &self.header.block_hash()).0
    }
}

impl BurnBlockIPC for MiningContractBlock {
    type H = ExtendedStacksHeader;
    type B = MiningContractBlock;

    fn height(&self) -> u64 {
        self.header.height().into()
    }

    fn header(&self) -> ExtendedStacksHeader {
        self.header.clone()
    }

    fn block(&self) -> MiningContractBlock {
        self.clone()
    }
}

impl BurnchainBlockDownloader for AppChainClient {
    type H = ExtendedStacksHeader;
    type B = MiningContractBlock;

    fn download(
        &mut self,
        header: &ExtendedStacksHeader,
    ) -> Result<MiningContractBlock, burnchain_error> {
        self.with_session(|client, tcp_socket, _peer_info| {
            client.download_block(tcp_socket, header)
        })
    }
}

impl BurnchainBlockParser for AppChainClient {
    type D = AppChainClient;

    fn parse(&mut self, block: &MiningContractBlock) -> Result<BurnchainBlock, burnchain_error> {
        Ok(BurnchainBlock::Stacks(block.clone()))
    }
}

impl BurnchainIndexer for AppChainClient {
    type P = AppChainClient;

    fn connect(&mut self) -> Result<(), burnchain_error> {
        self.bootup(&self.boot_code.clone()).and_then(|_| Ok(()))
    }

    fn get_first_block_height(&self) -> u64 {
        self.config
            .as_ref()
            .expect("BUG: bootup() not yet called successfully")
            .start_block()
    }

    fn get_first_block_header_hash(&self) -> Result<BurnchainHeaderHash, burnchain_error> {
        if let Some(config) = self.config.as_ref() {
            Ok(config.start_block_hash())
        } else {
            Err(burnchain_error::NotConnected)
        }
    }

    fn get_first_block_header_timestamp(&self) -> Result<u64, burnchain_error> {
        Ok(0)
    }

    fn get_stacks_epochs(&self) -> Vec<StacksEpoch> {
        vec![
            // first block must always be the genesis epoch
            StacksEpoch {
                epoch_id: GENESIS_EPOCH,
                start_height: 0,
                end_height: 1,
                block_limit: self
                    .config
                    .as_ref()
                    .expect("BUG: bootup() not yet called successfully")
                    .block_limit()
                    .clone(),
                network_epoch: PEER_VERSION_EPOCH_2_0,
            },
            StacksEpoch {
                epoch_id: StacksEpochId::Epoch2_05,
                start_height: 1,
                end_height: STACKS_EPOCH_MAX,
                block_limit: self
                    .config
                    .as_ref()
                    .expect("BUG: bootup() not yet called successfully")
                    .block_limit()
                    .clone(),
                network_epoch: PEER_VERSION_EPOCH_2_05,
            },
        ]
    }

    fn get_headers_path(&self) -> String {
        self.headers_path.clone()
    }

    fn get_headers_height(&self) -> Result<u64, burnchain_error> {
        let light_client = LightClientDB::new(&self.headers_path, false)?;
        light_client
            .get_headers_height()
            .map_err(|e| burnchain_error::Indexer(IndexerError::Stacks(e)))
    }

    fn get_highest_header_height(&self) -> Result<u64, burnchain_error> {
        let light_client = LightClientDB::new(&self.headers_path, false)?;
        light_client
            .get_highest_header_height()
            .map_err(|e| burnchain_error::Indexer(IndexerError::Stacks(e)))
    }

    fn find_chain_reorg(&mut self) -> Result<u64, burnchain_error> {
        debug!("Checking for burnchain reorg...");
        self.with_session(|client, tcp_socket, peer_info| {
            client.find_reorg_height(tcp_socket, peer_info)
        })
    }

    fn sync_headers(
        &mut self,
        _start_height: u64,
        _end_height: Option<u64>,
    ) -> Result<u64, burnchain_error> {
        let (highest_header_opt, _) = self
            .with_session(|client, tcp_socket, _peer_info| client.sync_all_headers(tcp_socket))?;

        Ok(highest_header_opt
            .map(|hdr| hdr.header.total_work.work)
            .unwrap_or(self.get_highest_header_height()?))
    }

    fn drop_headers(&mut self, new_height: u64) -> Result<(), burnchain_error> {
        let mut light_client = LightClientDB::new(&self.headers_path, true)?;
        light_client
            .drop_headers(new_height)
            .map_err(|e| burnchain_error::Indexer(IndexerError::Stacks(e)))
    }

    fn read_headers(
        &self,
        start_block: u64,
        end_block: u64,
    ) -> Result<Vec<ExtendedStacksHeader>, burnchain_error> {
        let light_client = LightClientDB::new(&self.headers_path, false)?;
        light_client
            .read_block_headers(start_block, end_block)
            .map_err(|e| burnchain_error::Indexer(IndexerError::Stacks(e)))
    }

    fn downloader(&self) -> AppChainClient {
        self.cloned()
    }

    fn parser(&self) -> AppChainClient {
        self.cloned()
    }
}
