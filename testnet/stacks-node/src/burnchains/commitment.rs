use reqwest::StatusCode;
use stacks::address::AddressHashMode;
use stacks::chainstate::stacks::miner::Proposal;
use stacks::chainstate::stacks::{
    StacksPrivateKey, StacksPublicKey, StacksTransaction, StacksTransactionSigner, TransactionAuth,
    TransactionContractCall, TransactionPostConditionMode, TransactionSpendingCondition,
    TransactionVersion,
};
use stacks::net::http::HttpBlockProposalRejected;
use stacks::util::hash::hex_bytes;
use stacks::vm::types::{QualifiedContractIdentifier, TupleData};
use stacks::vm::ClarityName;
use stacks::vm::Value as ClarityValue;
use stacks_common::types::chainstate::{BlockHeaderHash, BurnchainHeaderHash, StacksAddress};
use stacks_common::util::hash::Sha512Trunc256Sum;

use crate::config::BurnchainConfig;
use crate::operations::BurnchainOpSigner;

use super::ClaritySignature;

pub trait Layer1Committer {
    /// Return the number of signatures that need to be included alongside a commit transaction
    fn commit_required_signatures(&self) -> u8;
    /// Send a block proposal to the participant indicated by `participant_index`.
    /// If `participant_index >= (self.commit_required_signatures - 1)`, this will return an error because:
    ///   * It refers to a non-existent participant (if >= self.commit_required_signatures)
    ///   * Or it refers to the current miner (which is logically = index self.commit_required_signatures - 1)
    fn propose_block_to(
        &self,
        participant_index: u8,
        proposal: &Proposal,
    ) -> Result<ClaritySignature, Error>;
    fn make_commit_tx(
        &self,
        committed_block_hash: BlockHeaderHash,
        target_tip: BurnchainHeaderHash,
        withdrawal_merkle_root: Sha512Trunc256Sum,
        signatures: Vec<ClaritySignature>,
        attempt: u64,
        op_signer: &mut BurnchainOpSigner,
    ) -> Result<StacksTransaction, Error>;
}

pub struct DirectCommitter {
    pub config: BurnchainConfig,
}

#[derive(Clone, Debug)]
pub struct MultiMinerParticipant {
    pub public_key: [u8; 33],
    pub rpc_server: String,
}

pub struct MultiPartyCommitter {
    pub config: BurnchainConfig,
    other_participants: Vec<MultiMinerParticipant>,
    required_signers: u8,
    contract: QualifiedContractIdentifier,
}

/// Represents the returned JSON
///  from the L1 /v2/accounts endpoint
#[derive(Deserialize)]
struct RpcAccountResponse {
    nonce: u64,
    #[allow(dead_code)]
    balance: String,
}

#[derive(Debug)]
pub enum Error {
    AlreadyCommitted,
    NonceGetFailure(String),
    BadCommitment,
    NoSuchParticipant,
    BlockProposalRequest(String),
    BlockProposalRejected(String),
}

fn l1_addr_from_signer(is_mainnet: bool, signer: &BurnchainOpSigner) -> StacksAddress {
    let hash_mode = AddressHashMode::SerializeP2PKH;
    let addr_version = if is_mainnet {
        hash_mode.to_version_mainnet()
    } else {
        hash_mode.to_version_testnet()
    };
    StacksAddress::from_public_keys(addr_version, &hash_mode, 1, &vec![signer.get_public_key()])
        .expect("Failed to make Stacks address from public key")
}

fn l1_get_nonce(l1_rpc_interface: &str, address: &StacksAddress) -> Result<u64, Error> {
    let url = format!("{}/v2/accounts/{}?proof=0", l1_rpc_interface, address);
    let response_json: RpcAccountResponse = reqwest::blocking::get(url)
        .map_err(|e| Error::NonceGetFailure(e.to_string()))?
        .json()
        .map_err(|e| Error::NonceGetFailure(e.to_string()))?;
    Ok(response_json.nonce)
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AlreadyCommitted => {
                write!(f, "Commitment previously constructed at this burn block")
            }
            Error::NonceGetFailure(e) => write!(f, "Failed to obtain miner's nonce: {}", e),
            Error::BlockProposalRequest(e) => {
                write!(f, "Failure during block proposal request: {}", e)
            }
            Error::BlockProposalRejected(e) => write!(f, "Rejected block proposal: {}", e),
            Error::BadCommitment => write!(f, "Submitted commitment contents are not valid"),
            Error::NoSuchParticipant => write!(
                f,
                "Participant index refers to a non-existent participant or the current node (self)"
            ),
        }
    }
}

impl MultiPartyCommitter {
    pub fn new(
        config: &BurnchainConfig,
        required_signers: u8,
        contract: &QualifiedContractIdentifier,
        other_participants: Vec<MultiMinerParticipant>,
    ) -> Self {
        Self {
            config: config.clone(),
            required_signers,
            contract: contract.clone(),
            other_participants,
        }
    }

    fn make_mine_contract_call(
        &self,
        sender: &StacksPrivateKey,
        sender_nonce: u64,
        tx_fee: u64,
        commit_to: BlockHeaderHash,
        target_tip: BurnchainHeaderHash,
        withdrawal_root: Sha512Trunc256Sum,
        signatures: Vec<ClaritySignature>,
    ) -> Result<StacksTransaction, Error> {
        let QualifiedContractIdentifier {
            issuer: contract_addr,
            name: contract_name,
        } = self.contract.clone();
        let version = if self.config.is_mainnet() {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };

        let block_val = ClarityValue::buff_from(commit_to.as_bytes().to_vec())
            .map_err(|_| Error::BadCommitment)?;
        let target_tip_val = ClarityValue::buff_from(target_tip.as_bytes().to_vec())
            .map_err(|_| Error::BadCommitment)?;
        let withdrawal_root_val = ClarityValue::buff_from(withdrawal_root.as_bytes().to_vec())
            .map_err(|_| Error::BadCommitment)?;
        let signatures_val = ClarityValue::list_from(
            signatures
                .into_iter()
                .map(|s| {
                    ClarityValue::buff_from(s.0.to_vec())
                        .expect("Failed to construct length 65 buffer")
                })
                .collect(),
        )
        .map_err(|_| Error::BadCommitment)?;

        let block_data_val = TupleData::from_data(vec![
            ("block".into(), block_val),
            ("withdrawal-root".into(), withdrawal_root_val),
            ("target-tip".into(), target_tip_val),
        ])
        .map_err(|_| Error::BadCommitment)?;

        let payload = TransactionContractCall {
            address: contract_addr.into(),
            contract_name,
            function_name: ClarityName::from("commit-block"),
            function_args: vec![block_data_val.into(), signatures_val],
        };

        let mut sender_spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(
            StacksPublicKey::from_private(sender),
        )
        .expect("Failed to create p2pkh spending condition from public key.");
        sender_spending_condition.set_nonce(sender_nonce);
        sender_spending_condition.set_tx_fee(tx_fee);
        let auth = TransactionAuth::Standard(sender_spending_condition);

        let mut unsigned_tx = StacksTransaction::new(version, auth, payload.into());
        unsigned_tx.anchor_mode = self.config.anchor_mode.clone();
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        unsigned_tx.chain_id = self.config.chain_id;

        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer.sign_origin(sender).unwrap();

        Ok(tx_signer
            .get_tx()
            .expect("Failed to get signed transaction from signer"))
    }

    pub fn make_commit_tx(
        &self,
        committed_block_hash: BlockHeaderHash,
        target_tip: BurnchainHeaderHash,
        withdrawal_merkle_root: Sha512Trunc256Sum,
        signatures: Vec<ClaritySignature>,
        attempt: u64,
        op_signer: &mut BurnchainOpSigner,
    ) -> Result<StacksTransaction, Error> {
        // todo: think about enabling replace-by-nonce?
        if attempt > 1 {
            return Err(Error::AlreadyCommitted);
        }

        // step 1: figure out the miner's nonce
        let miner_address = l1_addr_from_signer(self.config.is_mainnet(), op_signer);
        let nonce = l1_get_nonce(&self.config.get_rpc_url(), &miner_address).map_err(|e| {
            error!("Failed to obtain miner nonce: {}", e);
            e
        })?;

        // step 2: fee estimate (todo: #140)
        let fee = 100_000;
        self.make_mine_contract_call(
            op_signer.get_sk(),
            nonce,
            fee,
            committed_block_hash,
            target_tip,
            withdrawal_merkle_root,
            signatures,
        )
        .map_err(|e| {
            error!("Failed to construct contract call operation: {}", e);
            e
        })
    }
}

impl Layer1Committer for MultiPartyCommitter {
    fn commit_required_signatures(&self) -> u8 {
        // return (required_signers - 1) because the submitted transaction itself counts as a signature.
        self.required_signers.saturating_sub(1)
    }

    fn propose_block_to(
        &self,
        participant_index: u8,
        proposal: &Proposal,
    ) -> Result<ClaritySignature, Error> {
        if self.required_signers == 0
            || participant_index >= self.required_signers - 1
            || participant_index as usize >= self.other_participants.len()
        {
            return Err(Error::NoSuchParticipant);
        }
        let propose_to = &self.other_participants[participant_index as usize];
        let url = format!(
            "{}{}",
            &propose_to.rpc_server,
            stacks::net::http::PATH_STR_POST_BLOCK_PROPOSAL
        );
        let response = reqwest::blocking::Client::new()
            .post(url)
            .json(proposal)
            .send()
            .map_err(|e| Error::BlockProposalRequest(e.to_string()))?;
        match response.status() {
            StatusCode::OK => {
                let signature_hex: String = response
                    .json()
                    .map_err(|e| Error::BlockProposalRequest(e.to_string()))?;
                // 132 = 65 * 2 + "0x" prefix
                if signature_hex.len() != 132 {
                    return Err(Error::BlockProposalRequest(
                        "Bad signature hex length".into(),
                    ));
                }

                let signature_bytes = hex_bytes(&signature_hex[2..])
                    .map_err(|_| Error::BlockProposalRequest("Bad hex bytes".into()))?;
                if signature_bytes.len() != 65 {
                    return Err(Error::BlockProposalRequest(
                        "Bad signature byte length".into(),
                    ));
                }
                let mut signature_buff = [0u8; 65];
                signature_buff.copy_from_slice(&signature_bytes);
                Ok(ClaritySignature(signature_buff))
            }
            StatusCode::NOT_ACCEPTABLE => {
                let error_struct: HttpBlockProposalRejected = response
                    .json()
                    .map_err(|e| Error::BlockProposalRequest(e.to_string()))?;
                Err(Error::BlockProposalRejected(error_struct.error_message))
            }
            _ => {
                let error_message = response
                    .text()
                    .map_err(|e| Error::BlockProposalRequest(e.to_string()))?;
                Err(Error::BlockProposalRequest(error_message))
            }
        }
    }

    fn make_commit_tx(
        &self,
        committed_block_hash: BlockHeaderHash,
        target_tip: BurnchainHeaderHash,
        withdrawal_merkle_root: Sha512Trunc256Sum,
        signatures: Vec<ClaritySignature>,
        attempt: u64,
        op_signer: &mut BurnchainOpSigner,
    ) -> Result<StacksTransaction, Error> {
        self.make_commit_tx(
            committed_block_hash,
            target_tip,
            withdrawal_merkle_root,
            signatures,
            attempt,
            op_signer,
        )
    }
}

impl Layer1Committer for DirectCommitter {
    fn commit_required_signatures(&self) -> u8 {
        0
    }

    fn make_commit_tx(
        &self,
        committed_block_hash: BlockHeaderHash,
        target_tip: BurnchainHeaderHash,
        withdrawal_merkle_root: Sha512Trunc256Sum,
        _signatures: Vec<ClaritySignature>,
        attempt: u64,
        op_signer: &mut BurnchainOpSigner,
    ) -> Result<StacksTransaction, Error> {
        self.make_commit_tx(
            committed_block_hash,
            target_tip,
            withdrawal_merkle_root,
            attempt,
            op_signer,
        )
    }

    fn propose_block_to(
        &self,
        _participant_index: u8,
        _proposal: &Proposal,
    ) -> Result<ClaritySignature, Error> {
        Err(Error::NoSuchParticipant)
    }
}

impl DirectCommitter {
    fn make_mine_contract_call(
        &self,
        sender: &StacksPrivateKey,
        sender_nonce: u64,
        tx_fee: u64,
        commit_to: BlockHeaderHash,
        target_tip: BurnchainHeaderHash,
        withdrawal_root: Sha512Trunc256Sum,
    ) -> Result<StacksTransaction, Error> {
        let QualifiedContractIdentifier {
            issuer: contract_addr,
            name: contract_name,
        } = self.config.contract_identifier.clone();
        let version = if self.config.is_mainnet() {
            TransactionVersion::Mainnet
        } else {
            TransactionVersion::Testnet
        };
        let committed_block = commit_to.as_bytes().to_vec();
        let target_tip_bytes = target_tip.as_bytes().to_vec();
        let withdrawal_root_bytes = withdrawal_root.as_bytes().to_vec();
        let payload = TransactionContractCall {
            address: contract_addr.into(),
            contract_name,
            function_name: ClarityName::from("commit-block"),
            function_args: vec![
                ClarityValue::buff_from(committed_block).map_err(|_| Error::BadCommitment)?,
                ClarityValue::buff_from(target_tip_bytes).map_err(|_| Error::BadCommitment)?,
                ClarityValue::buff_from(withdrawal_root_bytes).map_err(|_| Error::BadCommitment)?,
            ],
        };

        let mut sender_spending_condition = TransactionSpendingCondition::new_singlesig_p2pkh(
            StacksPublicKey::from_private(sender),
        )
        .expect("Failed to create p2pkh spending condition from public key.");
        sender_spending_condition.set_nonce(sender_nonce);
        sender_spending_condition.set_tx_fee(tx_fee);
        let auth = TransactionAuth::Standard(sender_spending_condition);

        let mut unsigned_tx = StacksTransaction::new(version, auth, payload.into());
        unsigned_tx.anchor_mode = self.config.anchor_mode.clone();
        unsigned_tx.post_condition_mode = TransactionPostConditionMode::Allow;
        unsigned_tx.chain_id = self.config.chain_id;

        let mut tx_signer = StacksTransactionSigner::new(&unsigned_tx);
        tx_signer.sign_origin(sender).unwrap();

        Ok(tx_signer
            .get_tx()
            .expect("Failed to get signed transaction from signer"))
    }

    pub fn make_commit_tx(
        &self,
        committed_block_hash: BlockHeaderHash,
        target_tip: BurnchainHeaderHash,
        withdrawal_merkle_root: Sha512Trunc256Sum,
        attempt: u64,
        op_signer: &mut BurnchainOpSigner,
    ) -> Result<StacksTransaction, Error> {
        // todo: think about enabling replace-by-nonce?
        if attempt > 1 {
            return Err(Error::AlreadyCommitted);
        }

        // step 1: figure out the miner's nonce
        let miner_address = l1_addr_from_signer(self.config.is_mainnet(), op_signer);
        let nonce = l1_get_nonce(&self.config.get_rpc_url(), &miner_address).map_err(|e| {
            error!("Failed to obtain miner nonce: {}", e);
            e
        })?;

        // step 2: fee estimate (todo: #140)
        let fee = 100_000;
        self.make_mine_contract_call(
            op_signer.get_sk(),
            nonce,
            fee,
            committed_block_hash,
            target_tip,
            withdrawal_merkle_root,
        )
        .map_err(|e| {
            error!("Failed to construct contract call operation: {}", e);
            e
        })
    }
}
