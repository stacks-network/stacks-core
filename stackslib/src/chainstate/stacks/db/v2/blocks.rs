

use std::collections::{BTreeMap, btree_map::Entry};

use clarity::vm::{
    types::{PrincipalData, TupleData, BuffData, StacksAddressExtensions, QualifiedContractIdentifier}, 
    database::NULL_BURN_STATE_DB, ContractName, ast::ASTRules, 
    events::{StacksTransactionEvent, STXEventType, STXMintEventData}, 
    Value, costs::ExecutionCost, tests::BurnStateDB, 
    errors::{CheckErrors, Error as InterpreterError}, clarity::TransactionConnection, contexts::AssetMap, ClarityVersion
};
use stacks_common::{
    types::{chainstate::{StacksAddress, StacksBlockId, TrieHash, ConsensusHash, BlockHeaderHash}, Address, StacksEpochId}, 
    address::{
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_MAINNET_MULTISIG, 
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_MULTISIG
    }, util::hash::Hash160
};

use crate::{
    burnchains::bitcoin::address::LegacyBitcoinAddress, 
    chainstate::stacks::{
            address::StacksAddressExtensions as ChainstateStacksAddressExtensions,
            Error, events::StacksTransactionReceipt, TransactionVersion, boot, TransactionPayload, 
            TransactionSmartContract, StacksTransaction, TokenTransferMemo, StacksBlockHeader, 
            db::StacksHeaderInfo, 
            index::{
                ClarityMarfTrieId, db::DbConnection, trie_db::TrieDb, marf::MARF
            }
    }, 
    util_lib::{
        boot::{boot_code_addr, boot_code_tx_auth, boot_code_acc, boot_code_id}, 
        strings::{StacksString, VecDisplay}
    }, 
    core::{
        BURNCHAIN_BOOT_CONSENSUS_HASH, BOOT_BLOCK_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, 
        FIRST_STACKS_BLOCK_HASH, MAINNET_2_0_GENESIS_ROOT_HASH
    }, 
    net::atlas::BNS_CHARS_REGEX, 
    clarity_vm::clarity::{
        ClarityBlockConnection, ClarityConnection, ClarityInstance, ClarityTransactionConnection,
        Error as clarity_error,
    },
};

use super::{
    super::{ChainStateBootData, ClarityTx, DBConfig, CHAINSTATE_VERSION, StacksAccount, transactions::ClarityRuntimeTxError},
    utils::ChainStateUtils,
    StacksChainStateImpl
};

impl<Conn> StacksChainStateImpl<Conn>
where
    Conn: DbConnection + TrieDb
{
    /// Retrieves the root hash of the genesis block.
    pub fn get_genesis_root_hash(&self) -> Result<TrieHash, Error> {
        let root_hash = self.clarity_state.with_marf(|marf| {
            let index_block_hash = StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            );
            marf.get_root_hash_at(&index_block_hash)
        })?;

        Ok(root_hash)
    }

    /// Begin a transaction against the Clarity VM for initiating the genesis block
    ///  the genesis block is special cased because it must be evaluated _before_ the
    ///  cost contract is loaded in the boot code.
    pub fn genesis_block_begin<'a>(
        &'a mut self,
        burn_dbconn: &'a dyn BurnStateDB,
        parent_consensus_hash: &ConsensusHash,
        parent_block: &BlockHeaderHash,
        new_consensus_hash: &ConsensusHash,
        new_block: &BlockHeaderHash,
    ) -> ClarityTx<'a, 'a> {
        let conf = self.config();
        let db = &self.state_index;
        let clarity_instance = &mut self.clarity_state;

        // mix burn header hash and stacks block header hash together, since the stacks block hash
        // it not guaranteed to be globally unique (but the burn header hash _is_).
        let parent_index_block =
            ChainStateUtils::get_parent_index_block(parent_consensus_hash, parent_block);

        let new_index_block =
            StacksBlockHeader::make_index_block_hash(new_consensus_hash, new_block);

        test_debug!(
            "Begin processing genesis Stacks block off of {}/{}",
            parent_consensus_hash,
            parent_block
        );
        test_debug!(
            "Child MARF index root:  {} = {} + {}",
            new_index_block,
            new_consensus_hash,
            new_block
        );
        test_debug!(
            "Parent MARF index root: {} = {} + {}",
            parent_index_block,
            parent_consensus_hash,
            parent_block
        );

        let inner_clarity_tx = clarity_instance.begin_genesis_block(
            &parent_index_block,
            &new_index_block,
            db,
            burn_dbconn,
        );

        test_debug!("Got clarity TX!");
        ClarityTx {
            block: inner_clarity_tx,
            config: conf,
        }
    }
}