
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
use super::{StacksChainState, StacksChainStateImpl};

use super::{
    ChainStateBootData, ClarityTx, DBConfig, CHAINSTATE_VERSION, StacksAccount,
};

impl<Conn> StacksChainStateImpl<Conn>
where
    Conn: DbConnection + TrieDb
{
}