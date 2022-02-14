use std::env;

use stacks::chainstate::stacks::db::{
    ChainstateAccountBalance, ChainstateAccountLockup, ChainstateBNSName, ChainstateBNSNamespace,
    StacksHeaderInfo,
};
use stacks::chainstate::stacks::events::StacksTransactionReceipt;
use stacks::chainstate::stacks::StacksBlock;
use stacks::types::chainstate::BurnchainHeaderHash;
use stacks::types::chainstate::TrieHash;

use crate::genesis_data::USE_TEST_GENESIS_CHAINSTATE;
use crate::Config;

#[derive(Debug, Clone)]
pub struct ChainTip {
    pub metadata: StacksHeaderInfo,
    pub block: StacksBlock,
    pub receipts: Vec<StacksTransactionReceipt>,
}

impl ChainTip {
    pub fn genesis(
        first_burnchain_block_hash: &BurnchainHeaderHash,
        first_burnchain_block_height: u64,
        first_burnchain_block_timestamp: u64,
    ) -> ChainTip {
        ChainTip {
            metadata: StacksHeaderInfo::genesis(
                TrieHash([0u8; 32]),
                first_burnchain_block_hash,
                first_burnchain_block_height as u32,
                first_burnchain_block_timestamp,
            ),
            block: StacksBlock::genesis_block(),
            receipts: vec![],
        }
    }
}

pub fn get_account_lockups(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountLockup>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_lockups()
            .map(|item| ChainstateAccountLockup {
                address: item.address,
                amount: item.amount,
                block_height: item.block_height,
            }),
    )
}

pub fn get_account_balances(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateAccountBalance>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_balances()
            .map(|item| ChainstateAccountBalance {
                address: item.address,
                amount: item.amount,
            }),
    )
}

pub fn get_namespaces(
    use_test_chainstate_data: bool,
) -> Box<dyn Iterator<Item = ChainstateBNSNamespace>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_namespaces()
            .map(|item| ChainstateBNSNamespace {
                namespace_id: item.namespace_id,
                importer: item.importer,
                buckets: item.buckets,
                base: item.base as u64,
                coeff: item.coeff as u64,
                nonalpha_discount: item.nonalpha_discount as u64,
                no_vowel_discount: item.no_vowel_discount as u64,
                lifetime: item.lifetime as u64,
            }),
    )
}

pub fn get_names(use_test_chainstate_data: bool) -> Box<dyn Iterator<Item = ChainstateBNSName>> {
    Box::new(
        stx_genesis::GenesisData::new(use_test_chainstate_data)
            .read_names()
            .map(|item| ChainstateBNSName {
                fully_qualified_name: item.fully_qualified_name,
                owner: item.owner,
                zonefile_hash: item.zonefile_hash,
            }),
    )
}

// Check if the small test genesis chainstate data should be used.
// First check env var, then config file, then use default.
pub fn use_test_genesis_chainstate(config: &Config) -> bool {
    if env::var("BLOCKSTACK_USE_TEST_GENESIS_CHAINSTATE") == Ok("1".to_string()) {
        true
    } else if let Some(use_test_genesis_chainstate) = config.node.use_test_genesis_chainstate {
        use_test_genesis_chainstate
    } else {
        USE_TEST_GENESIS_CHAINSTATE
    }
}
