use crate::burnchains::l1_events::burnchain_from_config;
use crate::burnchains::tests::{make_test_new_block, random_sortdb_test_dir};
use crate::config::BurnchainConfig;
use crate::{burnchains::db_indexer::DBBurnchainIndexer, rand::RngCore};
use rand;
use stacks::burnchains::events::{NewBlock, NewBlockTxEvent};
use stacks::burnchains::indexer::BurnchainIndexer;
use stacks::burnchains::Burnchain;
use stacks::burnchains::Error as BurnchainError;
use stacks::chainstate::coordinator::CoordinatorCommunication;
use stacks::types::chainstate::{BurnchainHeaderHash, StacksBlockId};
use stacks::util::hash::to_hex;

/// Create config settings for the tests.
fn make_test_config() -> BurnchainConfig {
    let mut config = BurnchainConfig::default();
    config.chain = "stacks_layer_1".to_string();
    config.mode = "hyperchain".to_string();
    config.first_burn_header_hash =
        "0101010101010101010101010101010101010101010101010101010101010101".to_string();
    config.first_burn_header_timestamp = 1u64;
    config
}

/// Make indexer with test settings.
fn make_test_indexer() -> DBBurnchainIndexer {
    DBBurnchainIndexer::new(&random_sortdb_test_dir(), make_test_config(), true)
        .expect("Couldn't create indexer.")
}

/// Tests that we can make a DBBurnchainIndexer and connect.
#[test]
fn test_connect() {
    let mut indexer = make_test_indexer();
    indexer.connect(true).expect("Couldn't connect.");
}

/// Make indexer with test settings and add 10 test new blocks.
fn make_test_indexer_add_10_block_branch() -> DBBurnchainIndexer {
    let mut indexer = make_test_indexer();
    indexer.connect(true).expect("Couldn't connect.");

    let input_channel = indexer.get_channel();

    // Add heights up to 10.
    for block_idx in 1..11 {
        let new_block = make_test_new_block(
            block_idx,
            block_idx as u8,
            (block_idx - 1) as u8,
            make_test_config().contract_identifier.clone(),
        );
        input_channel
            .push_block(new_block)
            .expect("Failed to push block");
    }

    indexer
}
/// Tests that we can open an input channel, input some blocks, and see that reflected
/// in `get_highest_header_height`.
#[test]
fn test_highest_height() {
    let indexer = make_test_indexer_add_10_block_branch();
    let highest_height = indexer
        .get_highest_header_height()
        .expect("Couldn't get height");
    assert_eq!(10, highest_height);
}

#[test]
fn test_read_headers() {
    let indexer = make_test_indexer_add_10_block_branch();
    let headers = indexer.read_headers(1, 11).expect("Couldn't get height");
    for header in &headers {
        info!("{:?}", &header);
    }
    assert_eq!(10, headers.len());
}

/// Create the following fork:
///    / 3
/// 1
///    \ 2 -> 4
///
/// These are added in the order [1, 3, 2, 4]. Becasue of lexicographic tie-breaking based on hash,
/// the first (only) reorg is at 4.
#[test]
fn test_detect_reorg() {
    let mut indexer = make_test_indexer();
    indexer.connect(true).expect("Couldn't connect.");

    let input_channel = indexer.get_channel();

    let contract_identifier = make_test_config().contract_identifier.clone();
    input_channel
        .push_block(make_test_new_block(
            0,
            1u8,
            0u8,
            contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    // Highest height is 0.
    assert_eq!(
        0,
        indexer
            .find_chain_reorg()
            .expect("Call to `find_chain_reorg` failed.")
    );

    input_channel
        .push_block(make_test_new_block(
            1,
            3u8,
            1u8,
            contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    // Only one chain, at height 1.
    assert_eq!(
        1,
        indexer
            .find_chain_reorg()
            .expect("Call to `find_chain_reorg` failed.")
    );

    input_channel
        .push_block(make_test_new_block(
            1,
            2u8,
            1u8,
            contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    // Chain tip hasn't changed based on lexicographic tie-breaking. Same chain tip as before.
    assert_eq!(
        1,
        indexer
            .find_chain_reorg()
            .expect("Call to `find_chain_reorg` failed.")
    );

    input_channel
        .push_block(make_test_new_block(
            2,
            4u8,
            2u8,
            contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    // New chain tip, common ancestor is at height 0.
    assert_eq!(
        0,
        indexer
            .find_chain_reorg()
            .expect("Call to `find_chain_reorg` failed.")
    );
}

/// `sync_headers` shouldn't block, and should always return the max height.
#[test]
fn test_sync_headers() {
    let mut indexer = make_test_indexer_add_10_block_branch();

    /// No matter what the inputs, the answer is `10`, the max height.
    assert_eq!(
        10,
        indexer
            .sync_headers(1, Some(2))
            .expect("Couldn't get height")
    );
    assert_eq!(
        10,
        indexer
            .sync_headers(1, Some(11))
            .expect("Couldn't get height")
    );
    assert_eq!(
        10,
        indexer.sync_headers(1, None).expect("Couldn't get height")
    );
}

/// `drop_headers` is a no-op. Should just always return success.
#[test]
fn test_drop_headers() {
    let mut indexer = make_test_indexer_add_10_block_branch();

    indexer
        .drop_headers(1)
        .expect("`drop_headers` should succed");
    indexer
        .drop_headers(10)
        .expect("`drop_headers` should succed");
    indexer
        .drop_headers(20)
        .expect("`drop_headers` should succed");
}

/// Test that if we set "first header hash" to something higher than the first block,
/// that will be the first block we record.
#[test]
fn test_first_header_hash_requires_waiting() {
    let mut config = make_test_config();

    config.first_burn_header_hash =
        "0303030303030303030303030303030303030303030303030303030303030303".to_string();
    let mut indexer = DBBurnchainIndexer::new(&random_sortdb_test_dir(), config, true)
        .expect("Couldn't create indexer.");

    indexer.connect(true).expect("Couldn't connect.");

    let input_channel = indexer.get_channel();

    // Add heights up to 10.
    for block_idx in 1..11 {
        let new_block = make_test_new_block(
            block_idx,
            block_idx as u8,
            (block_idx - 1) as u8,
            make_test_config().contract_identifier.clone(),
        );
        input_channel
            .push_block(new_block)
            .expect("Failed to push block");
    }

    let headers = indexer.read_headers(1, 11).expect("Couldn't get height");
    for header in &headers {
        info!("{:?}", &header);
    }
}

/// Test the DBBurnchainIndexer in the context of Burnchain::sync_with_indexer.
#[test]
fn test_db_sync_with_indexer() {
    let mut indexer = make_test_indexer();
    let config = make_test_config();
    let burnchain_dir = random_sortdb_test_dir();

    let first_burn_header_hash = BurnchainHeaderHash(
        StacksBlockId::from_hex(&config.first_burn_header_hash)
            .expect("Could not parse `first_burn_header_hash`.")
            .0,
    );

    let mut burnchain =
        burnchain_from_config(&burnchain_dir, &config).expect("Could not create Burnchain.");
    let (sortition_db, burn_db) = burnchain
        .connect_db(
            &indexer,
            true,
            first_burn_header_hash,
            config.first_burn_header_timestamp,
        )
        .expect("Could not connect burnchain.");

    let (_receivers, channels) = CoordinatorCommunication::instantiate();

    let target_block_height_opt = Some(10);

    let input_channel = indexer.get_channel();

    // Add heights up to 10.
    for block_idx in 1..11 {
        let new_block = make_test_new_block(
            block_idx,
            block_idx as u8,
            (block_idx - 1) as u8,
            make_test_config().contract_identifier.clone(),
        );
        input_channel
            .push_block(new_block)
            .expect("Failed to push block");
    }

    let result = burnchain
        .sync_with_indexer(
            &mut indexer,
            channels.clone(),
            target_block_height_opt,
            None,
            None,
        )
        .expect("Call to `sync_with_indexer` should succeed.");

    assert_eq!(10, result.block_height);
    assert_eq!(
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        result.block_hash.to_string()
    );
}

/// Test the DBBurnchainIndexer in the context of Burnchain::sync_with_indexer. Include
/// a fork, and just call sync_with_indexer once at the end.
#[test]
fn test_db_sync_with_indexer_with_fork_call_at_end() {
    let mut indexer = make_test_indexer();
    let config = make_test_config();
    let burnchain_dir = random_sortdb_test_dir();

    let first_burn_header_hash = BurnchainHeaderHash(
        StacksBlockId::from_hex(&config.first_burn_header_hash)
            .expect("Could not parse `first_burn_header_hash`.")
            .0,
    );

    let mut burnchain =
        burnchain_from_config(&burnchain_dir, &config).expect("Could not create Burnchain.");
    let (sortition_db, burn_db) = burnchain
        .connect_db(
            &indexer,
            true,
            first_burn_header_hash,
            config.first_burn_header_timestamp,
        )
        .expect("Could not connect burnchain.");

    let (_receivers, channels) = CoordinatorCommunication::instantiate();

    let target_block_height_opt = Some(10);

    let input_channel = indexer.get_channel();

    input_channel
        .push_block(make_test_new_block(
            1,
            1 as u8,
            0 as u8,
            make_test_config().contract_identifier.clone(),
        ))
        .expect("Failed to push block");

    input_channel
        .push_block(make_test_new_block(
            2,
            3,
            1 as u8,
            make_test_config().contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    input_channel
        .push_block(make_test_new_block(
            2,
            2,
            1 as u8,
            make_test_config().contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    input_channel
        .push_block(make_test_new_block(
            3,
            4,
            2 as u8,
            make_test_config().contract_identifier.clone(),
        ))
        .expect("Failed to push block");

    let result = burnchain
        .sync_with_indexer(
            &mut indexer,
            channels.clone(),
            target_block_height_opt,
            None,
            None,
        )
        .expect("Call to `sync_with_indexer` should succeed.");

    // The block "4" is the highest block. So we tracked the fork.
    assert_eq!(3, result.block_height);
    assert_eq!(
        "0404040404040404040404040404040404040404040404040404040404040404",
        result.block_hash.to_string()
    );
}

/// Test the DBBurnchainIndexer in the context of Burnchain::sync_with_indexer. Include
/// a fork, and call `sync_with_indexer` interspersed with the adding of blocks.
#[test]
fn test_db_sync_with_indexer_with_fork_calls_interspersed() {
    let mut indexer = make_test_indexer();
    let config = make_test_config();
    let burnchain_dir = random_sortdb_test_dir();

    let first_burn_header_hash = BurnchainHeaderHash(
        StacksBlockId::from_hex(&config.first_burn_header_hash)
            .expect("Could not parse `first_burn_header_hash`.")
            .0,
    );

    let mut burnchain =
        burnchain_from_config(&burnchain_dir, &config).expect("Could not create Burnchain.");
    let (sortition_db, burn_db) = burnchain
        .connect_db(
            &indexer,
            true,
            first_burn_header_hash,
            config.first_burn_header_timestamp,
        )
        .expect("Could not connect burnchain.");

    let (_receivers, channels) = CoordinatorCommunication::instantiate();

    let target_block_height_opt = Some(10);

    let input_channel = indexer.get_channel();

    input_channel
        .push_block(make_test_new_block(
            1,
            1 as u8,
            0 as u8,
            make_test_config().contract_identifier.clone(),
        ))
        .expect("Failed to push block");

    let result = burnchain.sync_with_indexer(
        &mut indexer,
        channels.clone(),
        target_block_height_opt,
        None,
        None,
    );

    // TODO: Is this right?
    assert_eq!("Try synchronizing again", result.unwrap_err().to_string());

    input_channel
        .push_block(make_test_new_block(
            2,
            3,
            1 as u8,
            make_test_config().contract_identifier.clone(),
        ))
        .expect("Failed to push block");

    let result = burnchain
        .sync_with_indexer(
            &mut indexer,
            channels.clone(),
            target_block_height_opt,
            None,
            None,
        )
        .expect("Call to `sync_with_indexer` should succeed.");

    // So far chain tip is block 3.
    assert_eq!(2, result.block_height);
    assert_eq!(
        "0303030303030303030303030303030303030303030303030303030303030303",
        result.block_hash.to_string()
    );
    input_channel
        .push_block(make_test_new_block(
            2,
            2,
            1 as u8,
            make_test_config().contract_identifier.clone(),
        ))
        .expect("Failed to push block");

    let result = burnchain
        .sync_with_indexer(
            &mut indexer,
            channels.clone(),
            target_block_height_opt,
            None,
            None,
        )
        .expect("Call to `sync_with_indexer` should succeed.");

    // Chain tip is still node 3, which beats 2 by lexicographic sort.
    assert_eq!(2, result.block_height);
    assert_eq!(
        "0303030303030303030303030303030303030303030303030303030303030303",
        result.block_hash.to_string()
    );
    input_channel
        .push_block(make_test_new_block(
            3,
            4,
            2 as u8,
            make_test_config().contract_identifier.clone(),
        ))
        .expect("Failed to push block");

    let result = burnchain
        .sync_with_indexer(
            &mut indexer,
            channels.clone(),
            target_block_height_opt,
            None,
            None,
        )
        .expect("Call to `sync_with_indexer` should succeed.");

    // Chain tip is 4, which has higher height than 3, and constitutes reorg.
    assert_eq!(3, result.block_height);
    assert_eq!(
        "0404040404040404040404040404040404040404040404040404040404040404",
        result.block_hash.to_string()
    );
}
