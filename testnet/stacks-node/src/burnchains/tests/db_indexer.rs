use crate::burnchains::burnchain_from_config;
use crate::burnchains::db_indexer::DBBurnchainIndexer;
use crate::burnchains::tests::{make_test_new_block, random_sortdb_test_dir};
use crate::config::BurnchainConfig;
use stacks::burnchains::indexer::BurnchainIndexer;
use stacks::chainstate::coordinator::CoordinatorCommunication;

/// Create config settings for the tests.
fn make_test_config() -> BurnchainConfig {
    let mut config = BurnchainConfig::default();
    config.chain = "stacks_layer_1".to_string();
    config.first_burn_header_height = 1;
    config
}

/// Make indexer with test settings.
fn make_test_indexer() -> DBBurnchainIndexer {
    let mut indexer = DBBurnchainIndexer::new(&random_sortdb_test_dir(), make_test_config(), true)
        .expect("Couldn't create indexer.");
    indexer
        .connect(true)
        .expect("Could not connect test indexer.");
    indexer
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
            1,
            1u8,
            0u8,
            contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    assert_eq!(
        1,
        indexer
            .find_chain_reorg()
            .expect("Call to `find_chain_reorg` failed.")
    );

    input_channel
        .push_block(make_test_new_block(
            2,
            3u8,
            1u8,
            contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    assert_eq!(
        2,
        indexer
            .find_chain_reorg()
            .expect("Call to `find_chain_reorg` failed.")
    );

    input_channel
        .push_block(make_test_new_block(
            2,
            2u8,
            1u8,
            contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    // Chain tip changes based on lexicographic tie-breaking.
    assert_eq!(
        1,
        indexer
            .find_chain_reorg()
            .expect("Call to `find_chain_reorg` failed.")
    );

    input_channel
        .push_block(make_test_new_block(
            3,
            4u8,
            2u8,
            contract_identifier.clone(),
        ))
        .expect("Failed to push block");
    // Not a reorg because 2 was previous tip.
    assert_eq!(
        3,
        indexer
            .find_chain_reorg()
            .expect("Call to `find_chain_reorg` failed.")
    );
}

/// `sync_headers` shouldn't block, and should always return the max height.
#[test]
fn test_sync_headers() {
    let mut indexer = make_test_indexer_add_10_block_branch();

    // No matter what the inputs, the answer is `10`, the max height.
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
    let config = make_test_config();

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

    let mut burnchain =
        burnchain_from_config(&burnchain_dir, &config).expect("Could not create Burnchain.");
    let _ = burnchain
        .connect_db(&indexer, true)
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

/// Test the DBBurnchainIndexer in the context of Burnchain::sync_with_indexer. Create a short
/// sequence.
#[test]
fn test_db_sync_with_indexer_short_sequence() {
    let mut indexer = make_test_indexer();
    let mut config = make_test_config();
    config.first_burn_header_height = 0;
    let burnchain_dir = random_sortdb_test_dir();

    let mut burnchain =
        burnchain_from_config(&burnchain_dir, &config).expect("Could not create Burnchain.");
    let (_sortition_db, burn_db) = burnchain
        .connect_db(&indexer, true)
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

    let result = burnchain
        .sync_with_indexer(
            &mut indexer,
            channels.clone(),
            target_block_height_opt,
            None,
            None,
        )
        .expect("Call to `sync_with_indexer` should succeed.");

    assert_eq!(1, result.block_height);
    assert_eq!(
        "0101010101010101010101010101010101010101010101010101010101010101",
        result.block_hash.to_string()
    );
    let canonical_tip = burn_db
        .get_canonical_chain_tip()
        .expect("Should have a chain tip.");
    assert_eq!(1, canonical_tip.block_height);
    assert_eq!(
        "0101010101010101010101010101010101010101010101010101010101010101",
        canonical_tip.block_hash.to_string()
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

    assert_eq!(2, result.block_height);
    assert_eq!(
        "0202020202020202020202020202020202020202020202020202020202020202",
        result.block_hash.to_string()
    );
    let canonical_tip = burn_db
        .get_canonical_chain_tip()
        .expect("Should have a chain tip.");
    assert_eq!(2, canonical_tip.block_height);
    assert_eq!(
        "0202020202020202020202020202020202020202020202020202020202020202",
        canonical_tip.block_hash.to_string()
    );
}

/// Test the DBBurnchainIndexer in the context of Burnchain::sync_with_indexer. Include
/// a fork, and sync_with_indexer after every push.
#[test]
fn test_db_sync_with_indexer_long_fork_repeated_calls() {
    let mut indexer = make_test_indexer();
    let mut config = make_test_config();
    config.first_burn_header_height = 0;
    let burnchain_dir = random_sortdb_test_dir();

    let mut burnchain =
        burnchain_from_config(&burnchain_dir, &config).expect("Could not create Burnchain.");
    let (_sortition_db, burn_db) = burnchain
        .connect_db(&indexer, true)
        .expect("Could not connect burnchain.");

    let (_receivers, channels) = CoordinatorCommunication::instantiate();

    let target_block_height_opt = Some(10);

    let input_channel = indexer.get_channel();

    // Convenience method to push a block. Test the running chain tip against `expected_tip_height` and `expected_hash`.
    let mut push_height_block_parent =
        |block_height: u64,
         block_idx: u8,
         parent_block_idx: u8,
         expected_tip_height: u64,
         expected_tip_hash: &str| {
            input_channel
                .push_block(make_test_new_block(
                    block_height,
                    block_idx,
                    parent_block_idx,
                    make_test_config().contract_identifier.clone(),
                ))
                .expect("Failed to push block");

            let sync_result = burnchain
                .sync_with_indexer(
                    &mut indexer,
                    channels.clone(),
                    target_block_height_opt,
                    None,
                    None,
                )
                .expect("We expect call calls to succeed.");
            assert_eq!(expected_tip_height, sync_result.block_height);
            assert_eq!(expected_tip_hash, sync_result.block_hash.to_string());

            let canonical_tip = burn_db
                .get_canonical_chain_tip()
                .expect("Should have a chain tip.");
            assert_eq!(expected_tip_height, canonical_tip.block_height);
            assert_eq!(expected_tip_hash, canonical_tip.block_hash.to_string());
        };

    // Fork is:
    // 1 -> 2 -> 3 -> 4 -> 9 -> 10
    //   \-> 6 -> 7 -> 8 -> 5
    //
    // Order added is:
    // 1, 2, 3, 6, 4, 7, 5, 8, 9, 10
    push_height_block_parent(1, 1, 0, 1, &"01".repeat(32));
    push_height_block_parent(2, 2, 1, 2, &"02".repeat(32));
    push_height_block_parent(3, 3, 2, 3, &"03".repeat(32));
    push_height_block_parent(2, 6, 1, 3, &"03".repeat(32));
    push_height_block_parent(4, 4, 3, 4, &"04".repeat(32));
    push_height_block_parent(3, 7, 6, 4, &"04".repeat(32));
    push_height_block_parent(5, 9, 4, 5, &"09".repeat(32));
    push_height_block_parent(4, 8, 7, 5, &"09".repeat(32));
    push_height_block_parent(5, 5, 8, 5, &"05".repeat(32));
    push_height_block_parent(6, 10, 9, 6, &"0a".repeat(32));
}

/// Test the DBBurnchainIndexer in the context of Burnchain::sync_with_indexer. Include
/// a fork, and just call sync_with_indexer once at the end.
#[test]
fn test_db_sync_with_indexer_long_fork_call_at_end() {
    let mut indexer = make_test_indexer();
    let config = make_test_config();
    let burnchain_dir = random_sortdb_test_dir();

    let mut burnchain =
        burnchain_from_config(&burnchain_dir, &config).expect("Could not create Burnchain.");
    let (_sortition_db, burn_db) = burnchain
        .connect_db(&indexer, true)
        .expect("Could not connect burnchain.");

    let (_receivers, channels) = CoordinatorCommunication::instantiate();

    let target_block_height_opt = Some(10);

    let input_channel = indexer.get_channel();

    // Convenience method to push a block. Test the running chain tip against `expected_tip_height`.
    let push_height_block_parent = |block_height: u64, block_idx: u8, parent_block_idx: u8| {
        input_channel
            .push_block(make_test_new_block(
                block_height,
                block_idx,
                parent_block_idx,
                make_test_config().contract_identifier.clone(),
            ))
            .expect("Failed to push block");
    };

    // Fork is:
    // 1 -> 2 -> 3 -> 4 -> 5 -> 10
    //   \-> 6 -> 7 -> 8 -> 9
    //
    // Order added is:
    // 1, 2, 3, 6, 4, 7, 5, 8, 9, 10
    push_height_block_parent(1, 1, 0);
    push_height_block_parent(2, 2, 1);
    push_height_block_parent(3, 3, 2);
    push_height_block_parent(2, 6, 1);
    push_height_block_parent(4, 4, 3);
    push_height_block_parent(3, 7, 6);
    push_height_block_parent(5, 5, 4);
    push_height_block_parent(4, 8, 7);
    push_height_block_parent(5, 9, 8);
    push_height_block_parent(6, 10, 5);

    let sync_result = burnchain
        .sync_with_indexer(
            &mut indexer,
            channels.clone(),
            target_block_height_opt,
            None,
            None,
        )
        .expect("We expect call calls to succeed.");
    assert_eq!(6, sync_result.block_height);
    assert_eq!(
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        sync_result.block_hash.to_string()
    );
    let canonical_tip = burn_db
        .get_canonical_chain_tip()
        .expect("Should have a chain tip.");
    assert_eq!(6, canonical_tip.block_height);
    assert_eq!(
        "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
        canonical_tip.block_hash.to_string()
    );
}
