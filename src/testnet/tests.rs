use testnet;
use rand::RngCore;
use util::hash::{to_hex, hex_bytes};
use testnet::mem_pool::MemPool;
use chainstate::stacks::db::{StacksChainState};
use super::node::{TESTNET_CHAIN_ID};
use chainstate::stacks::{TransactionPayload, CoinbasePayload};

pub fn new_test_conf() -> testnet::Config {
    // Testnet's name
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 8];
    rng.fill_bytes(&mut buf);
    let testnet_id = format!("stacks-testnet-{}", to_hex(&buf));
    
    let conf = testnet::Config {
        testnet_name: "testnet".to_string(),
        chain: "bitcoin".to_string(),
        burnchain_path: format!("/tmp/{}/burnchain", testnet_id),
        burnchain_block_time: 500,
        node_config: vec![testnet::NodeConfig {
            name: "L1".to_string(),
            path: format!("/tmp/{}/L1", testnet_id),
            mem_pool_path: format!("/tmp/{}/L1/mempool", testnet_id)
        }],
        sidecar_socket_address: None,
        sidecar_stream_transactions: false,
        sidecar_stream_blocks: false,
    };
    conf
}

#[test]
fn should_succeed_mining_valid_txs() {
    let conf = new_test_conf();
    
    let num_rounds = 4;
    let mut run_loop = testnet::RunLoop::new(conf);

    // Use tenure's hook for submitting transactions
    run_loop.apply_on_new_tenures(|round, tenure| {
        match round {
            1 => {
                // On round 1, publish the KV contract
                // $ cat /tmp/out.clar 
                // (define-map store ((key (buff 32))) ((value (buff 32))))
                // (define-public (get-value (key (buff 32)))
                //    (match (map-get? store ((key key)))
                //        entry (ok (get value entry))
                //        (ok "")))
                //
                // (define-public (set-value (key (buff 32)) (value (buff 32)))
                //    (begin
                //        (map-set store ((key key)) ((value value)))
                //        (ok 'true))
                // ./blockstack-cli --testnet publish 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 0 store /tmp/out.clar
                let publish_contract = "8000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000000000000000000000101d314ff08deb3c5349d97f454be72d026c4bd3b939799301eca062a9f8fd86c294dba97f27863d8bf99113a935e61f6ecb1ddb51cd5816e9887ac709244bc43b0030200000000010573746f72650000016228646566696e652d6d61702073746f72652028286b657920286275666620333229292920282876616c756520286275666620333229292929202020202020202020202020200a28646566696e652d7075626c696320286765742d76616c756520286b65792028627566662033322929290a20202020286d6174636820286d61702d6765743f2073746f72652028286b6579206b65792929290a2020202020202020656e74727920286f6b20286765742076616c756520656e74727929290a2020202020202020286f6b2022222929290a0a28646566696e652d7075626c696320287365742d76616c756520286b65792028627566662033322929202876616c75652028627566662033322929290a2020202028626567696e0a2020202020202020286d61702d7365742073746f72652028286b6579206b6579292920282876616c75652076616c75652929290a2020202020202020286f6b2027747275652929290a";
                tenure.mem_pool.submit(hex_bytes(publish_contract).unwrap().to_vec());
            },
            2 => {
                // On round 2, publish a "get:foo" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 1 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store get-value -e \"foo\"
                let get_foo = "8000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000100000000000000000100e11fa0938e579c868137cfdd95fc0d6107a32c7a8864bbff2852c792c1759a38314e42922702b709c7b17c93d406f9d8057fb7c14736e5d85ff24acf89e921d6030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265096765742d76616c7565000000010200000003666f6f";
                tenure.mem_pool.submit(hex_bytes(get_foo).unwrap().to_vec());
            },
            3 => {
                // On round 3, publish a "set:foo=bar" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 1 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store set-value -e \"foo\" -e \"bar\"
                let set_foo_bar = "8000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe40000000000000002000000000000000001012409d25688e8101db21c1193b068a688d8c78fd120e87521e3e39887bbe7678b52f861ea5b798cc91642ee7e73a2135186d3f211194628d22ad8f433a3e56e31030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265097365742d76616c7565000000020200000003666f6f0200000003626172";
                tenure.mem_pool.submit(hex_bytes(set_foo_bar).unwrap().to_vec());
            },
            4 => {
                // On round 4, publish a "get:foo" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 3 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store get-value -e \"foo\"
                let get_foo = "8000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe40000000000000003000000000000000001014b327858d4a83c6cb4fb44021910c1ece6c1caf9cdefa13368ee004bca4558ff6c362ab66b0c416dbb7d54cb7e879debe1b27962e33569a5d8465345ab0a92c3030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265096765742d76616c7565000000010200000003666f6f";
                tenure.mem_pool.submit(hex_bytes(get_foo).unwrap().to_vec());
            },
            _ => {}
        };
        return
    });

    // Use block's hook for asserting expectations
    run_loop.apply_on_new_chain_states(|round, chain_state, _| {
        match round {
            0 => {
                // Inspecting the chain at round 0.
                // - Chain length should be 1.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 1);
                
                // Block #1 should only have 1 txs
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 1);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });
            },
            1 => {
                // Inspecting the chain at round 1.
                // - Chain length should be 2.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 2);
                
                // Block #2 should only have 2 txs
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the smart contract published
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match contract_tx.payload {
                    TransactionPayload::SmartContract(_) => true,
                    _ => false,
                });
            },
            2 => {
                // Inspecting the chain at round 2.
                // - Chain length should be 3.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 3);
                
                // Block #3 should only have 2 txs
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the smart contract published
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match contract_tx.payload {
                    TransactionPayload::ContractCall(_) => true,
                    _ => false,
                });
            },
            3 => {
                // Inspecting the chain at round 3.
                // - Chain length should be 4.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 4);
                
                // Block #4 should only have 2 txs
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the smart contract published
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match contract_tx.payload {
                    TransactionPayload::ContractCall(_) => true,
                    _ => false,
                });
            },
            4 => {
                // Inspecting the chain at round 4.
                // - Chain length should be 5.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 5);
                
                // Block #5 should only have 2 txs
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the smart contract published
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match contract_tx.payload {
                    TransactionPayload::ContractCall(_) => true,
                    _ => false,
                });
            },
            _ => {}
        }
    });
    run_loop.start(num_rounds);
}

#[test]
fn should_succeed_handling_malformed_and_valid_txs() {
    let conf = new_test_conf();
    
    let num_rounds = 4;
    let mut run_loop = testnet::RunLoop::new(conf);

    // Use tenure's hook for submitting transactions
    run_loop.apply_on_new_tenures(|round, tenure| {
        match round {
            1 => {
                // On round 1, publish the KV contract
                // $ cat /tmp/out.clar 
                // (define-map store ((key (buff 32))) ((value (buff 32))))
                // (define-public (get-value (key (buff 32)))
                //    (match (map-get? store ((key key)))
                //        entry (ok (get value entry))
                //        (ok "")))
                //
                // (define-public (set-value (key (buff 32)) (value (buff 32)))
                //    (begin
                //        (map-set store ((key key)) ((value value)))
                //        (ok 'true))
                // ./blockstack-cli --testnet publish 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 0 store /tmp/out.clar
                let publish_contract = "8000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000000000000000000000101d314ff08deb3c5349d97f454be72d026c4bd3b939799301eca062a9f8fd86c294dba97f27863d8bf99113a935e61f6ecb1ddb51cd5816e9887ac709244bc43b0030200000000010573746f72650000016228646566696e652d6d61702073746f72652028286b657920286275666620333229292920282876616c756520286275666620333229292929202020202020202020202020200a28646566696e652d7075626c696320286765742d76616c756520286b65792028627566662033322929290a20202020286d6174636820286d61702d6765743f2073746f72652028286b6579206b65792929290a2020202020202020656e74727920286f6b20286765742076616c756520656e74727929290a2020202020202020286f6b2022222929290a0a28646566696e652d7075626c696320287365742d76616c756520286b65792028627566662033322929202876616c75652028627566662033322929290a2020202028626567696e0a2020202020202020286d61702d7365742073746f72652028286b6579206b6579292920282876616c75652076616c75652929290a2020202020202020286f6b2027747275652929290a";
                tenure.mem_pool.submit(hex_bytes(publish_contract).unwrap().to_vec());
            },
            2 => {
                // On round 2, publish a "get:foo" transaction (mainnet instead of testnet).
                // Will not be mined
                // ./blockstack-cli contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 1 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store get-value -e \"foo\"
                let get_foo = "0000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000100000000000000000100cbb46766a2bc03261f6bd428fdd6ce63da8ed04713e6476426390ccc15d2b1c133d9ba30a47b51cd467a09a25f3d7fa2bb4b85379f7d0601df02268cb623e231030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265096765742d76616c7565000000010200000003666f6f";
                tenure.mem_pool.submit(hex_bytes(get_foo).unwrap().to_vec());
            },
            3 => {
                // On round 3, publish a "set:foo=bar" transaction (chain-id not matching).
                // Will not be mined
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 1 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store set-value -e \"foo\" -e \"bar\"
                let set_foo_bar = "8000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000100000000000000000101e57846af212a3e9536c86446d3f39210f6edd691f5c6db65feea3e188822dc2c09e8f82b2f7449d54b58e1a6666b003f65c104f3f9b41a34211560b8ce2c1095030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265097365742d76616c7565000000020200000003666f6f0200000003626172";
                tenure.mem_pool.submit(hex_bytes(set_foo_bar).unwrap().to_vec());
            },
            4 => {
                // On round 4, publish a "get:foo" transaction
                // ./blockstack-cli --testnet contract-call 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 1 STGT7GSMZG7EA0TS6MVSKT5JC1DCDFGZWJJZXN8A store get-value -e \"foo\"
                let get_foo = "8000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000100000000000000000100e11fa0938e579c868137cfdd95fc0d6107a32c7a8864bbff2852c792c1759a38314e42922702b709c7b17c93d406f9d8057fb7c14736e5d85ff24acf89e921d6030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265096765742d76616c7565000000010200000003666f6f";
                tenure.mem_pool.submit(hex_bytes(get_foo).unwrap().to_vec());
            },
            _ => {}
        };
        return
    });

    // Use block's hook for asserting expectations
    run_loop.apply_on_new_chain_states(|round, chain_state, _| {
        match round {
            0 => {
                // Inspecting the chain at round 0.
                // - Chain length should be 1.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 1);
                
                // Block #1 should only have 1 txs
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 1);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });
            },
            1 => {
                // Inspecting the chain at round 1.
                // - Chain length should be 2.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 2);
                
                // Block #2 should only have 2 txs
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the smart contract published
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match contract_tx.payload {
                    TransactionPayload::SmartContract(_) => true,
                    _ => false,
                });
            },
            2 => {
                // Inspecting the chain at round 2.
                // - Chain length should be 3.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 3);
                
                // Block #3 should only have 1 tx (the other being invalid)
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 1);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });
            },
            3 => {
                // Inspecting the chain at round 3.
                // - Chain length should be 4.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 4);
                
                // Block #4 should only have 1 tx (the other being invalid)
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 1);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });
            },
            4 => {
                // Inspecting the chain at round 4.
                // - Chain length should be 5.
                let mut blocks = StacksChainState::list_blocks(&chain_state.blocks_db, &chain_state.blocks_path).unwrap();
                blocks.sort();
                assert!(blocks.len() == 5);
                
                // Block #5 should only have 2 txs
                let chain_tip = blocks.last().unwrap();
                let block = StacksChainState::load_block(&chain_state.blocks_path, &chain_tip.0, &chain_tip.1).unwrap().unwrap();
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the contract-call 
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match contract_tx.payload {
                    TransactionPayload::ContractCall(_) => true,
                    _ => false,
                });
            },
            _ => {}
        }
    });
    run_loop.start(num_rounds);
}
