use testnet;
use rand::RngCore;
use util::hash::{to_hex, hex_bytes};
use testnet::mem_pool::MemPool;
use chainstate::stacks::db::{StacksChainState};
use super::node::{TESTNET_CHAIN_ID};
use chainstate::stacks::{TransactionPayload, CoinbasePayload};

fn new_test_conf() -> testnet::Config {
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
        }]
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
                let publish_contract = "8000000000040047A043044D57CBA070BF33FE09109D8C2A3268CF00000000000000000000000000000000000023D4FDA2FE32E6F4F4C51AD9D35F74E79874B01948559CA59E0A197440C651224B3375C3DA0DA7860D90D8D7CBA328CDA905102DF36A5ED82CB6743E42DA624A030200000000010573746F72650000015628646566696E652D6D61702073746F72652028286B657920286275666620333229292920282876616C7565202862756666203332292929290A0A28646566696E652D7075626C696320286765742D76616C756520286B65792028627566662033322929290A20202020286D6174636820286D61702D6765743F2073746F72652028286B6579206B65792929290A2020202020202020656E74727920286F6B20286765742076616C756520656E74727929290A2020202020202020286F6B2022222929290A0A28646566696E652D7075626C696320287365742D76616C756520286B65792028627566662033322929202876616C75652028627566662033322929290A2020202028626567696E0A2020202020202020286D61702D7365742073746F72652028286B6579206B6579292920282876616C75652076616C75652929290A2020202020202020286F6B2027747275652929290A";
                tenure.mem_pool.submit(hex_bytes(publish_contract).unwrap().to_vec());
            },
            2 => {
                // On round 2, publish a "get:foo" transaction
                let get_foo = "8000000000040047A043044D57CBA070BF33FE09109D8C2A3268CF0000000000000001000000000000000000003086C902FDDC04AFD579BF8B817D4D1A0617F179C4C457A090A110CB2181A4CE2E58F0F743B384EC8C1AC41D8ABE59AD9F1412984FFD58D0B5D71628BCBDBF31030200000000021A47A043044D57CBA070BF33FE09109D8C2A3268CF0573746F7265096765742D76616C756500000001000000080200000003666F6F";
                tenure.mem_pool.submit(hex_bytes(get_foo).unwrap().to_vec());
            },
            3 => {
                // On round 3, publish a "set:foo=bar" transaction
                let set_foo_bar = "8000000000040047A043044D57CBA070BF33FE09109D8C2A3268CF000000000000000200000000000000000001DB7A4D0616825D95CD28CF348BA3B6EE985FA03C1B0D9D35CABBA535A7A72C77142AA1EA6A58FF3D2440717480682D9B5E420B654E77905012E7A1EF544DEEDE030200000000021A47A043044D57CBA070BF33FE09109D8C2A3268CF0573746F7265097365742D76616C756500000002000000080200000003666F6F000000080200000003626172";
                tenure.mem_pool.submit(hex_bytes(set_foo_bar).unwrap().to_vec());
            },
            4 => {
                // On round 4, publish a "get:foo" transaction
                let get_foo = "8000000000040047A043044D57CBA070BF33FE09109D8C2A3268CF000000000000000300000000000000000001C5A5E218CEC2AC0567FB11CE697CF0E214922AE83B5AF22DE911F3758AD04A887E44A92A67D178F4E93BD6E0B4C2B691A979A48DB46CD4B141D6C6A9A0489679030200000000021A47A043044D57CBA070BF33FE09109D8C2A3268CF0573746F7265096765742D76616C756500000001000000080200000003666F6F";
                tenure.mem_pool.submit(hex_bytes(get_foo).unwrap().to_vec());
            },
            _ => {}
        };
        return
    });

    // Use block's hook for asserting expectations
    run_loop.apply_on_new_chain_states(|round, chain_state| {
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
                let publish_contract = "8000000000040047A043044D57CBA070BF33FE09109D8C2A3268CF00000000000000000000000000000000000023D4FDA2FE32E6F4F4C51AD9D35F74E79874B01948559CA59E0A197440C651224B3375C3DA0DA7860D90D8D7CBA328CDA905102DF36A5ED82CB6743E42DA624A030200000000010573746F72650000015628646566696E652D6D61702073746F72652028286B657920286275666620333229292920282876616C7565202862756666203332292929290A0A28646566696E652D7075626C696320286765742D76616C756520286B65792028627566662033322929290A20202020286D6174636820286D61702D6765743F2073746F72652028286B6579206B65792929290A2020202020202020656E74727920286F6B20286765742076616C756520656E74727929290A2020202020202020286F6B2022222929290A0A28646566696E652D7075626C696320287365742D76616C756520286B65792028627566662033322929202876616C75652028627566662033322929290A2020202028626567696E0A2020202020202020286D61702D7365742073746F72652028286B6579206B6579292920282876616C75652076616C75652929290A2020202020202020286F6B2027747275652929290A";
                tenure.mem_pool.submit(hex_bytes(publish_contract).unwrap().to_vec());
            },
            2 => {
                // On round 2, publish a "get:foo" transaction (mainnet instead of testnet)
                let get_foo = "0000000000040047A043044D57CBA070BF33FE09109D8C2A3268CF0000000000000001000000000000000000003086C902FDDC04AFD579BF8B817D4D1A0617F179C4C457A090A110CB2181A4CE2E58F0F743B384EC8C1AC41D8ABE59AD9F1412984FFD58D0B5D71628BCBDBF31030200000000021A47A043044D57CBA070BF33FE09109D8C2A3268CF0573746F7265096765742D76616C756500000001000000080200000003666F6F";
                tenure.mem_pool.submit(hex_bytes(get_foo).unwrap().to_vec());
            },
            3 => {
                // On round 3, publish a "set:foo=bar" transaction (chain-id not matching)
                let set_foo_bar = "8000010000040047A043044D57CBA070BF33FE09109D8C2A3268CF000000000000000200000000000000000001DB7A4D0616825D95CD28CF348BA3B6EE985FA03C1B0D9D35CABBA535A7A72C77142AA1EA6A58FF3D2440717480682D9B5E420B654E77905012E7A1EF544DEEDE030200000000021A47A043044D57CBA070BF33FE09109D8C2A3268CF0573746F7265097365742D76616C756500000002000000080200000003666F6F000000080200000003626172";
                tenure.mem_pool.submit(hex_bytes(set_foo_bar).unwrap().to_vec());
            },
            4 => {
                // On round 4, publish a "get:foo" transaction
                let get_foo = "8000000000040047A043044D57CBA070BF33FE09109D8C2A3268CF000000000000000300000000000000000001C5A5E218CEC2AC0567FB11CE697CF0E214922AE83B5AF22DE911F3758AD04A887E44A92A67D178F4E93BD6E0B4C2B691A979A48DB46CD4B141D6C6A9A0489679030200000000021A47A043044D57CBA070BF33FE09109D8C2A3268CF0573746F7265096765742D76616C756500000001000000080200000003666F6F";
                tenure.mem_pool.submit(hex_bytes(get_foo).unwrap().to_vec());
            },
            _ => {}
        };
        return
    });

    // Use block's hook for asserting expectations
    run_loop.apply_on_new_chain_states(|round, chain_state| {
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
