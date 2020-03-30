use testnet;
use rand::RngCore;
use util::hash::{to_hex, hex_bytes};
use testnet::helium::mem_pool::MemPool;
use chainstate::stacks::db::{StacksChainState};
use chainstate::stacks::events::{StacksTransactionEvent};
use super::node::{TESTNET_CHAIN_ID};
use super::config::{InitialBalance};

use chainstate::stacks::{TransactionPayload, CoinbasePayload};
use vm::types::PrincipalData;

pub fn new_test_conf() -> testnet::helium::Config {
    
    // secretKey: "b1cf9cee5083f421c84d7cb53be5edf2801c3c78d63d53917aee0bdc8bd160ee01",
    // publicKey: "03e2ed46873d0db820e8c6001aabc082d72b5b900b53b7a1b9714fe7bde3037b81",
    // stacksAddress: "ST2VHM28V9E5QCRD6C73215KAPSBKQGPWTEE5CMQT"

    let mut conf = testnet::helium::Config::default();
    conf.add_initial_balance("ST2VHM28V9E5QCRD6C73215KAPSBKQGPWTEE5CMQT".to_string(), 10000);
    conf
}

#[test]
fn should_succeed_mining_valid_txs() {
    let conf = new_test_conf();
    
    let num_rounds = 6;
    let mut run_loop = testnet::helium::RunLoop::new(conf);

    // Use tenure's hook for submitting transactions
    run_loop.apply_on_new_tenures(|round, tenure| {
        match round {
            1 => {
                // On round 1, publish the KV contract
                // $ cat /tmp/out.clar 
                // (define-map store ((key (buff 32))) ((value (buff 32))))
                // (define-public (get-value (key (buff 32)))
                //     (begin
                //         (print (concat "Getting key " key))
                //         (match (map-get? store ((key key)))
                //             entry (ok (get value entry))
                //             (err 0))))
                // (define-public (set-value (key (buff 32)) (value (buff 32)))
                //     (begin
                //         (print (concat "Setting key " key))
                //         (map-set store ((key key)) ((value value)))
                //         (ok 'true)))
                // ./blockstack-cli --testnet publish 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 0 store /tmp/out.clar
                let publish_contract = "8000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000000000000000000000100cdb7ba3165e8f05b043592837b3bceb96acb3a8c5d945620964a63d08c9e9f714cd628a91ad950c4a4885c0a63ae722049cf7bb9de110faec8a0b37531aef422030200000000010573746f7265000001c528646566696e652d6d61702073746f72652028286b657920286275666620333229292920282876616c7565202862756666203332292929290a0a28646566696e652d7075626c696320286765742d76616c756520286b65792028627566662033322929290a2020202028626567696e0a2020202020202020287072696e742028636f6e636174202247657474696e67206b65792022206b657929290a2020202020202020286d6174636820286d61702d6765743f2073746f72652028286b6579206b65792929290a202020202020202020202020656e74727920286f6b20286765742076616c756520656e74727929290a202020202020202020202020286572722030292929290a0a28646566696e652d7075626c696320287365742d76616c756520286b65792028627566662033322929202876616c75652028627566662033322929290a2020202028626567696e0a2020202020202020287072696e742028636f6e636174202253657474696e67206b65792022206b657929290a2020202020202020286d61702d7365742073746f72652028286b6579206b6579292920282876616c75652076616c75652929290a2020202020202020286f6b202774727565292929";
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
            5 => {
                // On round 5, publish a stacks transaction
                // ./blockstack-cli --testnet token-transfer b1cf9cee5083f421c84d7cb53be5edf2801c3c78d63d53917aee0bdc8bd160ee01 0 0 ST195Q2HPXY576N4CT2A0R94D7DRYSX54A5X3YZTH 1000
                let transfer_1000_stx = "80000000000400b71a091b4b8b7661a661c620966ab6573bc2dcd300000000000000000000000000000000000052e21c1ae9574987cf1a22e939dba83c6eab4ff4041902f58e7727a8cda53eac6387ef23cf61549b45fe7b5d50cd158265ba586ee35e0cf3234394ea380ffb41030200000000001a525b8a36ef8a73548cd0940c248d3b71ecf4a45100000000000003e800000000000000000000000000000000000000000000000000000000000000000000";
                tenure.mem_pool.submit(hex_bytes(transfer_1000_stx).unwrap().to_vec());
            },
            _ => {}
        };
        return
    });

    // Use block's hook for asserting expectations
    run_loop.apply_on_new_chain_states(|round, _chain_state, block, chain_tip_info, receipts| {
        match round {
            0 => {
                // Inspecting the chain at round 0.
                // - Chain length should be 1.
                assert!(chain_tip_info.block_height == 1);
                
                // Block #1 should only have 0 txs
                assert!(block.txs.len() == 1);

                // 0 event should have been produced
                let events: Vec<StacksTransactionEvent> = receipts.iter().flat_map(|a| a.events.clone()).collect();
                assert!(events.len() == 0);
            },
            1 => {
                // Inspecting the chain at round 1.
                // - Chain length should be 2.
                assert!(chain_tip_info.block_height == 2);
                
                // Block #2 should only have 2 txs
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

                // 0 event should have been produced
                let events: Vec<StacksTransactionEvent> = receipts.iter().flat_map(|a| a.events.clone()).collect();
                assert!(events.len() == 0);
            },
            2 => {
                // Inspecting the chain at round 2.
                // - Chain length should be 3.
                assert!(chain_tip_info.block_height == 3);
                
                // Block #3 should only have 2 txs
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the get-value contract-call
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match contract_tx.payload {
                    TransactionPayload::ContractCall(_) => true,
                    _ => false,
                });

                // 0 event should have been produced
                let events: Vec<StacksTransactionEvent> = receipts.iter().flat_map(|a| a.events.clone()).collect();
                assert!(events.len() == 0);
            },
            3 => {
                // Inspecting the chain at round 3.
                // - Chain length should be 4.
                assert!(chain_tip_info.block_height == 4);
                
                // Block #4 should only have 2 txs
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the set-value contract-call
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match contract_tx.payload {
                    TransactionPayload::ContractCall(_) => true,
                    _ => false,
                });
                
                // 1 event should have been produced
                let events: Vec<StacksTransactionEvent> = receipts.iter().flat_map(|a| a.events.clone()).collect();
                assert!(events.len() == 1);
            },
            4 => {
                // Inspecting the chain at round 4.
                // - Chain length should be 5.
                assert!(chain_tip_info.block_height == 5);
                
                // Block #5 should only have 2 txs
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the get-value contract-call
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match contract_tx.payload {
                    TransactionPayload::ContractCall(_) => true,
                    _ => false,
                });

                // 1 event should have been produced
                let events: Vec<StacksTransactionEvent> = receipts.iter().flat_map(|a| a.events.clone()).collect();
                assert!(events.len() == 1);
            },
            6 => {
                // Inspecting the chain at round 5.
                // - Chain length should be 6.
                assert!(chain_tip_info.block_height == 6);
                
                // Block #6 should only have 2 txs
                assert!(block.txs.len() == 2);

                // Transaction #1 should be the coinbase from the leader
                let coinbase_tx = &block.txs[0];
                assert!(coinbase_tx.chain_id == TESTNET_CHAIN_ID);
                assert!(match coinbase_tx.payload {
                    TransactionPayload::Coinbase(_) => true,
                    _ => false,
                });

                // Transaction #2 should be the STX transfer
                let contract_tx = &block.txs[1];
                assert!(contract_tx.chain_id == TESTNET_CHAIN_ID);

                assert!(match contract_tx.payload {
                    TransactionPayload::TokenTransfer(_,_,_) => true,
                    _ => false,
                });

                // 1 event should have been produced
                let events: Vec<StacksTransactionEvent> = receipts.iter().flat_map(|a| a.events.clone()).collect();
                assert!(events.len() == 1);
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
    let mut run_loop = testnet::helium::RunLoop::new(conf);

    // Use tenure's hook for submitting transactions
    run_loop.apply_on_new_tenures(|round, tenure| {
        match round {
            1 => {
                // On round 1, publish the KV contract
                // $ cat /tmp/out.clar 
                // (define-map store ((key (buff 32))) ((value (buff 32))))
                // (define-public (get-value (key (buff 32)))
                //     (begin
                //         (print (concat "Getting key " key))
                //         (match (map-get? store ((key key)))
                //             entry (ok (get value entry))
                //             (err 0))))
                // (define-public (set-value (key (buff 32)) (value (buff 32)))
                //     (begin
                //         (print (concat "Setting key " key))
                //         (map-set store ((key key)) ((value value)))
                //         (ok 'true)))
                // ./blockstack-cli --testnet publish 043ff5004e3d695060fa48ac94c96049b8c14ef441c50a184a6a3875d2a000f3 0 0 store /tmp/out.clar
                let publish_contract = "8000000000040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000000000000000000000100cdb7ba3165e8f05b043592837b3bceb96acb3a8c5d945620964a63d08c9e9f714cd628a91ad950c4a4885c0a63ae722049cf7bb9de110faec8a0b37531aef422030200000000010573746f7265000001c528646566696e652d6d61702073746f72652028286b657920286275666620333229292920282876616c7565202862756666203332292929290a0a28646566696e652d7075626c696320286765742d76616c756520286b65792028627566662033322929290a2020202028626567696e0a2020202020202020287072696e742028636f6e636174202247657474696e67206b65792022206b657929290a2020202020202020286d6174636820286d61702d6765743f2073746f72652028286b6579206b65792929290a202020202020202020202020656e74727920286f6b20286765742076616c756520656e74727929290a202020202020202020202020286572722030292929290a0a28646566696e652d7075626c696320287365742d76616c756520286b65792028627566662033322929202876616c75652028627566662033322929290a2020202028626567696e0a2020202020202020287072696e742028636f6e636174202253657474696e67206b65792022206b657929290a2020202020202020286d61702d7365742073746f72652028286b6579206b6579292920282876616c75652076616c75652929290a2020202020202020286f6b202774727565292929";
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
                let set_foo_bar = "8000000001040021a3c334fc0ee50359353799e8b2605ac6be1fe4000000000000000100000000000000000101e57846af212a3e9536c86446d3f39210f6edd691f5c6db65feea3e188822dc2c09e8f82b2f7449d54b58e1a6666b003f65c104f3f9b41a34211560b8ce2c1095030200000000021a21a3c334fc0ee50359353799e8b2605ac6be1fe40573746f7265097365742d76616c7565000000020200000003666f6f0200000003626172";
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
    run_loop.apply_on_new_chain_states(|round, chain_state, block, chain_tip_info, _receipts| {
        match round {
            0 => {
                // Inspecting the chain at round 0.
                // - Chain length should be 1.
                assert!(chain_tip_info.block_height == 1);
                
                // Block #1 should only have 1 txs
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
                assert!(chain_tip_info.block_height == 2);
                
                // Block #2 should only have 2 txs
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
                assert!(chain_tip_info.block_height == 3);
                
                // Block #3 should only have 1 tx (the other being invalid)
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
                assert!(chain_tip_info.block_height == 4);
                
                // Block #4 should only have 1 tx (the other being invalid)
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
                assert!(chain_tip_info.block_height == 5);
                
                // Block #5 should only have 2 txs
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
