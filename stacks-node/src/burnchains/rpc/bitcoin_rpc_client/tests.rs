// Copyright (C) 2025 Stacks Open Internet Foundation
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

mod tests {
    use super::super::*;
    mod unit {

        use serde_json::json;

        use super::*;

        mod utils {

            use super::*;

            pub fn setup_client(server: &mockito::ServerGuard) -> BitcoinRpcClient {
                let url = server.url();
                let parsed = url::Url::parse(&url).unwrap();

                BitcoinRpcClient::new(
                    parsed.host_str().unwrap().to_string(),
                    parsed.port_or_known_default().unwrap(),
                    parsed.scheme() == "https",
                    RpcAuth::None,
                    "mywallet".into(),
                    30,
                    "stacks".to_string(),
                )
                .expect("Rpc Client creation should be ok!")
            }
        }

        #[test]
        fn test_get_blockchain_info_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "getblockchaininfo",
                "params": []
            });

            let mock_response = json!({
                "id": "stacks",
                "result": {
                    "chain": "regtest",
                    "blocks": 1,
                    "headers": 2,
                    "bestblockhash": "00000"
                },
                "error": null
            });

            let mut server: mockito::ServerGuard = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let info = client
                .get_blockchain_info()
                .expect("get info should be ok!");

            assert_eq!("regtest", info.chain);
            assert_eq!(1, info.blocks);
            assert_eq!(2, info.headers);
            assert_eq!("00000", info.best_block_hash);
        }

        #[test]
        fn test_create_wallet_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "createwallet",
                "params": ["testwallet", true]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": {
                    "name": "testwallet",
                    "warning": null
                },
                "error": null
            });

            let mut server: mockito::ServerGuard = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            client
                .create_wallet("testwallet", Some(true))
                .expect("create wallet should be ok!");
        }

        #[test]
        fn test_list_wallets_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "listwallets",
                "params": []
            });

            let mock_response = json!({
                "id": "stacks",
                "result": ["wallet1", "wallet2"],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let result = client.list_wallets().expect("Should list wallets");

            assert_eq!(2, result.len());
            assert_eq!("wallet1", result[0]);
            assert_eq!("wallet2", result[1]);
        }

        #[test]
        fn test_list_unspent_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "listunspent",
                "params": [
                    1,
                    10,
                    ["BTC_ADDRESS_1"],
                    true,
                    {
                        "minimumAmount": "0.00001000",
                        "maximumCount": 5
                    }
                ]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": [{
                    "txid": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                    "vout": 0,
                    "scriptPubKey": "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
                    "amount": 0.00001,
                    "confirmations": 6
                }],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/wallet/mywallet")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let result = client
                .list_unspent(
                    Some(1),
                    Some(10),
                    Some(&["BTC_ADDRESS_1"]),
                    Some(true),
                    Some("0.00001000"), // 1000 sats = 0.00001000 BTC
                    Some(5),
                )
                .expect("Should parse unspent outputs");

            assert_eq!(1, result.len());
            let utxo = &result[0];
            assert_eq!("0.00001", utxo.amount);
            assert_eq!(0, utxo.vout);
            assert_eq!(6, utxo.confirmations);
            assert_eq!(
                "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                utxo.txid,
            );
            assert_eq!(
                "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
                utxo.script_pub_key,
            );
        }

        #[test]
        fn test_generate_to_address_ok() {
            let num_blocks = 3;
            let address = "00000000000000000000000000000000000000000000000000000";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "generatetoaddress",
                "params": [num_blocks, address],
            });

            let mock_response = json!({
                "id": "stacks",
                "result": [
                    "block_hash1",
                    "block_hash2",
                ],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let result = client
                .generate_to_address(num_blocks, address)
                .expect("Should work!");
            assert_eq!(2, result.len());
            assert_eq!("block_hash1", result[0]);
            assert_eq!("block_hash2", result[1]);
        }

        #[test]
        fn test_get_transaction_ok() {
            let txid = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "gettransaction",
                "params": [txid]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": {
                    "confirmations": 6,
                },
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/wallet/mywallet")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let info = client.get_transaction(txid).expect("Should be ok!");
            assert_eq!(6, info.confirmations);
        }

        #[test]
        fn test_get_raw_transaction_ok() {
            let txid = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
            let expected_ser_tx = "000111222333444555666";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "getrawtransaction",
                "params": [txid]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_ser_tx,
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let ser_tx = client.get_raw_transaction(txid).expect("Should be ok!");
            assert_eq!(expected_ser_tx, ser_tx);
        }

        #[test]
        fn test_generate_block_ok() {
            let addr = "myaddr";
            let txid1 = "txid1";
            let txid2 = "txid2";
            let expected_block_hash = "block_hash";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "generateblock",
                "params": [addr, [txid1, txid2]]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": {
                    "hash" : expected_block_hash
                },
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let result = client
                .generate_block(addr, &[txid1, txid2])
                .expect("Should be ok!");
            assert_eq!(expected_block_hash, result);
        }

        #[test]
        fn test_send_raw_transaction_ok_with_defaults() {
            let raw_tx = "raw_tx_hex";
            let expected_txid = "txid1";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "sendrawtransaction",
                "params": [raw_tx, 0.10, 0]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_txid,
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let txid = client
                .send_raw_transaction(raw_tx, None, None)
                .expect("Should work!");
            assert_eq!(txid, expected_txid);
        }

        #[test]
        fn test_send_raw_transaction_ok_with_custom_params() {
            let raw_tx = "raw_tx_hex";
            let expected_txid = "txid1";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "sendrawtransaction",
                "params": [raw_tx, 0.0, 5_000]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_txid,
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let txid = client
                .send_raw_transaction(raw_tx, Some(0.0), Some(5_000))
                .expect("Should work!");
            assert_eq!(txid, expected_txid);
        }

        #[test]
        fn test_get_descriptor_info_ok() {
            let descriptor = format!("addr(bc1_address)");
            let expected_checksum = "mychecksum";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "getdescriptorinfo",
                "params": [descriptor]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": {
                    "checksum": expected_checksum
                },
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let info = client
                .get_descriptor_info(&descriptor)
                .expect("Should work!");
            assert_eq!(expected_checksum, info.checksum);
        }

        #[test]
        fn test_import_descriptors_ok() {
            let descriptor = "addr(1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)#checksum";
            let timestamp = 0;
            let internal = true;

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "importdescriptors",
                "params": [
                    [
                        {
                            "desc": descriptor,
                            "timestamp": 0,
                            "internal": true
                        }
                    ]
                ]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": [{
                    "success": true,
                    "warnings": []
                }],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let desc_req = ImportDescriptorsRequest {
                descriptor: descriptor.to_string(),
                timestamp: Timestamp::Time(timestamp),
                internal: Some(internal),
            };
            let result = client.import_descriptors(&[&desc_req]);
            assert!(result.is_ok());
        }

        #[test]
        fn test_stop_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "stop",
                "params": []
            });

            let mock_response = json!({
                "id": "stacks",
                "result": "Bitcoin Core stopping",
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let result = client.stop().expect("Should work!");
            assert_eq!("Bitcoin Core stopping", result);
        }

        #[test]
        fn test_get_new_address_ok() {
            let expected_address = "btc_addr_1";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "getnewaddress",
                "params": [""]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_address,
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let address = client.get_new_address(None, None).expect("Should be ok!");
            assert_eq!(expected_address, address);
        }

        #[test]
        fn test_send_to_address_ok() {
            let address = "btc_addr_1";
            let amount = 0.5;
            let expected_txid = "txid_1";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "sendtoaddress",
                "params": [address, amount]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_txid,
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/wallet/mywallet")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let txid = client
                .send_to_address(address, amount)
                .expect("Should be ok!");
            assert_eq!(expected_txid, txid);
        }

        #[test]
        fn test_invalidate_block_ok() {
            let hash = "0000";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "invalidateblock",
                "params": [hash]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": null,
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            client.invalidate_block(hash).expect("Should be ok!");
        }

        #[test]
        fn test_get_block_hash_ok() {
            let height = 1;
            let expected_hash = "0000";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "getblockhash",
                "params": [height]
            });

            let mock_response = json!({
                "id": "stacks",
                "result": expected_hash,
                "error": null,
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let hash = client.get_block_hash(height).expect("Should be ok!");
            assert_eq!(expected_hash, hash);
        }
    }

    mod inte {
        use std::env;

        use stacks::core::BITCOIN_REGTEST_FIRST_BLOCK_HASH;

        use super::*;
        use crate::tests::bitcoin_regtest::BitcoinCoreController;

        mod utils {
            use std::net::TcpListener;

            use stacks::config::Config;

            use super::*;
            use crate::util::get_epoch_time_ms;

            pub fn create_stx_config() -> Config {
                let mut config = Config::default();
                config.burnchain.magic_bytes = "T3".as_bytes().into();
                config.burnchain.username = Some(String::from("user"));
                config.burnchain.password = Some(String::from("12345"));
                // overriding default "0.0.0.0" because doesn't play nicely on Windows.
                config.burnchain.peer_host = String::from("127.0.0.1");
                // avoiding peer port biding to reduce the number of ports to bind to.
                config.burnchain.peer_port = 0;

                //Ask the OS for a free port. Not guaranteed to stay free,
                //after TcpListner is dropped, but good enough for testing
                //and starting bitcoind right after config is created
                let tmp_listener =
                    TcpListener::bind("127.0.0.1:0").expect("Failed to bind to get a free port");
                let port = tmp_listener.local_addr().unwrap().port();

                config.burnchain.rpc_port = port;

                let now = get_epoch_time_ms();
                let dir = format!("/tmp/rpc-client-{port}-{now}");
                config.node.working_dir = dir;

                config
            }

            pub fn create_client_no_auth_from_stx_config(config: Config) -> BitcoinRpcClient {
                BitcoinRpcClient::new(
                    config.burnchain.peer_host,
                    config.burnchain.rpc_port,
                    config.burnchain.rpc_ssl,
                    RpcAuth::None,
                    config.burnchain.wallet_name,
                    config.burnchain.timeout,
                    "stacks".to_string(),
                )
                .expect("Rpc client creation should be ok!")
            }
        }

        #[ignore]
        #[test]
        fn test_rpc_call_fails_when_bitcond_with_auth_but_rpc_no_auth() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let config_with_auth = utils::create_stx_config();

            let mut btcd_controller = BitcoinCoreController::new(config_with_auth.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = utils::create_client_no_auth_from_stx_config(config_with_auth);

            let err = client.get_blockchain_info().expect_err("Should fail!");

            match err {
                BitcoinRpcClientError::Rpc(RpcError::Service(ref msg)) => {
                    assert!(msg.contains("401"));
                }
                _ => panic!("Expected RpcError::Service, got: {:?}", err),
            }
        }

        #[ignore]
        #[test]
        fn test_rpc_call_fails_when_bitcond_no_auth_and_rpc_no_auth() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config_no_auth = utils::create_stx_config();
            config_no_auth.burnchain.username = None;
            config_no_auth.burnchain.password = None;

            let mut btcd_controller = BitcoinCoreController::new(config_no_auth.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = utils::create_client_no_auth_from_stx_config(config_no_auth);

            let err = client.get_blockchain_info().expect_err("Should fail!");

            match err {
                BitcoinRpcClientError::Rpc(RpcError::Service(ref msg)) => {
                    assert!(msg.contains("401"));
                }
                _ => panic!("Expected RpcError::Service, got: {:?}", err),
            }
        }

        #[ignore]
        #[test]
        fn test_client_creation_fails_due_to_stx_config_missing_auth() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config_no_auth = utils::create_stx_config();
            config_no_auth.burnchain.username = None;
            config_no_auth.burnchain.password = None;

            let err = BitcoinRpcClient::from_stx_config(&config_no_auth)
                .expect_err("Client should fail!");

            assert_eq!("Missing RPC credentials!", err);
        }

        #[ignore]
        #[test]
        fn test_get_blockchain_info_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let config = utils::create_stx_config();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");

            let info = client.get_blockchain_info().expect("Should be ok!");
            assert_eq!("regtest", info.chain);
            assert_eq!(0, info.blocks);
            assert_eq!(0, info.headers);
            assert_eq!(BITCOIN_REGTEST_FIRST_BLOCK_HASH, info.best_block_hash);
        }

        #[ignore]
        #[test]
        fn test_wallet_listing_and_creation_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let config = utils::create_stx_config();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");

            let wallets = client.list_wallets().unwrap();
            assert_eq!(0, wallets.len());

            client
                .create_wallet("mywallet1", Some(false))
                .expect("mywallet1 creation should be ok!");

            let wallets = client.list_wallets().unwrap();
            assert_eq!(1, wallets.len());
            assert_eq!("mywallet1", wallets[0]);

            client
                .create_wallet("mywallet2", Some(false))
                .expect("mywallet2 creation should be ok!");

            let wallets = client.list_wallets().unwrap();
            assert_eq!(2, wallets.len());
            assert_eq!("mywallet1", wallets[0]);
            assert_eq!("mywallet2", wallets[1]);
        }

        #[ignore]
        #[test]
        fn test_wallet_creation_fails_if_already_exists() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let config = utils::create_stx_config();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");

            client
                .create_wallet("mywallet1", Some(false))
                .expect("mywallet1 creation should be ok!");

            let err = client
                .create_wallet("mywallet1", Some(false))
                .expect_err("mywallet1 creation should fail now!");

            assert!(matches!(
                err,
                BitcoinRpcClientError::Rpc(RpcError::Service(_))
            ));
        }

        #[ignore]
        #[test]
        fn test_generate_to_address_and_list_unspent_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config = utils::create_stx_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");
            client.create_wallet("my_wallet", Some(false)).expect("OK");
            let address = client.get_new_address(None, None).expect("Should work!");

            let utxos = client
                .list_unspent(None, None, None, Some(false), Some("1"), Some(10))
                .expect("list_unspent should be ok!");
            assert_eq!(0, utxos.len());

            let blocks = client.generate_to_address(102, &address).expect("OK");
            assert_eq!(102, blocks.len());

            let utxos = client
                .list_unspent(None, None, None, Some(false), Some("1"), Some(10))
                .expect("list_unspent should be ok!");
            assert_eq!(2, utxos.len());

            let utxos = client
                .list_unspent(None, None, None, Some(false), Some("1"), Some(1))
                .expect("list_unspent should be ok!");
            assert_eq!(1, utxos.len());
        }

        #[ignore]
        #[test]
        fn test_generate_block_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config = utils::create_stx_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");
            client.create_wallet("my_wallet", Some(false)).expect("OK");
            let address = client.get_new_address(None, None).expect("Should work!");

            let block_hash = client.generate_block(&address, &[]).expect("OK");
            assert_eq!(64, block_hash.len());
        }

        #[ignore]
        #[test]
        fn test_get_raw_transaction_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config = utils::create_stx_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .add_arg("-fallbackfee=0.0002")
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");
            client
                .create_wallet("my_wallet", Some(false))
                .expect("create wallet ok!");

            let address = client
                .get_new_address(None, None)
                .expect("get new address ok!");

            //Create 1 UTXO
            _ = client
                .generate_to_address(101, &address)
                .expect("generate to address ok!");

            //Need `fallbackfee` arg
            let txid = client
                .send_to_address(&address, 2.0)
                .expect("send to address ok!");

            let raw_tx = client
                .get_raw_transaction(&txid)
                .expect("get raw transaction ok!");
            assert_ne!("", raw_tx);
        }

        #[ignore]
        #[test]
        fn test_get_transaction_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config = utils::create_stx_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .add_arg("-fallbackfee=0.0002")
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");
            client
                .create_wallet("my_wallet", Some(false))
                .expect("create wallet ok!");
            let address = client
                .get_new_address(None, None)
                .expect("get new address ok!");

            //Create 1 UTXO
            _ = client
                .generate_to_address(101, &address)
                .expect("generate to address ok!");

            //Need `fallbackfee` arg
            let txid = client
                .send_to_address(&address, 2.0)
                .expect("send to address ok!");

            let resp = client.get_transaction(&txid).expect("get transaction ok!");
            assert_eq!(0, resp.confirmations);
        }

        #[ignore]
        #[test]
        fn test_get_descriptor_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config = utils::create_stx_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");
            client
                .create_wallet("my_wallet", None)
                .expect("create wallet ok!");

            let address = "mqqxPdP1dsGk75S7ta2nwyU8ujDnB2Yxvu";
            let checksum = "spfcmvsn";

            let descriptor = format!("addr({address})");
            let info = client
                .get_descriptor_info(&descriptor)
                .expect("get descriptor ok!");
            assert_eq!(checksum, info.checksum);
        }

        #[ignore]
        #[test]
        fn test_import_descriptor_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config = utils::create_stx_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");
            client
                .create_wallet("my_wallet", Some(true))
                .expect("create wallet ok!");

            let address = "mqqxPdP1dsGk75S7ta2nwyU8ujDnB2Yxvu";
            let checksum = "spfcmvsn";

            let desc_req = ImportDescriptorsRequest {
                descriptor: format!("addr({address})#{checksum}"),
                timestamp: Timestamp::Time(0),
                internal: Some(true),
            };

            let response = client
                .import_descriptors(&[&desc_req])
                .expect("import descriptor ok!");
            assert_eq!(1, response.len());
            assert!(response[0].success);
        }

        #[ignore]
        #[test]
        fn test_stop_bitcoind_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let config = utils::create_stx_config();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");
            let msg = client.stop().expect("Should shutdown!");
            assert_eq!("Bitcoin Core stopping", msg);
        }

        #[ignore]
        #[test]
        fn test_invalidate_block_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config = utils::create_stx_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");
            client.create_wallet("my_wallet", Some(false)).expect("OK");
            let address = client.get_new_address(None, None).expect("Should work!");
            let block_hash = client.generate_block(&address, &[]).expect("OK");

            client
                .invalidate_block(&block_hash)
                .expect("Invalidate valid hash should be ok!");
            client
                .invalidate_block("invalid_hash")
                .expect_err("Invalidate invalid hash should fail!");
        }

        #[ignore]
        #[test]
        fn test_get_block_hash_ok() {
            if env::var("BITCOIND_TEST") != Ok("1".into()) {
                return;
            }

            let mut config = utils::create_stx_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config).expect("Client creation ok!");

            let hash = client
                .get_block_hash(0)
                .expect("Should return regtest genesis block hash!");
            assert_eq!(BITCOIN_REGTEST_FIRST_BLOCK_HASH, hash);
        }
    }
}
