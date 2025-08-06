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

//! Unit Tests for [`BitcoinRpcClient`]

use serde_json::json;
use stacks::burnchains::bitcoin::address::BitcoinAddress;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::burnchains::Txid;
use stacks::types::chainstate::BurnchainHeaderHash;
use stacks::types::Address;
use stacks_common::deps_common::bech32;
use stacks_common::deps_common::bitcoin::network::serialize::serialize_hex;

use super::*;

mod utils {

    use super::*;

    pub const BITCOIN_ADDRESS_LEGACY_STR: &str = "mp7gy5VhHzBzk1tJUtP7Qwdrp87XEWnxd4";
    pub const BITCOIN_TXID_HEX: &str =
        "b9a0d01a3e21809e920fa022dfdd85368d56d1cacc5229f7a704c4d5fbccc6bd";
    pub const BITCOIN_BLOCK_HASH: &str =
        "0000000000000000011f5b3c4e7e9f4dc2c88f0b6c3a3b17e5a7d0dfeb3bb3cd";

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
fn test_get_blockchain_info_ok_for_regtest() {
    let expected_block_hash = utils::BITCOIN_BLOCK_HASH;

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
            "bestblockhash": expected_block_hash
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

    assert_eq!(BitcoinNetworkType::Regtest, info.chain);
    assert_eq!(1, info.blocks);
    assert_eq!(2, info.headers);
    assert_eq!(expected_block_hash, info.best_block_hash.to_hex());
}

#[test]
fn test_get_blockchain_info_ok_for_testnet() {
    let expected_block_hash = utils::BITCOIN_BLOCK_HASH;

    let expected_request = json!({
        "jsonrpc": "2.0",
        "id": "stacks",
        "method": "getblockchaininfo",
        "params": []
    });

    let mock_response = json!({
        "id": "stacks",
        "result": {
            "chain": "test",
            "blocks": 1,
            "headers": 2,
            "bestblockhash": expected_block_hash
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

    assert_eq!(BitcoinNetworkType::Testnet, info.chain);
    assert_eq!(1, info.blocks);
    assert_eq!(2, info.headers);
    assert_eq!(expected_block_hash, info.best_block_hash.to_hex());
}

#[test]
fn test_get_blockchain_info_fails_for_unknown_network() {
    let expected_block_hash = utils::BITCOIN_BLOCK_HASH;

    let expected_request = json!({
        "jsonrpc": "2.0",
        "id": "stacks",
        "method": "getblockchaininfo",
        "params": []
    });

    let mock_response = json!({
        "id": "stacks",
        "result": {
            "chain": "unknown",
            "blocks": 1,
            "headers": 2,
            "bestblockhash": expected_block_hash
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
    let error = client
        .get_blockchain_info()
        .expect_err("get info should fail!");

    assert!(matches!(
        error,
        BitcoinRpcClientError::Rpc(RpcError::Decode(_))
    ));
}

#[test]
fn test_get_blockchain_info_ok_for_mainnet_network() {
    let expected_block_hash = utils::BITCOIN_BLOCK_HASH;

    let expected_request = json!({
        "jsonrpc": "2.0",
        "id": "stacks",
        "method": "getblockchaininfo",
        "params": []
    });

    let mock_response = json!({
        "id": "stacks",
        "result": {
            "chain": "main",
            "blocks": 1,
            "headers": 2,
            "bestblockhash": expected_block_hash
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

    assert_eq!(BitcoinNetworkType::Mainnet, info.chain);
    assert_eq!(1, info.blocks);
    assert_eq!(2, info.headers);
    assert_eq!(expected_block_hash, info.best_block_hash.to_hex());
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
    let txid_hex = utils::BITCOIN_TXID_HEX;
    let expected_tx_hex = "0100000001b1f2f67426d26301f0b20467e9fdd93557cb3cbbcb8d79f3a9c7b6c8ec7f69e8000000006a47304402206369d5eb2b7c99f540f4cf3ff2fd6f4b90f89c4328bfa0b6db0c30bb7f2c3d4c022015a1c0e5f6a0b08c271b2d218e6a7a29f5441dbe39d9a5cbcc223221ad5dbb59012103a34e84c8c7ebc8ecb7c2e59ff6672f392c792fc1c4f3c6fa2e7d3d314f1f38c9ffffffff0200e1f505000000001976a9144621d7f4ce0c956c80e6f0c1b9f78fe0c49cb82088ac80fae9c7000000001976a91488ac1f0f01c2a5c2e8f4b4f1a3b1a04d2f35b4c488ac00000000";

    let expected_request = json!({
        "jsonrpc": "2.0",
        "id": "stacks",
        "method": "getrawtransaction",
        "params": [txid_hex]
    });

    let mock_response = json!({
        "id": "stacks",
        "result": expected_tx_hex,
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

    let txid = Txid::from_hex(txid_hex).unwrap();
    let raw_tx = client.get_raw_transaction(&txid).expect("Should be ok!");
    assert_eq!(txid_hex, raw_tx.txid().to_string());
    assert_eq!(expected_tx_hex, serialize_hex(&raw_tx).unwrap());
}

#[test]
fn test_generate_block_ok() {
    let legacy_addr_str = utils::BITCOIN_ADDRESS_LEGACY_STR;
    let txid1 = "txid1";
    let txid2 = "txid2";
    let expected_block_hash = utils::BITCOIN_BLOCK_HASH;

    let expected_request = json!({
        "jsonrpc": "2.0",
        "id": "stacks",
        "method": "generateblock",
        "params": [legacy_addr_str, [txid1, txid2]]
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

    let addr = BitcoinAddress::from_string(legacy_addr_str).expect("valid address!");
    let result = client
        .generate_block(&addr, &[txid1, txid2])
        .expect("Should be ok!");
    assert_eq!(expected_block_hash, result.to_hex());
}

#[test]
fn test_generate_block_fails_for_invalid_block_hash() {
    let legacy_addr_str = utils::BITCOIN_ADDRESS_LEGACY_STR;
    let txid1 = "txid1";
    let txid2 = "txid2";
    let expected_block_hash = "invalid_block_hash";

    let expected_request = json!({
        "jsonrpc": "2.0",
        "id": "stacks",
        "method": "generateblock",
        "params": [legacy_addr_str, [txid1, txid2]]
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

    let addr = BitcoinAddress::from_string(legacy_addr_str).expect("valid address!");
    let error = client
        .generate_block(&addr, &[txid1, txid2])
        .expect_err("Should fail!");
    assert!(matches!(
        error,
        BitcoinRpcClientError::Rpc(RpcError::Decode(_))
    ));
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
    let expected_address = utils::BITCOIN_ADDRESS_LEGACY_STR;

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
    assert_eq!(expected_address, address.to_string());
}

#[test]
fn test_get_new_address_fails_for_invalid_address() {
    let expected_address = "invalid_address";

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

    let error = client
        .get_new_address(None, None)
        .expect_err("Should fail!");
    assert!(matches!(
        error,
        BitcoinRpcClientError::Rpc(RpcError::Decode(_))
    ))
}

#[test]
fn test_send_to_address_ok() {
    let address_str = utils::BITCOIN_ADDRESS_LEGACY_STR;
    let amount = 0.5;
    let expected_txid_str = utils::BITCOIN_TXID_HEX;

    let expected_request = json!({
        "jsonrpc": "2.0",
        "id": "stacks",
        "method": "sendtoaddress",
        "params": [address_str, amount]
    });

    let mock_response = json!({
        "id": "stacks",
        "result": expected_txid_str,
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

    let address = BitcoinAddress::from_string(&address_str).unwrap();
    let txid = client
        .send_to_address(&address, amount)
        .expect("Should be ok!");
    assert_eq!(expected_txid_str, txid.to_hex());
}

#[test]
fn test_send_to_address_fails_for_invalid_tx_id() {
    let address_str = utils::BITCOIN_ADDRESS_LEGACY_STR;
    let amount = 0.5;
    let expected_txid_str = "invalid_tx_id";

    let expected_request = json!({
        "jsonrpc": "2.0",
        "id": "stacks",
        "method": "sendtoaddress",
        "params": [address_str, amount]
    });

    let mock_response = json!({
        "id": "stacks",
        "result": expected_txid_str,
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

    let address = BitcoinAddress::from_string(&address_str).unwrap();
    let error = client
        .send_to_address(&address, amount)
        .expect_err("Should fail!");
    assert!(matches!(
        error,
        BitcoinRpcClientError::Rpc(RpcError::Decode(_))
    ));
}

#[test]
fn test_invalidate_block_ok() {
    let hash = utils::BITCOIN_BLOCK_HASH;

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

    let bhh = BurnchainHeaderHash::from_hex(&hash).unwrap();
    client.invalidate_block(&bhh).expect("Should be ok!");
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

#[test]
fn test_addr() {
    let regtest_hrp = "bcrt1qhzhzvy2v4ykg877s87nwuh37teqzxj95ecutjf";

    let decoded = bech32::decode(regtest_hrp).unwrap();
    println!("WHAT: {decoded:?}");

    let f = bech32::encode("tb", decoded.1, decoded.2).unwrap();
    println!("F===: {f:?}");

    BitcoinAddress::from_string(&f).unwrap();
}
