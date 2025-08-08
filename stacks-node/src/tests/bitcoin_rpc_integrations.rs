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

//! Integration tests for [`BitcoinRpcClient`]

use std::env;

use stacks::burnchains::bitcoin::address::LegacyBitcoinAddressType;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::core::BITCOIN_REGTEST_FIRST_BLOCK_HASH;
use stacks::types::chainstate::BurnchainHeaderHash;

use crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType;
use crate::burnchains::rpc::bitcoin_rpc_client::{
    BitcoinRpcClient, BitcoinRpcClientError, ImportDescriptorsRequest, Timestamp,
};
use crate::burnchains::rpc::rpc_transport::RpcError;
use crate::tests::bitcoin_regtest::BitcoinCoreController;

mod utils {
    use std::net::TcpListener;

    use stacks::config::Config;

    use crate::burnchains::rpc::bitcoin_rpc_client::BitcoinRpcClient;
    use crate::burnchains::rpc::rpc_transport::RpcAuth;
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

    assert!(
        matches!(err, BitcoinRpcClientError::Rpc(RpcError::Network(_))),
        "Expected RpcError::Network, got: {err:?}"
    );
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

    assert!(
        matches!(err, BitcoinRpcClientError::Rpc(RpcError::Network(_))),
        "Expected RpcError::Network, got: {err:?}"
    );
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

    let err = BitcoinRpcClient::from_stx_config(&config_no_auth).expect_err("Client should fail!");

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
    assert_eq!(BitcoinNetworkType::Regtest, info.chain);
    assert_eq!(0, info.blocks);
    assert_eq!(0, info.headers);
    assert_eq!(
        BITCOIN_REGTEST_FIRST_BLOCK_HASH,
        info.best_block_hash.to_hex()
    );
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

    match &err {
        BitcoinRpcClientError::Rpc(RpcError::Network(msg)) => {
            assert!(msg.contains("500"), "Bitcoind v25 returns HTTP 500)");
        }
        BitcoinRpcClientError::Rpc(RpcError::Service(_)) => {
            assert!(true, "Bitcoind v26+ returns HTTP 200");
        }
        _ => panic!("Expected Network or Service error, got {err:?}"),
    }
}

#[ignore]
#[test]
fn test_get_new_address_for_each_address_type() {
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

    //Check Legacy type OK
    let legacy = client
        .get_new_address(None, Some(AddressType::Legacy))
        .expect("legacy address ok!");
    assert_eq!(
        LegacyBitcoinAddressType::PublicKeyHash,
        legacy.expect_legacy().addrtype
    );

    //Check Legacy p2sh type OK
    let p2sh = client
        .get_new_address(None, Some(AddressType::P2shSegwit))
        .expect("p2sh address ok!");
    assert_eq!(
        LegacyBitcoinAddressType::ScriptHash,
        p2sh.expect_legacy().addrtype
    );

    //Bech32 currently failing due to BitcoinAddress not supporting Regtest HRP
    client
        .get_new_address(None, Some(AddressType::Bech32))
        .expect_err("bech32 should fail!");

    //Bech32m currently failing due to BitcoinAddress not supporting Regtest HRP
    client
        .get_new_address(None, Some(AddressType::Bech32m))
        .expect_err("bech32m should fail!");

    //None defaults to bech32 so fails as well
    client
        .get_new_address(None, None)
        .expect_err("default (bech32) should fail!");
}

#[ignore]
#[test]
fn test_generate_to_address_ok() {
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
    let address = client
        .get_new_address(None, Some(AddressType::Legacy))
        .expect("Should work!");

    let blocks = client
        .generate_to_address(102, &address)
        .expect("Should be ok!");
    assert_eq!(102, blocks.len());
}

#[ignore]
#[test]
fn test_list_unspent_ok() {
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
    let address = client
        .get_new_address(None, Some(AddressType::Legacy))
        .expect("Should work!");

    let utxos = client
        .list_unspent(None, None, None, Some(false), Some(1), Some(10))
        .expect("list_unspent should be ok!");
    assert_eq!(0, utxos.len());

    _ = client
        .generate_to_address(102, &address)
        .expect("generate to address ok!");

    let utxos = client
        .list_unspent(None, None, None, Some(false), Some(1), Some(10))
        .expect("list_unspent should be ok!");
    assert_eq!(2, utxos.len());

    let utxos = client
        .list_unspent(None, None, None, Some(false), Some(1), Some(1))
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
    client
        .create_wallet("my_wallet", Some(false))
        .expect("create wallet ok!");
    let address = client
        .get_new_address(None, Some(AddressType::Legacy))
        .expect("get new address ok!");

    let block_hash = client
        .generate_block(&address, &[])
        .expect("generate block ok!");
    assert_eq!(64, block_hash.to_hex().len());
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
        .get_new_address(None, Some(AddressType::Legacy))
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

    assert_eq!(txid.to_string(), raw_tx.txid().to_string());
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
        .get_new_address(None, Some(AddressType::Legacy))
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
    client
        .create_wallet("my_wallet", Some(false))
        .expect("create wallet ok!");
    let address = client
        .get_new_address(None, Some(AddressType::Legacy))
        .expect("get new address ok!");
    let block_hash = client
        .generate_block(&address, &[])
        .expect("generate block ok!");

    client
        .invalidate_block(&block_hash)
        .expect("Invalidate valid hash should be ok!");

    let nonexistent_hash = BurnchainHeaderHash::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();
    client
        .invalidate_block(&nonexistent_hash)
        .expect_err("Invalidate nonexistent hash should fail!");
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
