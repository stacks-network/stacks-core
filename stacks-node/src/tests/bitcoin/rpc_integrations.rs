// Copyright (C) 2025-2026 Stacks Open Internet Foundation
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

//! Integration tests for [`BitcoinRpcClient`].
//!
//! These tests run against a real `bitcoind` node in Docker (via
//! `BitcoinCoreContainer`). Set `BITCOIN_IMAGE_TAG` to run the suite
//! against a specific Bitcoin Core image tag (for example, `25` or `25.2`).
//! If `BITCOIN_IMAGE_TAG` is not set (or is empty),
//! tests fall back to `BITCOIN_IMAGE_TAG_FALLBACK`.
//!
//! CI uses this mechanism to automate checks across
//! the relevant set of Bitcoin Core versions.

use stacks::burnchains::bitcoin::address::LegacyBitcoinAddressType;
use stacks::burnchains::bitcoin::BitcoinNetworkType;
use stacks::core::BITCOIN_REGTEST_FIRST_BLOCK_HASH;
use stacks::types::chainstate::BurnchainHeaderHash;

use crate::burnchains::rpc::bitcoin_rpc_client::test_utils::AddressType;
use crate::burnchains::rpc::bitcoin_rpc_client::{
    BitcoinRpcClientError, ImportDescriptorsRequest, Timestamp,
};
use crate::burnchains::rpc::rpc_transport::RpcError;
use crate::tests::bitcoin::core_container::BitcoinCoreContainer;

mod utils {
    use std::env;

    use crate::burnchains::rpc::bitcoin_rpc_client::BitcoinRpcClient;
    use crate::burnchains::rpc::rpc_transport::RpcAuth;
    use crate::tests::bitcoin::core_container::{
        BitcoinCoreContainer, BITCOIN_RPC_PASSWORD, BITCOIN_RPC_USERNAME,
    };

    const ENV_BITCOIN_IMAGE_TAG: &str = "BITCOIN_IMAGE_TAG";
    const BITCOIN_IMAGE_TAG_FALLBACK: &str = "25";

    pub fn get_bitcoin_image_tag() -> String {
        match env::var(ENV_BITCOIN_IMAGE_TAG) {
            Ok(tag) if !tag.trim().is_empty() => tag,
            _ => BITCOIN_IMAGE_TAG_FALLBACK.to_string(),
        }
    }

    pub fn create_container_no_auth(image_tag: &str) -> BitcoinCoreContainer {
        let mut result = BitcoinCoreContainer::new(image_tag);
        result
            .add_arg("-regtest=1")
            .add_arg("-server=1")
            .add_arg("-rest=1")
            .add_arg("-rpcbind=0.0.0.0")
            .add_arg("-rpcallowip=0.0.0.0/0")
            .add_arg("-rpcallowip=::/0");
        result
    }

    pub fn create_client_from_container(container: &BitcoinCoreContainer) -> BitcoinRpcClient {
        create_client_from_container_and_auth(
            container,
            RpcAuth::Basic {
                username: BITCOIN_RPC_USERNAME.into(),
                password: BITCOIN_RPC_PASSWORD.into(),
            },
        )
    }

    pub fn create_client_no_auth_from_container(
        container: &BitcoinCoreContainer,
    ) -> BitcoinRpcClient {
        create_client_from_container_and_auth(container, RpcAuth::None)
    }

    fn create_client_from_container_and_auth(
        container: &BitcoinCoreContainer,
        auth: RpcAuth,
    ) -> BitcoinRpcClient {
        BitcoinRpcClient::new(
            "127.0.0.1".to_string(),
            container.get_host_rpc_port(),
            auth,
            300,
            "stacks".to_string(),
        )
        .expect("Rpc client creation should be ok!")
    }
}

#[ignore]
#[test]
fn test_rpc_call_fails_when_bitcond_with_auth_but_rpc_no_auth() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_no_auth_from_container(&btc_container);

    let err = client.get_blockchain_info().expect_err("Should fail!");
    assert!(
        matches!(err, BitcoinRpcClientError::Rpc(RpcError::NetworkIO(_))),
        "Expected RpcError::Network, got: {err:?}"
    );
}

#[ignore]
#[test]
fn test_rpc_call_fails_when_bitcond_no_auth_and_rpc_no_auth() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = utils::create_container_no_auth(&image_tag);
    btc_container.start();

    let client = utils::create_client_no_auth_from_container(&btc_container);

    let err = client.get_blockchain_info().expect_err("Should fail!");
    assert!(
        matches!(err, BitcoinRpcClientError::Rpc(RpcError::NetworkIO(_))),
        "Expected RpcError::Network, got: {err:?}"
    );
}

#[ignore]
#[test]
fn test_get_blockchain_info_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

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
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

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
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    client
        .create_wallet("mywallet1", Some(false))
        .expect("mywallet1 creation should be ok!");

    let err = client
        .create_wallet("mywallet1", Some(false))
        .expect_err("mywallet1 creation should fail now!");

    match &err {
        BitcoinRpcClientError::Rpc(RpcError::NetworkIO(_)) => {
            assert!(true, "Bitcoind v25 returns HTTP 500)");
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
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client.create_wallet(&wallet, Some(false)).expect("OK");

    // Check Legacy p2pkh type OK
    let p2pkh = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("p2pkh address ok!");
    assert_eq!(
        LegacyBitcoinAddressType::PublicKeyHash,
        p2pkh.expect_legacy().addrtype
    );

    // Check Legacy p2sh type OK
    let p2sh = client
        .get_new_address(wallet, None, Some(AddressType::P2shSegwit))
        .expect("p2sh address ok!");
    assert_eq!(
        LegacyBitcoinAddressType::ScriptHash,
        p2sh.expect_legacy().addrtype
    );

    // Check Bech32 p2wpkh OK
    let p2wpkh = client
        .get_new_address(wallet, None, Some(AddressType::Bech32))
        .expect("p2wpkh address ok!");
    assert!(p2wpkh.expect_segwit().is_p2wpkh());

    // Check Bech32m p2tr OK
    let p2tr = client
        .get_new_address(wallet, None, Some(AddressType::Bech32m))
        .expect("p2tr address ok!");
    assert!(p2tr.expect_segwit().is_p2tr());

    // Check default to be bech32 p2wpkh
    let default = client
        .get_new_address(wallet, None, None)
        .expect("default address ok!");
    assert!(default.expect_segwit().is_p2wpkh());
}

#[ignore]
#[test]
fn test_generate_to_address_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client.create_wallet(wallet, Some(false)).expect("OK");
    let address = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("Should work!");

    let blocks = client
        .generate_to_address(102, &address)
        .expect("Should be ok!");
    assert_eq!(102, blocks.len());
}

#[ignore]
#[test]
fn test_list_unspent_empty_with_empty_wallet() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client.create_wallet(wallet, Some(false)).expect("OK");

    let utxos = client
        .list_unspent(wallet, None, None, None, None, None, None)
        .expect("all list_unspent should be ok!");
    assert_eq!(0, utxos.len());
}

#[ignore]
#[test]
fn test_list_unspent_with_defaults() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client.create_wallet(wallet, Some(false)).expect("OK");

    let address = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("Should work!");

    _ = client
        .generate_to_address(102, &address)
        .expect("generate to address ok!");

    let utxos = client
        .list_unspent(wallet, None, None, None, None, None, None)
        .expect("all list_unspent should be ok!");
    assert_eq!(2, utxos.len());
}

#[ignore]
#[test]
fn test_list_unspent_one_address_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client.create_wallet(wallet, Some(false)).expect("OK");
    let address = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("Should work!");

    _ = client
        .generate_to_address(102, &address)
        .expect("generate to address ok!");

    let all_utxos = client
        .list_unspent(wallet, None, None, None, Some(false), Some(1), Some(10))
        .expect("all list_unspent should be ok!");
    assert_eq!(2, all_utxos.len());
    assert_eq!(address, all_utxos[0].address);
    assert_eq!(address, all_utxos[1].address);

    let addr_utxos = client
        .list_unspent(
            wallet,
            None,
            None,
            Some(&[&address]),
            Some(false),
            Some(1),
            Some(10),
        )
        .expect("list_unspent per address should be ok!");
    assert_eq!(2, addr_utxos.len());
    assert_eq!(address, addr_utxos[0].address);
    assert_eq!(address, addr_utxos[1].address);

    let max1_utxos = client
        .list_unspent(wallet, None, None, None, Some(false), Some(1), Some(1))
        .expect("list_unspent per address and max count should be ok!");
    assert_eq!(1, max1_utxos.len());
    assert_eq!(address, max1_utxos[0].address);
}

#[ignore]
#[test]
fn test_list_unspent_two_addresses_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client.create_wallet(wallet, Some(false)).expect("OK");

    let address1 = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("address 1 ok!");
    let address2 = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("address 2 ok!");

    _ = client
        .generate_to_address(2, &address1)
        .expect("generate to address 1 ok!");
    _ = client
        .generate_to_address(101, &address2)
        .expect("generate to address 2 ok!");

    let all_utxos = client
        .list_unspent(wallet, None, None, None, Some(false), None, None)
        .expect("all list_unspent should be ok!");
    assert_eq!(3, all_utxos.len());

    let addr1_utxos = client
        .list_unspent(
            wallet,
            None,
            None,
            Some(&[&address1]),
            Some(false),
            None,
            None,
        )
        .expect("list_unspent per address1 should be ok!");
    assert_eq!(2, addr1_utxos.len());
    assert_eq!(address1, addr1_utxos[0].address);
    assert_eq!(address1, addr1_utxos[1].address);

    let addr2_utxos = client
        .list_unspent(
            wallet,
            None,
            None,
            Some(&[&address2]),
            Some(false),
            None,
            None,
        )
        .expect("list_unspent per address2 should be ok!");
    assert_eq!(1, addr2_utxos.len());
    assert_eq!(address2, addr2_utxos[0].address);

    let all2_utxos = client
        .list_unspent(
            wallet,
            None,
            None,
            Some(&[&address1, &address2]),
            Some(false),
            None,
            None,
        )
        .expect("all list_unspent for both addresses should be ok!");
    assert_eq!(3, all2_utxos.len());
}

#[ignore]
#[test]
fn test_generate_block_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client
        .create_wallet(wallet, Some(false))
        .expect("create wallet ok!");
    let address = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("get new address ok!");

    let block_hash = client
        .generate_block(&address, &[])
        .expect("generate block ok!");
    assert_eq!(64, block_hash.to_hex().len());
}

#[ignore]
#[test]
fn test_get_raw_transaction_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client
        .create_wallet(wallet, Some(false))
        .expect("create wallet ok!");

    let address = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("get new address ok!");

    //Create 1 UTXO
    _ = client
        .generate_to_address(101, &address)
        .expect("generate to address ok!");

    //Need `fallbackfee` arg
    let txid = client
        .send_to_address(wallet, &address, 2.0)
        .expect("send to address ok!");

    let raw_tx = client
        .get_raw_transaction(&txid)
        .expect("get raw transaction ok!");

    assert_eq!(txid.to_hex(), raw_tx.txid().to_string());
}

#[ignore]
#[test]
fn test_get_transaction_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client
        .create_wallet(wallet, Some(false))
        .expect("create wallet ok!");
    let address = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("get new address ok!");

    //Create 1 UTXO
    _ = client
        .generate_to_address(101, &address)
        .expect("generate to address ok!");

    //Need `fallbackfee` arg
    let txid = client
        .send_to_address(wallet, &address, 2.0)
        .expect("send to address ok!");

    let resp = client
        .get_transaction(wallet, &txid)
        .expect("get transaction ok!");
    assert_eq!(0, resp.confirmations);
}

#[ignore]
#[test]
fn test_get_descriptor_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client
        .create_wallet(wallet, None)
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
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client
        .create_wallet(wallet, Some(true))
        .expect("create wallet ok!");

    let address = "mqqxPdP1dsGk75S7ta2nwyU8ujDnB2Yxvu";
    let checksum = "spfcmvsn";

    let desc_req = ImportDescriptorsRequest {
        descriptor: format!("addr({address})#{checksum}"),
        timestamp: Timestamp::Time(0),
        internal: Some(true),
    };

    let response = client
        .import_descriptors(wallet, &[&desc_req])
        .expect("import descriptor ok!");
    assert_eq!(1, response.len());
    assert!(response[0].success);
    assert_eq!(0, response[0].warnings.len());
    assert_eq!(None, response[0].error);
}

#[ignore]
#[test]
fn test_import_descriptor_twice_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client
        .create_wallet(wallet, Some(true))
        .expect("create wallet ok!");

    let address = "mqqxPdP1dsGk75S7ta2nwyU8ujDnB2Yxvu";
    let checksum = "spfcmvsn";

    let desc_req = ImportDescriptorsRequest {
        descriptor: format!("addr({address})#{checksum}"),
        timestamp: Timestamp::Time(0),
        internal: Some(true),
    };

    let _ = client
        .import_descriptors(wallet, &[&desc_req])
        .expect("import descriptor ok: first time!");

    let response = client
        .import_descriptors(wallet, &[&desc_req])
        .expect("import descriptor ok: second time!");
    assert_eq!(1, response.len());
    assert!(response[0].success);
    assert_eq!(0, response[0].warnings.len());
    assert_eq!(None, response[0].error);
}

#[ignore]
#[test]
fn test_stop_bitcoind_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);
    let msg = client.stop().expect("Should shutdown!");
    assert_eq!("Bitcoin Core stopping", msg);
}

#[ignore]
#[test]
fn test_invalidate_block_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client
        .create_wallet(wallet, Some(false))
        .expect("create wallet ok!");
    let address = client
        .get_new_address(&wallet, None, Some(AddressType::Legacy))
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
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let bhh = client
        .get_block_hash(0)
        .expect("Should return regtest genesis block hash!");
    assert_eq!(BITCOIN_REGTEST_FIRST_BLOCK_HASH, bhh.to_hex());
}

#[ignore]
#[test]
fn test_send_raw_transaction_rebroadcast_ok() {
    let image_tag = utils::get_bitcoin_image_tag();

    let mut btc_container = BitcoinCoreContainer::new_with_defaults(&image_tag);
    btc_container.start();

    let client = utils::create_client_from_container(&btc_container);

    let wallet = "mywallet";
    client
        .create_wallet(wallet, Some(false))
        .expect("create wallet ok!");

    let address = client
        .get_new_address(wallet, None, Some(AddressType::Legacy))
        .expect("get new address ok!");

    //Create 1 UTXO
    _ = client
        .generate_to_address(101, &address)
        .expect("generate to address ok!");

    //Need `fallbackfee` arg
    let txid = client
        .send_to_address(wallet, &address, 2.0)
        .expect("send to address ok!");

    let raw_tx = client
        .get_raw_transaction(&txid)
        .expect("get raw transaction ok!");

    let txid = client
        .send_raw_transaction(&raw_tx, None, None)
        .expect("send raw transaction (rebroadcast) ok!");

    assert_eq!(txid.to_hex(), raw_tx.txid().to_string());
}
