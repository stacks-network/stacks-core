use serde_json::{json, Value};
use stacks::config::Config;

use crate::burnchains::bitcoin_regtest_controller::{ParsedUTXO, UTXO};
use crate::burnchains::rpc_transport::{RpcResult, RpcTransport};

#[derive(Debug, Clone, Deserialize)]
pub struct GetTransactionResponse {
    pub confirmations: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DescriptorInfoResponse {
    pub checksum: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GenerateBlockResponse {
    hash: String,
}

pub struct BitcoinRpcClient {
    global_ep: RpcTransport,
    wallet_ep: RpcTransport,
}

impl BitcoinRpcClient {
    pub fn from_params(
        host: String,
        port: u16,
        ssl: bool,
        username: String,
        password: String,
        wallet_name: String,
    ) -> Self {
        let protocol = if ssl { "https" } else { "http" };
        let global_path = format!("{protocol}://{host}:{port}");
        let wallet_path = format!("{global_path}/wallet/{wallet_name}");

        Self {
            global_ep: RpcTransport::new(global_path, username.clone(), password.clone()),
            wallet_ep: RpcTransport::new(wallet_path, username, password),
        }
    }

    //TODO: check config and eventually return Result<Self, Err>
    pub fn from_stx_config(config: &Config) -> Self {
        let host = config.burnchain.peer_host.clone();
        let port = config.burnchain.rpc_port;
        let ssl = config.burnchain.rpc_ssl;
        let username = config.burnchain.username.clone().unwrap();
        let password = config.burnchain.password.clone().unwrap();
        let wallet_name = config.burnchain.wallet_name.clone();

        let protocol = if ssl { "https" } else { "http" };
        let global_path = format!("{protocol}://{host}:{port}");
        let wallet_path = format!("{global_path}/wallet/{wallet_name}");

        Self {
            global_ep: RpcTransport::new(global_path, username.clone(), password.clone()),
            wallet_ep: RpcTransport::new(wallet_path, username, password),
        }
    }

    pub fn create_wallet(
        &self,
        wallet_name: &str,
        disable_private_keys: Option<bool>,
    ) -> RpcResult<()> {
        let disable_private_keys = disable_private_keys.unwrap_or(false);

        self.global_ep.send::<Value>(
            "createwallet",
            vec![wallet_name.into(), disable_private_keys.into()],
        )?;
        Ok(())
    }

    pub fn list_wallets(&self) -> RpcResult<Vec<String>> {
        self.global_ep.send("listwallets", vec![])
    }

    //TODO: Add wallet
    pub fn list_unspent(
        &self,
        addresses: Vec<String>,
        include_unsafe: bool,
        minimum_amount: u64,
        maximum_count: u64,
    ) -> RpcResult<Vec<UTXO>> {
        let min_conf = 0i64;
        let max_conf = 9999999i64;
        let minimum_amount = ParsedUTXO::sat_to_serialized_btc(minimum_amount);
        let maximum_count = maximum_count;

        let raw_utxos: Vec<ParsedUTXO> = self.wallet_ep.send(
            "listunspent",
            vec![
                min_conf.into(),
                max_conf.into(),
                addresses.into(),
                include_unsafe.into(),
                json!({
                    "minimumAmount": minimum_amount,
                    "maximumCount": maximum_count
                }),
            ],
        )?;

        let mut result = vec![];
        for raw_utxo in raw_utxos.iter() {
            let txid = match raw_utxo.get_txid() {
                Some(hash) => hash,
                None => continue,
            };

            let script_pub_key = match raw_utxo.get_script_pub_key() {
                Some(script_pub_key) => script_pub_key,
                None => {
                    //TODO: add warn log?
                    continue;
                }
            };

            let amount = match raw_utxo.get_sat_amount() {
                Some(amount) => amount,
                None => continue, //TODO: add warn log?
            };

            result.push(UTXO {
                txid,
                vout: raw_utxo.vout,
                script_pub_key,
                amount,
                confirmations: raw_utxo.confirmations,
            });
        }

        Ok(result)
    }

    pub fn generate_to_address(&self, num_block: u64, address: &str) -> RpcResult<Vec<String>> {
        self.global_ep
            .send("generatetoaddress", vec![num_block.into(), address.into()])
    }

    pub fn get_transaction(&self, txid: &str) -> RpcResult<GetTransactionResponse> {
        self.wallet_ep.send("gettransaction", vec![txid.into()])
    }

    /// Broadcasts a raw transaction to the Bitcoin network.
    ///
    /// This method sends a hex-encoded raw Bitcoin transaction using the
    /// `sendrawtransaction` RPC endpoint. It supports optional limits for the
    /// maximum fee rate and maximum burn amount to prevent accidental overspending.
    ///
    /// # Arguments
    ///
    /// * `tx` - A hex-encoded string representing the raw transaction.
    /// * `max_fee_rate` - Optional maximum fee rate (in BTC/kvB). If `None`, defaults to `0.10` BTC/kvB.
    ///     - Bitcoin Core will reject transactions exceeding this rate unless explicitly overridden.
    ///     - Set to `0.0` to disable fee rate limiting entirely.
    /// * `max_burn_amount` - Optional maximum amount (in satoshis) that can be "burned" in the transaction.
    ///     - Introduced in Bitcoin Core v25 (https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-25.0.md#rpc-and-other-apis)
    ///     - If `None`, defaults to `0`, meaning burning is not allowed.
    ///
    /// # Returns
    ///
    /// * On success, returns the transaction ID (`txid`) as a `String`.
    ///
    /// # Errors
    ///
    /// Returns an `RpcError` if the RPC call fails, the transaction is invalid,
    /// or if fee or burn limits are exceeded.
    pub fn send_raw_transaction(
        &self,
        tx: &str,
        max_fee_rate: Option<f64>,
        max_burn_amount: Option<u64>,
    ) -> RpcResult<String> {
        let max_fee_rate = max_fee_rate.unwrap_or(0.10);
        let max_burn_amount = max_burn_amount.unwrap_or(0);

        self.global_ep.send(
            "sendrawtransaction",
            vec![tx.into(), max_fee_rate.into(), max_burn_amount.into()],
        )
    }

    pub fn get_descriptor_info(&self, descriptor: &str) -> RpcResult<DescriptorInfoResponse> {
        self.global_ep
            .send("getdescriptorinfo", vec![descriptor.into()])
    }

    //TODO: Improve with descriptor_list
    pub fn import_descriptor(&self, descriptor: &str) -> RpcResult<()> {
        //let addr = format!("addr({})", address);
        let timestamp = 0;
        let internal = true;

        self.global_ep.send::<Value>(
            "importdescriptors",
            vec![json!([{ "desc": descriptor, "timestamp": timestamp, "internal": internal }])],
        )?;
        Ok(())
    }

    //TODO REMOVE:
    pub fn get_blockchaininfo(&self) -> RpcResult<()> {
        self.global_ep.send::<Value>("getblockchaininfo", vec![])?;
        Ok(())
    }
}

#[cfg(test)]
impl BitcoinRpcClient {
    pub fn get_raw_transaction(&self, txid: &str) -> RpcResult<String> {
        self.global_ep.send("getrawtransaction", vec![txid.into()])
    }

    pub fn generate_block(&self, address: &str, tx_ids: Vec<String>) -> RpcResult<String> {
        let response = self
            .global_ep
            .send::<GenerateBlockResponse>("generateblock", vec![address.into(), tx_ids.into()])?;
        Ok(response.hash)
    }

    /// Gracefully shuts down the Bitcoin Core node.
    ///
    /// Sends the `"stop"` RPC command using the global endpoint to request that `bitcoind` shuts down
    /// cleanly. This includes flushing the mempool, writing state to disk, and terminating the process.
    ///
    /// # Returns
    /// On success, returns the string:
    /// `"Bitcoin Core stopping"`
    ///
    /// # Errors
    /// Returns an error if the RPC command fails (e.g., connection issue or insufficient permissions).
    pub fn stop(&self) -> RpcResult<String> {
        self.global_ep.send("stop", vec![])
    }

    /// Get a new Bitcoin address from the wallet.
    ///
    /// # Arguments
    ///
    /// * `label` - Optional label to associate with the address.
    /// * `address_type` - Optional address type ("legacy", "p2sh-segwit", "bech32", "bech32m").
    ///
    /// # Returns
    ///
    /// A string representing the new Bitcoin address.
    pub fn get_new_address(
        &self,
        label: Option<&str>,
        address_type: Option<&str>,
    ) -> RpcResult<String> {
        let mut params = vec![];

        let label = label.unwrap_or("");
        params.push(label.into());

        if let Some(at) = address_type {
            params.push(at.into());
        }

        self.global_ep.send("getnewaddress", params)
    }

    /// Sends a specified amount of BTC to a given address.
    ///
    /// # Arguments
    /// * `address` - The destination Bitcoin address.
    /// * `amount` - Amount to send in BTC (not in satoshis).
    ///
    /// # Returns
    /// The transaction ID as hex string
    pub fn send_to_address(&self, address: &str, amount: f64) -> RpcResult<String> {
        self.wallet_ep
            .send("sendtoaddress", vec![address.into(), amount.into()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(test)]
    mod unit {

        use serde_json::json;
        use stacks::util::hash::to_hex;

        use super::*;

        mod utils {
            use super::*;

            pub fn setup_client(server: &mockito::ServerGuard) -> BitcoinRpcClient {
                let url = server.url();
                let parsed = url::Url::parse(&url).unwrap();

                BitcoinRpcClient::from_params(
                    parsed.host_str().unwrap().to_string(),
                    parsed.port_or_known_default().unwrap(),
                    parsed.scheme() == "https",
                    "user".into(),
                    "pass".into(),
                    "mywallet".into(),
                )
            }
        }

        #[test]
        fn test_create_wallet_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "createwallet",
                "params": ["testwallet", true]
            });

            let mut server: mockito::ServerGuard = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(r#"{"result":true,"error":null}"#)
                .create();

            let client = utils::setup_client(&server);
            let result = client.create_wallet("testwallet", Some(true));
            result.expect("Should work");
        }

        #[test]
        fn test_list_wallets_ok() {
            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "listwallets",
                "params": []
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(r#"{"result":["wallet1","wallet2"],"error":null}"#)
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
                    0,
                    9999999,
                    ["BTC_ADDRESS_1"],
                    true,
                    {
                        "minimumAmount": "0.00001000",
                        "maximumCount": 100
                    }
                ]
            });

            let mock_response = json!({
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
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let result = client
                .list_unspent(
                    vec!["BTC_ADDRESS_1".into()],
                    true,
                    1000, // 1000 sats = 0.00001000 BTC
                    100,
                )
                .expect("Should parse unspent outputs");

            assert_eq!(1, result.len());
            let utxo = &result[0];
            assert_eq!(1000, utxo.amount);
            assert_eq!(0, utxo.vout);
            assert_eq!(6, utxo.confirmations);
            assert_eq!(
                "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                utxo.txid.to_string(),
            );
            assert_eq!(
                "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac",
                to_hex(&utxo.script_pub_key.to_bytes()),
            );
        }

        #[test]
        fn test_generate_to_address_ok() {
            // Arrange
            let num_blocks = 3;
            let address = "00000000000000000000000000000000000000000000000000000";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "generatetoaddress",
                "params": [num_blocks, address],
            });

            let mock_response = json!({
                "result": [
                    "block_hash1",
                    "block_hash2",
                ],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
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
                "result": {
                    "confirmations": 6,
                },
                "error": null,
                //"id": "stacks"
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/wallet/mywallet")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
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
                "result": expected_ser_tx,
                "error": null,
                //"id": "stacks"
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
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
                "result": {
                    "hash" : expected_block_hash
                },
                "error": null,
                //"id": "stacks"
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);

            let result = client
                .generate_block(addr, vec![txid1.to_string(), txid2.to_string()])
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
                "result": expected_txid,
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
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
                "result": expected_txid,
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
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
            let address = "bc1_address";
            let descriptor = format!("addr({address})");
            let expected_checksum = "mychecksum";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "getdescriptorinfo",
                "params": [descriptor]
            });

            let mock_response = json!({
                "result": {
                    "checksum": expected_checksum
                },
                "error": null,
                //"id": "stacks"
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
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
        fn test_import_descriptor_ok() {
            let descriptor = "addr(1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)#checksum";

            let expected_request = json!({
                "jsonrpc": "2.0",
                "id": "stacks",
                "method": "importdescriptors",
                "params": [
                    [{
                        "desc": descriptor,
                        "timestamp": 0,
                        "internal": true
                    }]
                ]
            });

            let mock_response = json!({
                "result": [{
                    "success": true,
                    "warnings": []
                }],
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
                .match_body(mockito::Matcher::PartialJson(expected_request))
                .with_status(200)
                .with_header("Content-Type", "application/json")
                .with_body(mock_response.to_string())
                .create();

            let client = utils::setup_client(&server);
            let result = client.import_descriptor(&descriptor);
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
                "result": "Bitcoin Core stopping",
                "error": null
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
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
                "result": expected_address,
                "error": null,
                //"id": "stacks"
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
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
                "result": expected_txid,
                "error": null,
                //"id": "stacks"
            });

            let mut server = mockito::Server::new();
            let _m = server
                .mock("POST", "/wallet/mywallet")
                .match_header("authorization", "Basic dXNlcjpwYXNz")
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
    }

    #[cfg(test)]
    mod inte {
        use super::*;
        use crate::tests::bitcoin_regtest::BitcoinCoreController;

        mod utils {
            use std::net::TcpListener;

            use stacks::config::Config;

            use crate::util::get_epoch_time_ms;

            pub fn create_config() -> Config {
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
        }

        #[test]
        fn test_wallet_listing_and_creation_ok() {
            let config = utils::create_config();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);

            let wallets = client.list_wallets().unwrap();
            assert_eq!(0, wallets.len());

            client.create_wallet("mywallet1", Some(false)).unwrap();

            let wallets = client.list_wallets().unwrap();
            assert_eq!(1, wallets.len());
            assert_eq!("mywallet1", wallets[0]);

            client.create_wallet("mywallet2", Some(false)).unwrap();

            let wallets = client.list_wallets().unwrap();
            assert_eq!(2, wallets.len());
            assert_eq!("mywallet1", wallets[0]);
            assert_eq!("mywallet2", wallets[1]);
        }

        #[test]
        fn test_generate_to_address_and_list_unspent_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            client.create_wallet("my_wallet", Some(false)).expect("OK");
            let address = client.get_new_address(None, None).expect("Should work!");

            let utxos = client
                .list_unspent(vec![], false, 1, 10)
                .expect("list_unspent should be ok!");
            assert_eq!(0, utxos.len());

            let blocks = client.generate_to_address(102, &address).expect("OK");
            assert_eq!(102, blocks.len());

            let utxos = client
                .list_unspent(vec![], false, 1, 10)
                .expect("list_unspent should be ok!");
            assert_eq!(2, utxos.len());

            let utxos = client
                .list_unspent(vec![], false, 1, 1)
                .expect("list_unspent should be ok!");
            assert_eq!(1, utxos.len());

            //client.create_wallet("hello1").expect("OK");
            //client.create_wallet("hello2").expect("OK");
            //client.generate_to_address(64, address)
            //client.get_transaction("1", "hello1").expect("Boh");
            //client.get_blockchaininfo().expect("Boh");
        }

        #[test]
        fn test_generate_block_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            client.create_wallet("my_wallet", Some(false)).expect("OK");
            let address = client.get_new_address(None, None).expect("Should work!");

            let block_hash = client.generate_block(&address, vec![]).expect("OK");
            assert_eq!(64, block_hash.len());
        }

        #[test]
        fn test_get_raw_transaction_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .add_arg("-fallbackfee=0.0002")
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
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

        #[test]
        fn test_get_transaction_ok() {
            let mut config = utils::create_config();
            config.burnchain.wallet_name = "my_wallet".to_string();

            let mut btcd_controller = BitcoinCoreController::from_stx_config(config.clone());
            btcd_controller
                .add_arg("-fallbackfee=0.0002")
                .start_bitcoind_v2()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
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

        #[test]
        fn test_stop_bitcoind_ok() {
            let config = utils::create_config();

            let mut btcd_controller = BitcoinCoreController::new(config.clone());
            btcd_controller
                .start_bitcoind()
                .expect("bitcoind should be started!");

            let client = BitcoinRpcClient::from_stx_config(&config);
            let msg = client.stop().expect("Should shutdown!");
            assert_eq!("Bitcoin Core stopping", msg);
        }
    }
}
