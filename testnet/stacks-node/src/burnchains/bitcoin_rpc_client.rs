use serde_json::{json, Value};

use crate::burnchains::rpc_transport::{RpcResult, RpcTransport};
use crate::burnchains::bitcoin_regtest_controller::{ParsedUTXO, UTXO};

pub struct BitcoinRpcClient {
    transport: RpcTransport,
}

impl BitcoinRpcClient {
    pub fn from_params(
        host: String,
        port: u16,
        ssl: bool,
        username: String,
        password: String,
    ) -> Self {
        Self {
            transport: RpcTransport {
                host,
                port,
                ssl,
                username,
                password,
            },
        }
    }

    pub fn create_wallet(&self, wallet_name: &str) -> RpcResult<()> {
        let disable_private_keys = true;

        self.transport.send::<Value>(
            "createwallet",
            vec![wallet_name.into(), disable_private_keys.into()],
            None,
        )?;
        Ok(())
    }

    pub fn list_wallets(&self) -> RpcResult<Vec<String>> {
        self.transport.send("listwallets", vec![], None)
    }

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

        let raw_utxos: Vec<ParsedUTXO> = self.transport.send(
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
            None,
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
}

#[cfg(test)]
mod unit_tests {

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
        let result = client.create_wallet("testwallet");
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

        let response_body = json!({
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
            .mock("POST", "/")
            .match_header("authorization", "Basic dXNlcjpwYXNz")
            .match_body(mockito::Matcher::PartialJson(expected_request.clone()))
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(response_body.to_string())
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
}
