use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use reqwest::blocking::Client;

use base64::encode;

const RCP_CLIENT_ID: &str = "stacks";
const RCP_VERSION: &str = "2.0";

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: String,
    method: String,
    params: serde_json::Value,
}

#[derive(Deserialize, Debug)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<Value>,
    //id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum RpcError {
    Network(String),
    Parsing(String),
    Bitcoind(String),
}

pub type RpcResult<T> = Result<T, RpcError>;

/*
impl From<io::Error> for RPCError {
    fn from(ioe: io::Error) -> Self {
        Self::Network(format!("IO Error: {ioe:?}"))
    }
}

impl From<NetError> for RPCError {
    fn from(ne: NetError) -> Self {
        Self::Network(format!("Net Error: {ne:?}"))
    }
}
 */



pub struct BitcoinRpcClient {
    host: String,
    port: u16,
    ssl: bool,
    username: String,
    password: String,
}

impl BitcoinRpcClient {
     pub fn new(
        host: String,
        port: u16,
        ssl: bool,
        username: String,
        password: String,
    ) -> Self {
        /*
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        */
        Self {
            host,
            port,
            ssl,
            username,
            password,
            //client,
        }
    }

    pub fn create_wallet(&self, wallet_name: &str) -> RpcResult<()> {
        let disable_private_keys = true;
        
        self.call::<Value>(
            "createwallet", 
            vec![wallet_name.into(), disable_private_keys.into()],
            None)?;
        Ok(())
    }

    pub fn list_wallets(&self) -> RpcResult<Vec<String>> {
        self.call(
            "listwallets", 
            vec![], 
            None)
    }

    fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<Value>,
        wallet: Option<&str>,
    ) -> RpcResult<T> {
        let request = JsonRpcRequest {
            jsonrpc: RCP_VERSION.to_string(),
            id: RCP_CLIENT_ID.to_string(),
            method: method.to_string(),
            params: Value::Array(params),
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();

        let response = 
            //self.client
            client
            .post(&self.build_url(wallet))
            .header("Authorization", self.auth_header())
            .json(&request)
            .send()
            .map_err(|err| RpcError::Network(err.to_string()))?;

        let parsed: JsonRpcResponse<T> = response.json().map_err(|e| {
            RpcError::Parsing(format!("Failed to parse RPC response: {}", e))
        })?;

        match (parsed.result, parsed.error) {
            (Some(result), None) => Ok(result),
            (_, Some(err)) => Err(RpcError::Bitcoind(format!("{:#}", err))),
            _ => Err(RpcError::Parsing("Missing both result and error".into())),
        }
    }

    fn build_url(&self, wallet_opt: Option<&str>) -> String {
        let protocol = if self.ssl { "https" } else { "http" };
        let mut url = format!("{}://{}:{}", protocol, self.host, self.port);
        if let Some(wallet) = wallet_opt {
            url.push_str(&format!("/wallet/{}", wallet));
        }
        url
    }

    fn auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.username, self.password);
        format!("Basic {}", encode(credentials))
    }
}

#[cfg(test)]
mod unit_tests {

    use serde_json::json;

    use super::*;

    mod utils {
        use super::*;

        pub fn setup_client(server: &mockito::ServerGuard) -> BitcoinRpcClient {
            let url = server.url();
            let parsed = url::Url::parse(&url).unwrap();

            BitcoinRpcClient {
                host: parsed.host_str().unwrap().to_string(),
                port: parsed.port_or_known_default().unwrap(),
                ssl: parsed.scheme() == "https",
                username: "user".into(),
                password: "pass".into(),
            }
        }
    }

    #[test]
    fn test_create_wallet() {
        let expected_request = json!({
            "jsonrpc": "2.0",
            "id": "stacks",
            "method": "createwallet",
            "params": ["testwallet", true]
        });

        let mut server: mockito::ServerGuard = mockito::Server::new();
        let _m = server.mock("POST", "/")
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
    fn test_list_wallets() {
        let expected_request = json!({
            "jsonrpc": "2.0",
            "id": "stacks",
            "method": "listwallets",
            "params": []
        });

        let mut server = mockito::Server::new();
        let _m = server.mock("POST", "/")
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
}