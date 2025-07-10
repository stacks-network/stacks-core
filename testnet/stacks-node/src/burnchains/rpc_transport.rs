use std::time::Duration;

use base64::encode;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;

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
    //Bitcoind(String),
    Service(String),
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

pub struct RpcTransport {
    pub url: String,
    pub username: String,
    pub password: String,
}

impl RpcTransport {
    pub fn new(url: String, username: String, password: String) -> Self {
        RpcTransport {
            url,
            username,
            password,
        }
    }

    pub fn send<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<Value>,
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

        //self.client
        let response = client
            .post(&self.url)
            .header("Authorization", self.auth_header())
            .json(&request)
            .send()
            .map_err(|err| RpcError::Network(err.to_string()))?;

        let parsed: JsonRpcResponse<T> = response
            .json()
            .map_err(|e| RpcError::Parsing(format!("Failed to parse RPC response: {}", e)))?;

        match (parsed.result, parsed.error) {
            (Some(result), None) => Ok(result),
            (_, Some(err)) => Err(RpcError::Service(format!("{:#}", err))),
            _ => Err(RpcError::Parsing("Missing both result and error".into())),
        }
    }

    fn auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.username, self.password);
        format!("Basic {}", encode(credentials))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    mod utils {
        use super::*;

        pub fn setup_transport(server: &mockito::ServerGuard) -> RpcTransport {
            RpcTransport {
                url: server.url(),
                username: "user".into(),
                password: "pass".into(),
            }
        }
    }

    #[test]
    fn test_send_with_string_result_ok() {
        let expected_request = json!({
            "jsonrpc": "2.0",
            "id": "stacks",
            "method": "some_method",
            "params": ["param1"]
        });

        let response_body = json!({
            "result": "some_result",
            "error": null
        });

        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .match_header("authorization", "Basic dXNlcjpwYXNz")
            .match_body(mockito::Matcher::PartialJson(expected_request))
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(response_body.to_string())
            .create();

        let transport = utils::setup_transport(&server);

        let result: RpcResult<String> = transport.send("some_method", vec!["param1".into()]);
        assert_eq!(result.unwrap(), "some_result");
    }

    #[test]
    fn test_send_fails_with_network_error() {
        let transport = RpcTransport::new(
            "http://127.0.0.1:65535".to_string(),
            "user".to_string(),
            "pass".to_string(),
        );

        let result: RpcResult<Value> = transport.send("dummy_method", vec![]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RpcError::Network(_)));
    }

    #[test]
    fn test_send_fails_with_http_500() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .with_status(500)
            .with_body("Internal Server Error")
            .create();

        let transport = utils::setup_transport(&server);
        let result: RpcResult<Value> = transport.send("dummy", vec![]);

        assert!(result.is_err());
        match result {
            Err(RpcError::Parsing(msg)) => {
                assert!(msg.starts_with("Failed to parse RPC response:"))
            }
            _ => panic!("Expected parse error"),
        }
    }

    #[test]
    fn test_send_fails_with_invalid_json() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body("not a valid json")
            .create();

        let transport = utils::setup_transport(&server);
        let result: RpcResult<Value> = transport.send("dummy", vec![]);

        assert!(result.is_err());
        match result {
            Err(RpcError::Parsing(msg)) => {
                assert!(msg.starts_with("Failed to parse RPC response:"))
            }
            _ => panic!("Expected parse error"),
        }
    }

    #[test]
    fn test_send_missing_result_and_error() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(r#"{"foo": "bar"}"#)
            .create();

        let transport = utils::setup_transport(&server);
        let result: RpcResult<Value> = transport.send("dummy", vec![]);

        match result {
            Err(RpcError::Parsing(msg)) => assert_eq!("Missing both result and error", msg),
            _ => panic!("Expected missing result/error error"),
        }
    }

    #[test]
    fn test_send_fails_with_service_error() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(
                r#"{
                "result": null,
                "error": {
                    "code": -32601,
                    "message": "Method not found"
                }
            }"#,
            )
            .create();

        let transport = utils::setup_transport(&server);
        let result: RpcResult<Value> = transport.send("unknown_method", vec![]);

        match result {
            Err(RpcError::Service(msg)) => assert_eq!(
                "{\n  \"code\": -32601,\n  \"message\": \"Method not found\"\n}",
                msg
            ),
            _ => panic!("Expected service error"),
        }
    }
}
