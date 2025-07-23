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

//! A simple JSON-RPC transport client using `reqwest` for HTTP communication.
//!
//! This module provides a wrapper around basic JSON-RPC interactions with support
//! for configurable authentication and timeouts. It serializes requests and parses
//! responses while exposing error types for network, parsing, and service-level issues.

use std::time::Duration;

use base64::encode;
use reqwest::blocking::Client as ReqwestClient;
use reqwest::header::AUTHORIZATION;
use reqwest::Error as ReqwestError;
use serde::Deserialize;
use serde_json::Value;

/// The JSON-RPC protocol version used in all requests.
/// Latest specification is `2.0`
const RCP_VERSION: &str = "2.0";

/// Represents a JSON-RPC request payload sent to the server.
#[derive(Serialize)]
struct JsonRpcRequest {
    /// JSON-RPC protocol version.
    jsonrpc: String,
    /// Unique identifier for the request.
    id: String,
    /// Name of the RPC method to invoke.
    method: String,
    /// Parameters to be passed to the RPC method.
    params: serde_json::Value,
}

/// Represents a JSON-RPC response payload received from the server.
#[derive(Deserialize, Debug)]
struct JsonRpcResponse<T> {
    /// ID matching the original request.
    id: String,
    /// Result returned from the RPC method, if successful.
    result: Option<T>,
    /// Error object returned by the RPC server, if the call failed.
    error: Option<Value>,
}

/// Represents a JSON-RPC error encountered during a transport operation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum RpcError {
    /// Represents a network-level error, such as connection failures or timeouts.
    Network(String),
    /// Indicates that the response could not be parsed or was malformed.
    Parsing(String),
    /// Represents an error returned by the RPC service itself.
    Service(String),
}

/// Alias for results returned from RPC operations using `RpcTransport`.
pub type RpcResult<T> = Result<T, RpcError>;

/// Represents supported authentication mechanisms for RPC requests.
#[derive(Debug, Clone)]
pub enum RpcAuth {
    /// No authentication is applied.
    None,
    /// HTTP Basic authentication using a username and password.
    Basic { username: String, password: String },
}

/// A transport mechanism for sending JSON-RPC requests over HTTP.
///
/// This struct encapsulates the target URL, optional authentication,
/// and an internal HTTP client.
pub struct RpcTransport {
    /// The base URL of the JSON-RPC endpoint.
    pub url: String,
    /// Optional authentication to apply to outgoing requests.
    pub auth: RpcAuth,
    /// The reqwest http client
    client: ReqwestClient,
}

impl RpcTransport {
    /// Creates a new `RpcTransport` with the given URL, authentication, and optional timeout.
    ///
    /// # Arguments
    ///
    /// * `url` - The JSON-RPC server endpoint.
    /// * `auth` - Authentication configuration (`None` or `Basic`).
    /// * `timeout` - Optional request timeout duration.
    ///
    /// # Errors
    ///
    /// Returns `RpcError::Network` if the HTTP client could not be built.
    pub fn new(url: String, auth: RpcAuth, timeout: Option<Duration>) -> RpcResult<Self> {
        let client = ReqwestClient::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| RpcError::Network(format!("Failed to build HTTP client: {}", e)))?;

        Ok(RpcTransport { url, auth, client })
    }

    /// Sends a JSON-RPC request with the given ID, method name, and parameters.
    ///
    /// # Arguments
    ///
    /// * `id` - A unique identifier for correlating responses.
    /// * `method` - The name of the JSON-RPC method to invoke.
    /// * `params` - A list of parameters to pass to the method.
    ///
    /// # Errors
    ///
    /// Returns:
    /// * `RpcError::Network` on network issues,
    /// * `RpcError::Parsing` for malformed or invalid responses,
    /// * `RpcError::Service` if the RPC server returns an error.
    pub fn send<T: for<'de> Deserialize<'de>>(
        &self,
        id: &str,
        method: &str,
        params: Vec<Value>,
    ) -> RpcResult<T> {
        let request = JsonRpcRequest {
            jsonrpc: RCP_VERSION.to_string(),
            id: id.to_string(),
            method: method.to_string(),
            params: Value::Array(params),
        };

        let mut request_builder = self.client.post(&self.url).json(&request);

        if let Some(auth_header) = self.auth_header() {
            request_builder = request_builder.header(AUTHORIZATION, auth_header);
        }

        let response = request_builder
            .send()
            .map_err(|err| RpcError::Network(err.to_string()))?;

        let parsed: JsonRpcResponse<T> = response.json().map_err(Self::classify_parse_error)?;

        if id != parsed.id {
            return Err(RpcError::Parsing(format!(
                "Invalid response: mismatched 'id': expected '{}', got '{}'",
                id, parsed.id
            )));
        }

        match (parsed.result, parsed.error) {
            (Some(result), None) => Ok(result),
            (_, Some(err)) => Err(RpcError::Service(format!("{:#}", err))),
            _ => Err(RpcError::Parsing(
                "Invalid response: missing both 'result' and 'error'".to_string(),
            )),
        }
    }

    /// Build auth header if needed
    fn auth_header(&self) -> Option<String> {
        match &self.auth {
            RpcAuth::None => None,
            RpcAuth::Basic { username, password } => {
                let credentials = format!("{}:{}", username, password);
                Some(format!("Basic {}", encode(credentials)))
            }
        }
    }

    /// Classify possible error coming from Json parsing
    fn classify_parse_error(e: ReqwestError) -> RpcError {
        if e.is_timeout() {
            RpcError::Network("Request timed out".to_string())
        } else if e.is_decode() {
            RpcError::Parsing(format!("Failed to parse RPC response: {e}"))
        } else {
            RpcError::Network(format!("Network error: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use serde_json::json;

    use super::*;

    mod utils {
        use crate::burnchains::rpc_transport::{RpcAuth, RpcTransport};

        pub fn rpc_no_auth(server: &mockito::ServerGuard) -> RpcTransport {
            RpcTransport::new(server.url(), RpcAuth::None, None)
                .expect("Rpc no auth creation should be ok!")
        }

        pub fn rpc_with_auth(
            server: &mockito::ServerGuard,
            username: String,
            password: String,
        ) -> RpcTransport {
            RpcTransport::new(server.url(), RpcAuth::Basic { username, password }, None)
                .expect("Rpc with auth creation should be ok!")
        }
    }

    #[test]
    fn test_send_with_string_result_ok() {
        let expected_request = json!({
            "jsonrpc": "2.0",
            "id": "client_id",
            "method": "some_method",
            "params": ["param1"]
        });

        let response_body = json!({
            "id": "client_id",
            "result": "some_result",
            "error": null
        });

        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(expected_request))
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(response_body.to_string())
            .create();

        let transport = utils::rpc_no_auth(&server);

        let result: RpcResult<String> =
            transport.send("client_id", "some_method", vec!["param1".into()]);
        assert_eq!(result.unwrap(), "some_result");
    }

    #[test]
    fn test_send_with_string_result_with_basic_auth_ok() {
        let expected_request = json!({
            "jsonrpc": "2.0",
            "id": "client_id",
            "method": "some_method",
            "params": ["param1"]
        });

        let response_body = json!({
            "id": "client_id",
            "result": "some_result",
            "error": null
        });

        let username = "user".to_string();
        let password = "pass".to_string();
        let credentials = base64::encode(format!("{}:{}", username, password));

        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .match_header(
                "authorization",
                mockito::Matcher::Exact(format!("Basic {credentials}")),
            )
            .match_body(mockito::Matcher::PartialJson(expected_request))
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(response_body.to_string())
            .create();

        let transport = utils::rpc_with_auth(&server, username, password);

        let result: RpcResult<String> =
            transport.send("client_id", "some_method", vec!["param1".into()]);
        assert_eq!(result.unwrap(), "some_result");
    }

    #[test]
    fn test_send_fails_with_network_error() {
        let transport =
            RpcTransport::new("http://127.0.0.1:65535".to_string(), RpcAuth::None, None)
                .expect("Should be created properly!");

        let result: RpcResult<Value> = transport.send("client_id", "dummy_method", vec![]);
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

        let transport = utils::rpc_no_auth(&server);
        let result: RpcResult<Value> = transport.send("client_id", "dummy", vec![]);

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

        let transport = utils::rpc_no_auth(&server);
        let result: RpcResult<Value> = transport.send("client_id", "dummy", vec![]);

        assert!(result.is_err());
        match result {
            Err(RpcError::Parsing(msg)) => {
                assert!(msg.starts_with("Failed to parse RPC response:"))
            }
            _ => panic!("Expected parse error"),
        }
    }

    #[test]
    fn test_send_fails_due_to_missing_result_and_error() {
        let response_body = json!({
            "id": "client_id",
            "foo": "bar",
        });

        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(response_body.to_string())
            .create();

        let transport = utils::rpc_no_auth(&server);
        let result: RpcResult<Value> = transport.send("client_id", "dummy", vec![]);

        match result {
            Err(RpcError::Parsing(msg)) => {
                assert_eq!("Invalid response: missing both 'result' and 'error'", msg)
            }
            _ => panic!("Expected missing result/error error"),
        }
    }

    #[test]
    fn test_send_fails_with_invalid_id() {
        let response_body = json!({
            "id": "wrong_client_id",
            "result": true,
        });

        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(response_body.to_string())
            .create();

        let transport = utils::rpc_no_auth(&server);
        let result: RpcResult<Value> = transport.send("client_id", "dummy", vec![]);

        match result {
            Err(RpcError::Parsing(msg)) => assert_eq!(
                "Invalid response: mismatched 'id': expected 'client_id', got 'wrong_client_id'",
                msg
            ),
            _ => panic!("Expected missing result/error error"),
        }
    }

    #[test]
    fn test_send_fails_with_service_error() {
        let response_body = json!({
            "id": "client_id",
            "result": null,
            "error": {
                "code": -32601,
                "message": "Method not found",
            }
        });

        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(response_body.to_string())
            .create();

        let transport = utils::rpc_no_auth(&server);
        let result: RpcResult<Value> = transport.send("client_id", "unknown_method", vec![]);

        match result {
            Err(RpcError::Service(msg)) => assert_eq!(
                "{\n  \"code\": -32601,\n  \"message\": \"Method not found\"\n}",
                msg
            ),
            _ => panic!("Expected service error"),
        }
    }

    #[test]
    fn test_send_fails_due_to_timeout() {
        let expected_request = json!({
            "jsonrpc": "2.0",
            "id": "client_id",
            "method": "delayed_method",
            "params": []
        });

        let response_body = json!({
            "id": "client_id",
            "result": "should_not_get_this",
            "error": null
        });

        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(expected_request))
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_chunked_body(move |writer| {
                // Simulate server delay
                thread::sleep(Duration::from_secs(2));
                writer.write_all(response_body.to_string().as_bytes())
            })
            .create();

        // Timeout shorter than the server's delay
        let timeout = Duration::from_millis(500);
        let transport = RpcTransport::new(server.url(), RpcAuth::None, Some(timeout)).unwrap();

        let result: RpcResult<String> = transport.send("client_id", "delayed_method", vec![]);

        assert!(result.is_err());

        match result.unwrap_err() {
            RpcError::Network(msg) => {
                assert_eq!("Request timed out", msg);
            }
            err => panic!("Expected network error, got: {:?}", err),
        }
    }
}
