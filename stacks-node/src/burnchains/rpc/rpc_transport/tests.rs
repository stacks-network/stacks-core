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

//! Unit Tests for [`RpcTransport`]

use std::thread;

use serde_json::json;

use super::*;

mod utils {
    use super::*;

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
    let transport = RpcTransport::new("http://127.0.0.1:65535".to_string(), RpcAuth::None, None)
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
        Err(RpcError::Network(msg)) => {
            assert!(msg.contains("500"))
        }
        _ => panic!("Expected error 500"),
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
        Err(RpcError::Network(msg)) => {
            assert!(msg.contains("invalid message"))
        }
        _ => panic!("Expected network error"),
    }
}

#[test]
fn test_send_ok_if_missing_both_result_and_error() {
    let response_body = json!({
        "id": "client_id",
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
    assert!(result.is_ok());
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
        Err(RpcError::Decode(msg)) => assert_eq!(
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
            assert!(msg.contains("Timed out"));
        }
        err => panic!("Expected network error, got: {:?}", err),
    }
}
