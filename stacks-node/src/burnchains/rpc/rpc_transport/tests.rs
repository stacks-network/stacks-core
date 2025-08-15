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
fn test_send_fails_due_to_unreachable_endpoint() {
    let unreachable_endpoint = "http://127.0.0.1:65535".to_string();
    let transport = RpcTransport::new(unreachable_endpoint, RpcAuth::None, None)
        .expect("Should be created properly!");

    let result: RpcResult<Value> = transport.send("client_id", "dummy_method", vec![]);
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert!(
        matches!(err, RpcError::NetworkIO(_)),
        "Expected NetworkIO error, got: {err:?}"
    );
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
        Err(RpcError::NetworkIO(e)) => {
            let msg = e.to_string();
            assert!(msg.contains("500"), "Should contain error 500!");
        }
        other => panic!("Expected NetworkIO error, got: {other:?}"),
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
        Err(RpcError::NetworkIO(e)) => {
            let msg = e.to_string();
            assert!(
                msg.contains("invalid message"),
                "Should contain 'invalid message'!"
            )
        }
        other => panic!("Expected NetworkIO error, got: {other:?}"),
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
        "id": "res_client_id_wrong",
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
    let result: RpcResult<Value> = transport.send("req_client_id", "dummy", vec![]);

    match result {
        Err(RpcError::MismatchedId(req_id, res_id)) => {
            assert_eq!("req_client_id", req_id);
            assert_eq!("res_client_id_wrong", res_id);
        }
        other => panic!("Expected MismatchedId, got {other:?}"),
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
        Err(RpcError::Service(err)) => {
            assert_eq!(-32601, err.code);
            assert_eq!("Method not found", err.message);
        }
        other => panic!("Expected Service error, got {other:?}"),
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
        RpcError::NetworkIO(e) => {
            let msg = e.to_string();
            assert!(msg.contains("Timed out"), "Should contain 'Timed out'!");
        }
        other => panic!("Expected NetworkIO error, got: {other:?}"),
    }
}
