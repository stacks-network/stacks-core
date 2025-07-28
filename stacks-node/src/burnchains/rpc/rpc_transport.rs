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

//! A simple JSON-RPC transport client using [`StacksHttpRequest`] for HTTP communication.
//!
//! This module provides a wrapper around basic JSON-RPC interactions with support
//! for configurable authentication and timeouts. It serializes requests and parses
//! responses while exposing error types for network, parsing, and service-level issues.

use std::io;
use std::time::Duration;

use base64::encode;
use serde::Deserialize;
use serde_json::Value;
use stacks::net::http::{HttpRequestContents, HttpResponsePayload};
use stacks::net::httpcore::{send_http_request, StacksHttpRequest};
use stacks::types::net::PeerHost;
use url::Url;

#[cfg(test)]
mod tests;

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
    /// Indicates that the request could not be encoded properly
    Encode(String),
    /// Indicates that the response could not be decoded properly.
    Decode(String),
    /// Represents an error returned by the RPC service itself.
    Service(String),
}

/// Alias for results returned from RPC operations using `RpcTransport`.
pub type RpcResult<T> = Result<T, RpcError>;

impl From<url::ParseError> for RpcError {
    fn from(e: url::ParseError) -> Self {
        Self::Network(format!("Url Error: {e:?}"))
    }
}

impl From<stacks_common::types::net::Error> for RpcError {
    fn from(e: stacks_common::types::net::Error) -> Self {
        Self::Network(format!("Net Error: {e:?}"))
    }
}

impl From<io::Error> for RpcError {
    fn from(e: io::Error) -> Self {
        Self::Network(format!("IO Error: {e:?}"))
    }
}

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
#[derive(Debug)]
pub struct RpcTransport {
    /// Host and port of the target JSON-RPC server.
    peer: PeerHost,
    /// Request path component of the URL (e.g., `/` or `/api`).
    path: String,
    /// Authentication to apply to outgoing requests.
    auth: RpcAuth,
    /// The maximum duration to wait for an HTTP request to complete.
    timeout: Duration,
}

impl RpcTransport {
    /// Creates a new `RpcTransport` with the given URL, authentication, and optional timeout.
    ///
    /// # Arguments
    ///
    /// * `url` - The JSON-RPC server endpoint.
    /// * `auth` - Authentication configuration (`None` or `Basic`).
    /// * `timeout` -  Optional timeout duration for HTTP requests. If `None`, defaults to 30 seconds.
    ///
    /// # Returns
    ///
    /// An instance of [`RpcTransport`] on success, or a [`RpcError`] otherwise.
    pub fn new(url: String, auth: RpcAuth, timeout: Option<Duration>) -> RpcResult<Self> {
        let url_obj = Url::parse(&url)?;
        let host = url_obj
            .host_str()
            .ok_or(RpcError::Network(format!("Missing host in url: {url}")))?;
        let port = url_obj
            .port_or_known_default()
            .ok_or(RpcError::Network(format!("Missing port in url: {url}")))?;

        let peer: PeerHost = format!("{host}:{port}").parse()?;
        let path = url_obj.path().to_string();
        let timeout = timeout.unwrap_or(Duration::from_secs(30));
        Ok(RpcTransport {
            peer,
            path,
            auth,
            timeout,
        })
    }

    /// Sends a JSON-RPC request with the given ID, method name, and parameters.
    ///
    /// # Arguments
    ///
    /// * `id` - A unique identifier for correlating responses.
    /// * `method` - The name of the JSON-RPC method to invoke.
    /// * `params` - A list of parameters to pass to the method.
    ///
    /// # Returns
    ///
    /// Returns `RpcResult<T>`, which is a result containing either the successfully deserialized response of type `T`
    /// or an `RpcError` otherwise
    pub fn send<T: for<'de> Deserialize<'de>>(
        &self,
        id: &str,
        method: &str,
        params: Vec<Value>,
    ) -> RpcResult<T> {
        let payload = JsonRpcRequest {
            jsonrpc: RCP_VERSION.to_string(),
            id: id.to_string(),
            method: method.to_string(),
            params: Value::Array(params),
        };

        let json_payload = serde_json::to_value(payload)
            .map_err(|e| RpcError::Encode(format!("Failed to encode request as JSON: {e:?}")))?;

        let mut request = StacksHttpRequest::new_for_peer(
            self.peer.clone(),
            "POST".to_string(),
            self.path.clone(),
            HttpRequestContents::new().payload_json(json_payload),
        )
        .map_err(|e| {
            RpcError::Encode(format!(
                "Failed to encode infallible data as HTTP request {e:?}"
            ))
        })?;
        request.add_header("Connection".into(), "close".into());

        if let Some(auth_header) = self.auth_header() {
            request.add_header("Authorization".to_string(), auth_header);
        }

        let host = request.preamble().host.hostname();
        let port = request.preamble().host.port();

        let response = send_http_request(&host, port, request, self.timeout)?;
        let json_response = match response.destruct().1 {
            HttpResponsePayload::JSON(js) => Ok(js),
            _ => Err(RpcError::Decode("Did not get a JSON response".to_string())),
        }?;

        let parsed_response: JsonRpcResponse<T> = serde_json::from_value(json_response)
            .map_err(|e| RpcError::Decode(format!("Json Parse Error: {e:?}")))?;

        if id != parsed_response.id {
            return Err(RpcError::Decode(format!(
                "Invalid response: mismatched 'id': expected '{}', got '{}'",
                id, parsed_response.id
            )));
        }

        if let Some(error) = parsed_response.error {
            return Err(RpcError::Service(format!("{:#}", error)));
        }

        if let Some(result) = parsed_response.result {
            Ok(result)
        } else {
            Ok(serde_json::from_value(Value::Null).unwrap())
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
}
