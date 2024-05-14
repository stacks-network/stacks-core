// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;

use hashbrown::HashMap;
use stacks_common::codec::MAX_MESSAGE_LEN;
use stacks_common::deps_common::httparse;
use stacks_common::util::chunked_encoding::*;

use crate::error::{EventError, RPCError};

pub const MAX_HTTP_HEADERS: usize = 32;
pub const MAX_HTTP_HEADER_LEN: usize = 4096;

/// Decoding of the relevant parts of a signer-directed HTTP request from the Stacks node
#[derive(Debug)]
pub struct SignerHttpRequest {
    pub verb: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body_offset: usize,
}

impl SignerHttpRequest {
    pub fn new(
        verb: String,
        path: String,
        headers: HashMap<String, String>,
        body_offset: usize,
    ) -> SignerHttpRequest {
        SignerHttpRequest {
            verb,
            path,
            headers,
            body_offset,
        }
    }

    /// Decompose into (verb, path, headers, body-offset)
    pub fn destruct(self) -> (String, String, HashMap<String, String>, usize) {
        (self.verb, self.path, self.headers, self.body_offset)
    }
}

/// Decode the HTTP request payload into its headers and body.
/// Returns (verb, path, table of headers, body_offset) on success
pub fn decode_http_request(payload: &[u8]) -> Result<SignerHttpRequest, EventError> {
    // realistically, there won't be more than 32 headers
    let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut req = httparse::Request::new(&mut headers_buf);
    let (verb, path, headers, body_offset) =
        if let Ok(httparse::Status::Complete(body_offset)) = req.parse(payload) {
            // version must be valid
            match req
                .version
                .ok_or(EventError::MalformedRequest("No HTTP version".to_string()))?
            {
                0 => {}
                1 => {}
                _ => {
                    return Err(EventError::MalformedRequest(
                        "Invalid HTTP version".to_string(),
                    ));
                }
            };

            let verb = req
                .method
                .ok_or(EventError::MalformedRequest("No HTTP method".to_string()))?
                .to_string();
            let path = req
                .path
                .ok_or(EventError::MalformedRequest("No HTTP path".to_string()))?
                .to_string();

            let mut headers: HashMap<String, String> = HashMap::new();
            for i in 0..req.headers.len() {
                let value = String::from_utf8(req.headers[i].value.to_vec()).map_err(|_e| {
                    EventError::MalformedRequest("Invalid HTTP header value: not utf-8".to_string())
                })?;
                if !value.is_ascii() {
                    return Err(EventError::MalformedRequest(
                        "Invalid HTTP request: header value is not ASCII-US".to_string(),
                    ));
                }
                if value.len() > MAX_HTTP_HEADER_LEN {
                    return Err(EventError::MalformedRequest(
                        "Invalid HTTP request: header value is too big".to_string(),
                    ));
                }

                let key = req.headers[i].name.to_string().to_lowercase();
                if headers.get(&key).is_some() {
                    return Err(EventError::MalformedRequest(format!(
                        "Invalid HTTP request: duplicate header \"{}\"",
                        key
                    )));
                }
                headers.insert(key, value);
            }
            (verb, path, headers, body_offset)
        } else {
            return Err(EventError::Deserialize(
                "Failed to decode HTTP headers".to_string(),
            ));
        };

    Ok(SignerHttpRequest::new(verb, path, headers, body_offset))
}

/// Decode the HTTP response payload into its headers and body.
/// Return the offset into payload where the body starts, and a table of headers.
///
/// If the payload contains a status code other than 200, then RPCERror::HttpError(..) will be
/// returned with the status code.
/// If the payload is missing necessary data, then RPCError::MalformedResponse(..) will be
/// returned, with a human-readable reason string.
/// If the payload does not contain a full HTTP header list, then RPCError::Deserialize(..) will be
/// returned.  This can happen if there are more than MAX_HTTP_HEADERS in the payload, for example.
pub fn decode_http_response(payload: &[u8]) -> Result<(HashMap<String, String>, usize), RPCError> {
    // realistically, there won't be more than 32 headers
    let mut headers_buf = [httparse::EMPTY_HEADER; MAX_HTTP_HEADERS];
    let mut resp = httparse::Response::new(&mut headers_buf);

    // consume respuest
    let (headers, body_offset) =
        if let Ok(httparse::Status::Complete(body_offset)) = resp.parse(payload) {
            if let Some(code) = resp.code {
                if code != 200 {
                    return Err(RPCError::HttpError(code.into()));
                }
            } else {
                return Err(RPCError::MalformedResponse(
                    "No HTTP status code returned".to_string(),
                ));
            }
            if let Some(version) = resp.version {
                if version != 0 && version != 1 {
                    return Err(RPCError::MalformedResponse(format!(
                        "Unrecognized HTTP code {}",
                        version
                    )));
                }
            } else {
                return Err(RPCError::MalformedResponse(
                    "No HTTP version given".to_string(),
                ));
            }
            let mut headers: HashMap<String, String> = HashMap::new();
            for i in 0..resp.headers.len() {
                let value = String::from_utf8(resp.headers[i].value.to_vec()).map_err(|_e| {
                    RPCError::MalformedResponse("Invalid HTTP header value: not utf-8".to_string())
                })?;
                if !value.is_ascii() {
                    return Err(RPCError::MalformedResponse(
                        "Invalid HTTP response: header value is not ASCII-US".to_string(),
                    ));
                }
                if value.len() > MAX_HTTP_HEADER_LEN {
                    return Err(RPCError::MalformedResponse(
                        "Invalid HTTP response: header value is too big".to_string(),
                    ));
                }

                let key = resp.headers[i].name.to_string().to_lowercase();
                if headers.contains_key(&key) {
                    return Err(RPCError::MalformedResponse(format!(
                        "Invalid HTTP respuest: duplicate header \"{}\"",
                        key
                    )));
                }
                headers.insert(key, value);
            }
            (headers, body_offset)
        } else {
            return Err(RPCError::Deserialize(
                "Failed to decode HTTP headers".to_string(),
            ));
        };

    Ok((headers, body_offset))
}

/// Decode an HTTP body, given the headers.
pub fn decode_http_body(headers: &HashMap<String, String>, mut buf: &[u8]) -> io::Result<Vec<u8>> {
    let chunked = if let Some(val) = headers.get("transfer-encoding") {
        val == "chunked"
    } else {
        false
    };

    let body = if chunked {
        // chunked encoding
        let ptr = &mut buf;
        let mut fd = HttpChunkedTransferReader::from_reader(ptr, MAX_MESSAGE_LEN.into());
        let mut decoded_body = vec![];
        fd.read_to_end(&mut decoded_body)?;
        decoded_body
    } else {
        // body is just as-is
        buf.to_vec()
    };

    Ok(body)
}

/// Run an HTTP request, synchronously, through the given read/write handle
/// Return the HTTP reply, decoded if it was chunked
pub fn run_http_request<S: Read + Write>(
    sock: &mut S,
    host: &str,
    verb: &str,
    path: &str,
    content_type: Option<&str>,
    payload: &[u8],
) -> Result<Vec<u8>, RPCError> {
    let content_length_hdr = if !payload.is_empty() {
        format!("Content-Length: {}\r\n", payload.len())
    } else {
        "".to_string()
    };

    let req_txt = if let Some(content_type) = content_type {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: {}\r\n{}User-Agent: libsigner/0.1\r\nAccept: */*\r\n\r\n",
            verb, path, host, content_type, content_length_hdr
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n{}User-Agent: libsigner/0.1\r\nAccept: */*\r\n\r\n",
            verb, path, host, content_length_hdr
        )
    };
    debug!("HTTP request\n{}", &req_txt);

    sock.write_all(req_txt.as_bytes())?;
    sock.write_all(payload)?;

    let mut buf = vec![];

    sock.read_to_end(&mut buf)?;

    let (headers, body_offset) = decode_http_response(&buf)?;
    if body_offset >= buf.len() {
        // no body
        debug!("No HTTP body");
        debug!("Headers: {:?}", &headers);
        return Ok(vec![]);
    }

    decode_http_body(&headers, &buf[body_offset..]).map_err(|e| e.into())
}
