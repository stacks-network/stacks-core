// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use std::collections::HashMap;
use std::error;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::net::TcpStream;
use std::str;

use libstackerdb::{
    stackerdb_get_chunk_path, stackerdb_get_metadata_path, stackerdb_post_chunk_path, SlotMetadata,
    StackerDBChunkAckData, StackerDBChunkData,
};

use clarity::vm::types::QualifiedContractIdentifier;

use stacks_common::codec::MAX_MESSAGE_LEN;
use stacks_common::deps_common::httparse;
use stacks_common::util::chunked_encoding::*;

use serde_json;

#[derive(Debug)]
pub enum RPCError {
    IO(io::Error),
    Deserialize(String),
    NotConnected,
    MalformedResponse(String),
    HttpError(u32),
}

impl fmt::Display for RPCError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RPCError::IO(ref s) => fmt::Display::fmt(s, f),
            RPCError::Deserialize(ref s) => fmt::Display::fmt(s, f),
            RPCError::HttpError(ref s) => {
                write!(f, "HTTP code {}", s)
            }
            RPCError::MalformedResponse(ref s) => {
                write!(f, "Malformed response: {}", s)
            }
            RPCError::NotConnected => {
                write!(f, "Not connected")
            }
        }
    }
}

impl error::Error for RPCError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            RPCError::IO(ref s) => Some(s),
            RPCError::Deserialize(..) => None,
            RPCError::HttpError(..) => None,
            RPCError::MalformedResponse(..) => None,
            RPCError::NotConnected => None,
        }
    }
}

impl From<io::Error> for RPCError {
    fn from(e: io::Error) -> RPCError {
        RPCError::IO(e)
    }
}

pub trait SignerSession {
    fn connect(
        &mut self,
        host: SocketAddr,
        stackerdb_contract_id: QualifiedContractIdentifier,
    ) -> Result<(), RPCError>;
    fn list_chunks(&mut self) -> Result<Vec<SlotMetadata>, RPCError>;
    fn get_chunks(
        &mut self,
        slots_and_versions: &[(u32, u32)],
    ) -> Result<Vec<Option<Vec<u8>>>, RPCError>;
    fn get_latest_chunks(&mut self, slot_ids: &[u32]) -> Result<Vec<Option<Vec<u8>>>, RPCError>;
    fn put_chunk(&mut self, chunk: StackerDBChunkData) -> Result<StackerDBChunkAckData, RPCError>;

    /// Get a single chunk with the given version
    /// Returns Ok(Some(..)) if the chunk exists
    /// Returns Ok(None) if the chunk with the given version does not exist
    /// Returns Err(..) on transport error
    fn get_chunk(&mut self, slot_id: u32, version: u32) -> Result<Option<Vec<u8>>, RPCError> {
        Ok(self.get_chunks(&[(slot_id, version)])?[0].clone())
    }

    /// Get a single latest chunk.
    /// Returns Ok(Some(..)) if the slot exists
    /// Returns Ok(None) if not
    /// Returns Err(..) on transport error
    fn get_latest_chunk(&mut self, slot_id: u32) -> Result<Option<Vec<u8>>, RPCError> {
        Ok(self.get_latest_chunks(&[(slot_id)])?[0].clone())
    }
}

/// signer session for a stackerdb instance
pub struct StackerDBSession {
    /// host we're talking to
    pub host: SocketAddr,
    /// contract we're talking to
    pub stackerdb_contract_id: QualifiedContractIdentifier,
    /// connection to the replica
    sock: Option<TcpStream>,
}

impl StackerDBSession {
    /// instantiate but don't connect
    pub fn new(
        host: SocketAddr,
        stackerdb_contract_id: QualifiedContractIdentifier,
    ) -> StackerDBSession {
        StackerDBSession {
            host,
            stackerdb_contract_id,
            sock: None,
        }
    }

    /// connect or reconnect to the node
    fn connect_or_reconnect(&mut self) -> Result<(), RPCError> {
        debug!("connect to {}", &self.host);
        self.sock = Some(TcpStream::connect(self.host.clone())?);
        Ok(())
    }

    /// Do something with the connected socket
    fn with_socket<F, R>(&mut self, todo: F) -> Result<R, RPCError>
    where
        F: FnOnce(&mut StackerDBSession, &mut TcpStream) -> R,
    {
        if self.sock.is_none() {
            self.connect_or_reconnect()?;
        }

        let mut sock = if let Some(s) = self.sock.take() {
            s
        } else {
            return Err(RPCError::NotConnected);
        };

        let res = todo(self, &mut sock);

        self.sock = Some(sock);
        Ok(res)
    }

    /// Decode the HTTP payload into its headers and body.
    /// Return the offset into payload where the body starts, and a table of headers.
    fn decode_http_response(payload: &[u8]) -> Result<(HashMap<String, String>, usize), RPCError> {
        // realistically, there won't be more than 32 headers
        let mut headers_buf = [httparse::EMPTY_HEADER; 32];
        let mut resp = httparse::Response::new(&mut headers_buf);

        // consume respuest
        let (headers, body_offset) = if let Ok(httparse::Status::Complete(body_offset)) =
            resp.parse(payload)
        {
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
                if value.len() > 4096 {
                    return Err(RPCError::MalformedResponse(format!(
                        "Invalid HTTP response: header value is too big"
                    )));
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

    /// send an HTTP RPC request and receive a reply.
    /// Return the HTTP reply, decoded if it was chunked
    fn run_http_request(
        &mut self,
        verb: &str,
        path: &str,
        content_type: Option<&str>,
        payload: &[u8],
    ) -> Result<Vec<u8>, RPCError> {
        self.with_socket(|session, sock| {
            let content_length_hdr = if payload.len() > 0 {
                format!("Content-Length: {}\r\n", payload.len())
            }
            else {
                "".to_string()
            };

            let req_txt = if let Some(content_type) = content_type {
                format!(
                    "{} {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\nContent-Type: {}\r\n{}User-Agent: stacks-signer/0.1\r\nAccept: */*\r\n\r\n",
                    verb, path, format!("{}", &session.host), content_type, content_length_hdr
                )
            }
            else {
                format!(
                    "{} {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n{}User-Agent: stacks-signer/0.1\r\nAccept: */*\r\n\r\n",
                    verb, path, format!("{}", &session.host), content_length_hdr
                )
            };
            debug!("HTTP request\n{}", &req_txt);

            sock.write_all(req_txt.as_bytes())?;
            sock.write_all(payload)?;

            let mut buf = vec![];

            sock.read_to_end(&mut buf)?;

            let (headers, body_offset) = Self::decode_http_response(&buf)?;
            if body_offset >= buf.len() {
                // no body
                debug!("No HTTP body");
                return Ok(vec![]);
            }

            let chunked = if let Some(val) = headers.get("transfer-encoding") {
                val == "chunked"
            }
            else {
                false
            };

            let body = if chunked {
                // chunked encoding
                debug!("HTTP response is chunked, at offset {}", body_offset);
                let ptr = &mut &buf[body_offset..];
                let mut fd = HttpChunkedTransferReader::from_reader(ptr, MAX_MESSAGE_LEN.into());
                let mut decoded_body = vec![];
                fd.read_to_end(&mut decoded_body)?;
                decoded_body
            }
            else {
                // body is just as-is
                debug!("HTTP response is raw, at offset {}", body_offset);
                buf[body_offset..].to_vec()
            };

            Ok(body)
        })?
    }
}

impl SignerSession for StackerDBSession {
    /// connect to the replica
    fn connect(
        &mut self,
        host: SocketAddr,
        stackerdb_contract_id: QualifiedContractIdentifier,
    ) -> Result<(), RPCError> {
        self.host = host;
        self.stackerdb_contract_id = stackerdb_contract_id;
        self.connect_or_reconnect()
    }

    /// query the replica for a list of chunks
    fn list_chunks(&mut self) -> Result<Vec<SlotMetadata>, RPCError> {
        let bytes = self.run_http_request(
            "GET",
            &stackerdb_get_metadata_path(self.stackerdb_contract_id.clone()),
            None,
            &[],
        )?;
        let metadata: Vec<SlotMetadata> = serde_json::from_slice(&bytes)
            .map_err(|e| RPCError::Deserialize(format!("{:?}", &e)))?;
        Ok(metadata)
    }

    /// query the replica for zero or more chunks
    fn get_chunks(
        &mut self,
        slots_and_versions: &[(u32, u32)],
    ) -> Result<Vec<Option<Vec<u8>>>, RPCError> {
        let mut payloads = vec![];
        for (slot_id, slot_version) in slots_and_versions.iter() {
            let path = stackerdb_get_chunk_path(
                self.stackerdb_contract_id.clone(),
                *slot_id,
                Some(*slot_version),
            );
            let chunk = match self.run_http_request("GET", &path, None, &[]) {
                Ok(body_bytes) => Some(body_bytes),
                Err(RPCError::HttpError(code)) => {
                    if code != 404 {
                        return Err(RPCError::HttpError(code));
                    }
                    None
                }
                Err(e) => {
                    return Err(e);
                }
            };
            payloads.push(chunk);
        }
        Ok(payloads)
    }

    /// query the replica for zero or more latest chunks
    fn get_latest_chunks(&mut self, slot_ids: &[u32]) -> Result<Vec<Option<Vec<u8>>>, RPCError> {
        let mut payloads = vec![];
        for slot_id in slot_ids.iter() {
            let path = stackerdb_get_chunk_path(self.stackerdb_contract_id.clone(), *slot_id, None);
            let chunk = match self.run_http_request("GET", &path, None, &[]) {
                Ok(body_bytes) => Some(body_bytes),
                Err(RPCError::HttpError(code)) => {
                    if code != 404 {
                        return Err(RPCError::HttpError(code));
                    }
                    None
                }
                Err(e) => {
                    return Err(e);
                }
            };
            payloads.push(chunk);
        }
        Ok(payloads)
    }

    /// upload a chunk
    fn put_chunk(&mut self, chunk: StackerDBChunkData) -> Result<StackerDBChunkAckData, RPCError> {
        let body =
            serde_json::to_vec(&chunk).map_err(|e| RPCError::Deserialize(format!("{:?}", &e)))?;
        let path = stackerdb_post_chunk_path(self.stackerdb_contract_id.clone());
        let resp_bytes = self.run_http_request("POST", &path, Some("application/json"), &body)?;
        let ack: StackerDBChunkAckData = serde_json::from_slice(&resp_bytes)
            .map_err(|e| RPCError::Deserialize(format!("{:?}", &e)))?;
        Ok(ack)
    }
}
