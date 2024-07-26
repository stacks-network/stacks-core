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

use std::net::{SocketAddr, TcpStream};
use std::str;

use clarity::vm::types::QualifiedContractIdentifier;
use libstackerdb::{
    stackerdb_get_chunk_path, stackerdb_get_metadata_path, stackerdb_post_chunk_path, SlotMetadata,
    StackerDBChunkAckData, StackerDBChunkData, SIGNERS_STACKERDB_CHUNK_SIZE,
    STACKERDB_MAX_CHUNK_SIZE,
};
use stacks_common::codec::StacksMessageCodec;

use crate::error::RPCError;
use crate::http::run_http_request;

/// Trait for connecting to and querying a signer Stacker DB replica
pub trait SignerSession {
    /// connect to the replica
    fn connect(
        &mut self,
        host: String,
        stackerdb_contract_id: QualifiedContractIdentifier,
    ) -> Result<(), RPCError>;
    /// query the replica for a list of chunks
    fn list_chunks(&mut self) -> Result<Vec<SlotMetadata>, RPCError>;
    /// query the replica for zero or more chunks
    fn get_chunks(
        &mut self,
        slots_and_versions: &[(u32, u32)],
    ) -> Result<Vec<Option<Vec<u8>>>, RPCError>;
    /// query the replica for zero or more latest chunks
    fn get_latest_chunks(&mut self, slot_ids: &[u32]) -> Result<Vec<Option<Vec<u8>>>, RPCError>;
    /// Upload a chunk to the stacker DB instance
    fn put_chunk(&mut self, chunk: &StackerDBChunkData) -> Result<StackerDBChunkAckData, RPCError>;

    /// Get a single chunk with the given version
    /// Returns Ok(Some(..)) if the chunk exists
    /// Returns Ok(None) if the chunk with the given version does not exist
    /// Returns Err(..) on transport error
    fn get_chunk(&mut self, slot_id: u32, version: u32) -> Result<Option<Vec<u8>>, RPCError> {
        let mut chunks = self.get_chunks(&[(slot_id, version)])?;
        // check if chunks is empty because [0] and remove(0) panic on out-of-bounds
        if chunks.is_empty() {
            return Ok(None);
        }
        // swap_remove breaks the ordering of latest_chunks, but we don't care because we
        //  only want the first element anyways.
        Ok(chunks.swap_remove(0))
    }

    /// Get a single latest chunk.
    /// Returns Ok(Some(..)) if the slot exists
    /// Returns Ok(None) if not
    /// Returns Err(..) on transport error
    fn get_latest_chunk(&mut self, slot_id: u32) -> Result<Option<Vec<u8>>, RPCError> {
        let mut latest_chunks = self.get_latest_chunks(&[slot_id])?;
        // check if latest_chunks is empty because [0] and remove(0) panic on out-of-bounds
        if latest_chunks.is_empty() {
            return Ok(None);
        }
        // swap_remove breaks the ordering of latest_chunks, but we don't care because we
        //  only want the first element anyways.
        Ok(latest_chunks.swap_remove(0))
    }

    /// Get a single latest chunk from the StackerDB and deserialize into `T` using the
    /// StacksMessageCodec.
    fn get_latest<T: StacksMessageCodec>(&mut self, slot_id: u32) -> Result<Option<T>, RPCError> {
        let Some(latest_bytes) = self.get_latest_chunk(slot_id)? else {
            return Ok(None);
        };
        Some(
            T::consensus_deserialize(&mut latest_bytes.as_slice()).map_err(|e| {
                let msg = format!("StacksMessageCodec::consensus_deserialize failure: {e}");
                RPCError::Deserialize(msg)
            }),
        )
        .transpose()
    }
}

/// signer session for a stackerdb instance
#[derive(Debug)]
pub struct StackerDBSession {
    /// host we're talking to
    pub host: String,
    /// contract we're talking to
    pub stackerdb_contract_id: QualifiedContractIdentifier,
    /// connection to the replica
    sock: Option<TcpStream>,
}

impl StackerDBSession {
    /// instantiate but don't connect
    pub fn new(host: &str, stackerdb_contract_id: QualifiedContractIdentifier) -> StackerDBSession {
        StackerDBSession {
            host: host.to_owned(),
            stackerdb_contract_id,
            sock: None,
        }
    }

    /// connect or reconnect to the node
    fn connect_or_reconnect(&mut self) -> Result<(), RPCError> {
        debug!("connect to {}", &self.host);
        self.sock = Some(TcpStream::connect(&self.host)?);
        Ok(())
    }

    /// Do something with the connected socket
    fn with_socket<F, R>(&mut self, todo: F) -> Result<R, RPCError>
    where
        F: FnOnce(&mut StackerDBSession, &mut TcpStream) -> R,
    {
        // TODO: fix this so we can use persistent connection
        // See https://github.com/stacks-network/stacks-blockchain/issues/3922
        //if self.sock.is_none() {
        self.connect_or_reconnect()?;

        let mut sock = if let Some(s) = self.sock.take() {
            s
        } else {
            return Err(RPCError::NotConnected);
        };

        let res = todo(self, &mut sock);

        self.sock = Some(sock);
        Ok(res)
    }

    /// send an HTTP RPC request and receive a reply.
    /// Return the HTTP reply, decoded if it was chunked
    fn rpc_request(
        &mut self,
        verb: &str,
        path: &str,
        content_type: Option<&str>,
        payload: &[u8],
    ) -> Result<Vec<u8>, RPCError> {
        self.with_socket(|session, sock| {
            run_http_request(sock, &session.host, verb, path, content_type, payload)
        })?
    }
}

impl SignerSession for StackerDBSession {
    /// connect to the replica
    fn connect(
        &mut self,
        host: String,
        stackerdb_contract_id: QualifiedContractIdentifier,
    ) -> Result<(), RPCError> {
        self.host = host;
        self.stackerdb_contract_id = stackerdb_contract_id;
        self.connect_or_reconnect()
    }

    /// query the replica for a list of chunks
    fn list_chunks(&mut self) -> Result<Vec<SlotMetadata>, RPCError> {
        let bytes = self.rpc_request(
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
            let chunk = match self.rpc_request("GET", &path, None, &[]) {
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
        let limit = if self.stackerdb_contract_id.name.starts_with("signer") {
            SIGNERS_STACKERDB_CHUNK_SIZE
        } else {
            usize::try_from(STACKERDB_MAX_CHUNK_SIZE)
                .expect("infallible: StackerDB chunk size exceeds usize::MAX")
        };
        for slot_id in slot_ids.iter() {
            let path = stackerdb_get_chunk_path(self.stackerdb_contract_id.clone(), *slot_id, None);
            let chunk = match self.rpc_request("GET", &path, None, &[]) {
                Ok(body_bytes) => {
                    // Verify that the chunk is not too large
                    if body_bytes.len() > limit {
                        None
                    } else {
                        Some(body_bytes)
                    }
                }
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
    fn put_chunk(&mut self, chunk: &StackerDBChunkData) -> Result<StackerDBChunkAckData, RPCError> {
        let body =
            serde_json::to_vec(chunk).map_err(|e| RPCError::Deserialize(format!("{:?}", &e)))?;
        let path = stackerdb_post_chunk_path(self.stackerdb_contract_id.clone());
        let resp_bytes = self.rpc_request("POST", &path, Some("application/json"), &body)?;
        let ack: StackerDBChunkAckData = serde_json::from_slice(&resp_bytes)
            .map_err(|e| RPCError::Deserialize(format!("{:?}", &e)))?;
        Ok(ack)
    }
}
