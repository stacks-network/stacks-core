/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use net::PeerAddress;
use net::Neighbor;
use net::NeighborKey;
use net::Error as net_error;
use net::db::PeerDB;
use net::asn::ASEntry4;

use net::*;
use net::codec::*;

use net::StacksMessage;

use net::connection::Connection;
use net::connection::ConnectionOptions;
use net::connection::NetworkReplyHandle;

use net::poll::NetworkState;
use net::poll::NetworkPollState;

use net::p2p::PeerNetwork;
use net::p2p::NetworkHandle;

use net::db::*;

use util::db::Error as db_error;
use util::db::DBConn;
use util::secp256k1::Secp256k1PublicKey;
use util::secp256k1::Secp256k1PrivateKey;

use chainstate::burn::db::burndb;
use chainstate::burn::db::burndb::BurnDB;

use burnchains::Burnchain;
use burnchains::BurnchainView;

use std::net::SocketAddr;

use std::collections::HashMap;
use std::collections::VecDeque;

use std::io::Read;
use std::io::Write;

use util::log;
use util::get_epoch_time_secs;
use util::hash::to_hex;

use mio::net as mio_net;

use rusqlite::Transaction;

// did we or did we not successfully send a message?
#[derive(Debug, Clone)]
pub struct NeighborHealthPoint {
    pub success: bool,
    pub time: u64
}

impl Default for NeighborHealthPoint {
    fn default() -> NeighborHealthPoint {
        NeighborHealthPoint {
            success: false,
            time: 0
        }
    }
}

pub const NUM_HEALTH_POINTS : usize = 32;
pub const HEALTH_POINT_LIFETIME : u64 = 12 * 3600;  // 12 hours
    
#[derive(Debug, Clone)]
pub struct NeighborStats {
    pub outbound: bool,
    pub first_contact_time: u64,
    pub last_contact_time: u64,
    pub last_send_time: u64,
    pub last_recv_time: u64,
    pub last_handshake_time: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub msgs_tx: u64,
    pub msgs_rx: u64,
    pub msgs_err: u64,
    pub healthpoints: VecDeque<NeighborHealthPoint>,
    pub peer_resets: u64,
    pub last_reset_time: u64,
    pub msg_rx_counts: HashMap<u8, u64>,
}

impl NeighborStats {
    pub fn new(outbound: bool) -> NeighborStats {
        NeighborStats {
            outbound: outbound,
            first_contact_time: 0,
            last_contact_time: 0,
            last_send_time: 0,
            last_recv_time: 0,
            last_handshake_time: 0,
            bytes_tx: 0,
            bytes_rx: 0,
            msgs_tx: 0,
            msgs_rx: 0,
            msgs_err: 0,
            healthpoints: VecDeque::new(),
            peer_resets: 0,
            last_reset_time: 0,
            msg_rx_counts: HashMap::new()
        }
    }
    
    pub fn add_healthpoint(&mut self, success: bool) -> () {
        let hp = NeighborHealthPoint {
            success: success,
            time: get_epoch_time_secs()
        };
        self.healthpoints.push_back(hp);
        while self.healthpoints.len() > NUM_HEALTH_POINTS {
            self.healthpoints.pop_front();
        }
    }

    /// Get a peer's perceived health -- the last $NUM_HEALTH_POINTS successful messages divided by
    /// the total.
    pub fn get_health_score(&self) -> f64 {
        // if we don't have enough data, assume 50%
        if self.healthpoints.len() < NUM_HEALTH_POINTS {
            return 0.5;
        }
        
        let mut successful = 0;
        let mut total = 0;
        let now = get_epoch_time_secs();
        for hp in self.healthpoints.iter() {
            // penalize stale data points -- only look at recent data
            if hp.success && now < hp.time + HEALTH_POINT_LIFETIME {
                successful += 1;
            }
            total += 1;
        }
        (successful as f64) / (total as f64)
    }
}

pub struct Conversation {
    pub connection: Connection,
    pub conn_id: usize,

    pub burnchain: Burnchain,                   // copy of our burnchain config
    pub seq: u32,                               // our sequence number when talknig to this peer
    pub heartbeat: u32,                         // how often do we send heartbeats?

    pub peer_network_id: u32,
    pub peer_version: u32,
    pub peer_services: u16,
    pub peer_addrbytes: PeerAddress,
    pub peer_port: u16,
    pub peer_heartbeat: u32,                    // how often do we need to ping the remote peer?
    pub peer_expire_block_height: u64,          // when does the peer's key expire?

    pub stats: NeighborStats
}

impl fmt::Display for Conversation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "convo:id={},peer={:?}", self.conn_id, &self.to_neighbor_key())
    }
}

impl fmt::Debug for Conversation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "convo:id={},peer={:?}", self.conn_id, &self.to_neighbor_key())
    }
}

impl NeighborKey {
    pub fn from_handshake(peer_version: u32, network_id: u32, handshake_data: &HandshakeData) -> NeighborKey {
        NeighborKey {
            peer_version: peer_version, 
            network_id: network_id,
            addrbytes: handshake_data.addrbytes.clone(),
            port: handshake_data.port,
        }
    }

    pub fn from_socketaddr(peer_version: u32, network_id: u32, addr: &SocketAddr) -> NeighborKey {
        NeighborKey {
            peer_version: peer_version,
            network_id: network_id,
            addrbytes: PeerAddress::from_socketaddr(addr),
            port: addr.port(),
        }
    }
}

impl Neighbor {
    /// Update fields in this neighbor from a given handshake.
    /// Also, re-calculate the peer's ASN and organization ID
    pub fn handshake_update(&mut self, conn: &DBConn, handshake_data: &HandshakeData) -> Result<(), net_error> {
        let pubk = handshake_data.node_public_key.to_public_key()?;
        let asn_opt = PeerDB::asn_lookup(conn, &handshake_data.addrbytes)
            .map_err(|_e| net_error::DBError)?;

        let asn = match asn_opt {
            Some(a) => a,
            None => 0
        };

        self.public_key = pubk;
        self.expire_block = handshake_data.expire_block_height;
        self.last_contact_time = get_epoch_time_secs();

        if asn != 0 {
            self.asn = asn;
            self.org = asn;       // TODO; AS number is a place-holder for an organization ID (an organization can own multiple ASs)
        }

        Ok(())
    }

    pub fn from_handshake(conn: &DBConn, peer_version: u32, network_id: u32, handshake_data: &HandshakeData) -> Result<Neighbor, net_error> {
        let addr = NeighborKey::from_handshake(peer_version, network_id, handshake_data);
        let pubk = handshake_data.node_public_key.to_public_key()?;

        let peer_opt = PeerDB::get_peer(conn, network_id, &addr.addrbytes, addr.port)
            .map_err(|_e| net_error::DBError)?;

        let mut neighbor = match peer_opt {
            Some(neighbor) => {
                let mut ret = neighbor.clone();
                ret.addr = addr.clone();
                ret
            },
            None => {
                let mut ret = Neighbor::empty(&addr, &pubk, handshake_data.expire_block_height);
                ret
            }
        };

        #[cfg(test)]
        {
            // setting BLOCKSTACK_NEIGHBOR_TEST_${PORTNUMBER} will let us select an organization
            // for this peer
            use std::env;
            match env::var(format!("BLOCKSTACK_NEIGHBOR_TEST_{}", addr.port).to_string()) {
                Ok(asn_str) => {
                    neighbor.asn = asn_str.parse().unwrap();
                    neighbor.org = neighbor.asn;
                    test_debug!("Override {:?} to ASN/org {}", &neighbor.addr, neighbor.asn);
                },
                Err(_) => {}
            };
        }

        neighbor.handshake_update(conn, &handshake_data)?;
        Ok(neighbor)
    }

    pub fn from_conversation(conn: &DBConn, convo: &Conversation) -> Result<Option<Neighbor>, net_error> {
        let addr = convo.to_neighbor_key();
        let peer_opt = PeerDB::get_peer(conn, addr.network_id, &addr.addrbytes, addr.port)
            .map_err(|_e| net_error::DBError)?;

        match peer_opt {
            None => {
                Ok(None)
            },
            Some(mut peer) => {
                if peer.asn == 0 {
                    let asn_opt = PeerDB::asn_lookup(conn, &addr.addrbytes)
                        .map_err(|_e| net_error::DBError)?;

                    match asn_opt {
                        Some(a) => {
                            if a != 0 {
                                peer.asn = a;
                            }
                        },
                        None => {}
                    };
                }
                Ok(Some(peer))
            }
        }
    }
}

impl Conversation {
    /// Create an unconnected conversation
    pub fn new(burnchain: &Burnchain, peer_addr: &SocketAddr, conn_opts: &ConnectionOptions, outbound: bool, conn_id: usize) -> Conversation {
        Conversation {
            connection: Connection::new(conn_opts, None),
            conn_id: conn_id,
            seq: 0,
            heartbeat: conn_opts.heartbeat,
            burnchain: burnchain.clone(),

            peer_network_id: 0,
            peer_version: 0,
            peer_addrbytes: PeerAddress::from_socketaddr(peer_addr),
            peer_port: peer_addr.port(),
            peer_heartbeat: 0,
            peer_services: 0,
            peer_expire_block_height: 0,

            stats: NeighborStats::new(outbound)
        }
    }

    /// Create a conversation from an existing conversation whose underlying network connection had to be
    /// reset.
    pub fn from_peer_reset(convo: &Conversation, conn_opts: &ConnectionOptions) -> Conversation {
        let stats = convo.stats.clone();
        Conversation {
            connection: Connection::new(conn_opts, None),
            conn_id: convo.conn_id,
            seq: 0,
            heartbeat: conn_opts.heartbeat,
            burnchain: convo.burnchain.clone(),

            peer_network_id: convo.peer_network_id,
            peer_version: convo.peer_version,
            peer_addrbytes: convo.peer_addrbytes.clone(),
            peer_port: convo.peer_port,
            peer_heartbeat: convo.peer_heartbeat,
            peer_services: convo.peer_services,
            peer_expire_block_height: convo.peer_expire_block_height,
            
            stats: NeighborStats {
                peer_resets: convo.stats.peer_resets + 1,
                last_reset_time: get_epoch_time_secs(),
                ..stats
            }
        }
    }

    pub fn to_neighbor_key(&self) -> NeighborKey {
        NeighborKey {
            peer_version: self.peer_version,
            network_id: self.peer_network_id,
            addrbytes: self.peer_addrbytes.clone(),
            port: self.peer_port
        }
    }
    
    fn check_consensus_hash(block_height: u64, their_consensus_hash: &ConsensusHash, burndb_conn: &DBConn) -> Result<bool, net_error> {
        // only proceed if our latest consensus hash matches 
        let our_consensus_hash_opt = burndb::get_consensus_or(burndb_conn, block_height, &ConsensusHash::empty())
            .map_err(|e| {
                error!("Failed to read burnchain DB consensus hash at {}: {:?}", block_height, e);
                net_error::DBError
            })?;

        match our_consensus_hash_opt {
            Some(our_consensus_hash) => {
                if our_consensus_hash != *their_consensus_hash {
                    // remote peer is on a different burnchain fork than us
                    test_debug!("{}: {:?} != {:?}", block_height, &our_consensus_hash, their_consensus_hash);
                    Ok(false)
                }
                else {
                    Ok(true)
                }
            },
            None => {
                // shouldn't happen 
                panic!("BurnDB is corrupt -- unable to read consensus hash for {}", block_height);
            }
        }
    }

    /// Validate an inbound message's preamble against our knowledge of the burn chain.
    /// Return Ok(true) if we can proceed
    /// Return Ok(false) if we can't proceed, but the remote peer is not in violation of the protocol 
    /// Return Err(net_error::InvalidMessage) if the remote peer returns an invalid message in
    ///     violation of the protocol
    pub fn is_preamble_valid(&self, msg: &StacksMessage, burndb_conn: &DBConn) -> Result<bool, net_error> {
        if msg.preamble.network_id != self.burnchain.network_id {
            // not on our network -- potentially blacklist this peer
            test_debug!("wrong network ID: {:x} != {:x}", msg.preamble.network_id, self.burnchain.network_id);
            return Err(net_error::InvalidMessage);
        }
        if (msg.preamble.peer_version & 0xff000000) != (self.burnchain.peer_version & 0xff000000) {
            // major version mismatch -- potentially blacklist this peer
            test_debug!("wrong peer version: {:x} != {:x}", msg.preamble.peer_version, self.burnchain.peer_version);
            return Err(net_error::InvalidMessage);
        }
        if msg.preamble.burn_stable_block_height + (self.burnchain.stable_confirmations as u64) != msg.preamble.burn_block_height {
            // invalid message -- potentially blacklist this peer
            test_debug!("wrong stable block height: {} != {}", msg.preamble.burn_stable_block_height + (self.burnchain.stable_confirmations as u64), msg.preamble.burn_block_height);
            return Err(net_error::InvalidMessage);
        }

        let block_height = burndb::get_block_height(burndb_conn)
            .map_err(|e| {
                error!("Failed to read burnchain DB: {:?}", e);
                net_error::DBError
            })?;

        if msg.preamble.burn_stable_block_height > block_height {
            // this node is too far ahead of us, but otherwise still potentially valid 
            test_debug!("remote peer is too far ahead of us: {} > {}", msg.preamble.burn_stable_block_height, block_height);
            return Ok(false);
        }
        else {
            // remote node's unstable burn block height is behind ours.
            // only proceed if our latest consensus hash matches theirs.
            let res = Conversation::check_consensus_hash(msg.preamble.burn_block_height, &msg.preamble.burn_consensus_hash, burndb_conn)?;
            if !res {
                // our chain tip disagrees with their chain tip -- don't engage
                return Ok(false);
            }
        }

        // must agree on stable consensus hash
        let rules_agree = Conversation::check_consensus_hash(msg.preamble.burn_stable_block_height, &msg.preamble.burn_stable_consensus_hash, burndb_conn)?;
        if !rules_agree {
            // remote peer disagrees on stable consensus hash -- follows different rules than us
            test_debug!("Consensus hash mismatch in preamble");
            return Err(net_error::InvalidMessage);
        }

        Ok(true)
    }

    /// Get next message sequence number, and increment.
    fn next_seq(&mut self) -> u32 {
        if self.seq == u32::max_value() {
            self.seq = 0;
        }
        let ret = self.seq;
        self.seq += 1;
        ret
    }

    /// Generate a signed message for this conversation 
    pub fn sign_message(&mut self, chain_view: &BurnchainView, private_key: &Secp256k1PrivateKey, payload: StacksMessageType) -> Result<StacksMessage, net_error> {
        let mut msg = StacksMessage::from_chain_view(self.burnchain.peer_version, self.burnchain.network_id, chain_view, payload);
        msg.sign(self.next_seq(), private_key)?;
        Ok(msg)
    }
    
    /// Generate a signed reply for this conversation 
    pub fn sign_reply(&mut self, chain_view: &BurnchainView, private_key: &Secp256k1PrivateKey, payload: StacksMessageType, seq: u32) -> Result<StacksMessage, net_error> {
        let mut msg = StacksMessage::from_chain_view(self.burnchain.peer_version, self.burnchain.network_id, chain_view, payload);
        msg.sign(seq, private_key)?;
        Ok(msg)
    }

    /// Queue up this message to this peer, and update our stats.
    pub fn relay_signed_message(&mut self, msg: StacksMessage) -> Result<(), net_error> {
        self.connection.relay_signed_message(msg)?;
        self.stats.msgs_tx += 1;
        Ok(())
    }
    
    /// Queue up this message to this peer, and update our stats.  Expect a reply.
    pub fn send_signed_message(&mut self, msg: StacksMessage, ttl: u64) -> Result<NetworkReplyHandle, net_error> {
        let rh = self.connection.send_signed_message(msg, ttl)?;
        self.stats.msgs_tx += 1;
        Ok(rh)
    }

    /// Reply to a ping with a pong.
    /// Called from the p2p network thread.
    pub fn handle_ping(&mut self, chain_view: &BurnchainView, message: &mut StacksMessage) -> Result<Option<StacksMessage>, net_error> {
        let ping_data = match message.payload {
            StacksMessageType::Ping(ref data) => data,
            _ => panic!("Message is not a ping")
        };
        let pong_data = PongData::from_ping(&ping_data);
        Ok(Some(StacksMessage::from_chain_view(self.burnchain.peer_version, self.burnchain.network_id, chain_view, StacksMessageType::Pong(pong_data))))
    }

    /// Validate a handshake request.
    /// Return Err(...) if the handshake request was invalid.
    pub fn validate_handshake(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView, message: &mut StacksMessage) -> Result<(), net_error> {
        let handshake_data = match message.payload {
            StacksMessageType::Handshake(ref mut data) => data.clone(),
            _ => panic!("Message is not a handshake")
        };

        match self.connection.get_public_key() {
            None => {
                // if we don't yet have a public key for this node, verify the message.
                // if it's improperly signed, it's a protocol-level error and the peer should be rejected.
                message.verify_secp256k1(&handshake_data.node_public_key)
                    .map_err(|_e| {
                        test_debug!("{:?}: invalid handshake: not signed with given public key", &self);
                        net_error::InvalidMessage
                    })?;
            },
            Some(_) => {
                // for outbound connections, the self-reported address must match socket address if we already have a public key.
                // (not the case for inbound connections, since the peer socket address we see may
                // not be the same as the address the remote peer thinks it has).
                if self.stats.outbound && (self.peer_addrbytes != handshake_data.addrbytes || self.peer_port != handshake_data.port) {
                    // wrong peer address
                    test_debug!("{:?}: invalid handshake -- wrong addr/port ({:?}:{:?})", &self, &handshake_data.addrbytes, handshake_data.port);
                    return Err(net_error::InvalidHandshake);
                }
            }
        };

        let their_public_key_res = handshake_data.node_public_key.to_public_key();
        let their_public_key = match their_public_key_res {
            Ok(pubk) => pubk,
            Err(_e) => {
                // bad public key
                test_debug!("{:?}: invalid handshake -- invalid public key", &self);
                return Err(net_error::InvalidMessage);
            }
        };


        if handshake_data.expire_block_height <= chain_view.burn_block_height {
            // already stale
            test_debug!("{:?}: invalid handshake -- stale public key (expired at {})", &self, handshake_data.expire_block_height);
            return Err(net_error::InvalidHandshake);
        }

        // the handshake cannot come from us 
        if handshake_data.node_public_key == StacksPublicKeyBuffer::from_public_key(&Secp256k1PublicKey::from_private(&local_peer.private_key)) {
            test_debug!("{:?}: invalid handshake -- got a handshake from myself", &self);
            return Err(net_error::InvalidHandshake);
        }

        Ok(())
    }

    /// Update connection state from handshake data
    fn update_from_handshake_data(&mut self, preamble: &Preamble, handshake_data: &HandshakeData) -> Result<(), net_error> {
        let pubk = handshake_data.node_public_key.to_public_key()?;

        self.peer_version = preamble.peer_version;
        self.peer_network_id = preamble.network_id;
        self.peer_services = handshake_data.services;
        self.peer_expire_block_height = handshake_data.expire_block_height;
        self.connection.set_public_key(Some(pubk.clone()));

        Ok(())
    }

    /// Handle a handshake request, and generate either a HandshakeAccept or a HandshakeReject
    /// payload to send back.
    /// A handshake will only be accepted if we do not yet know the public key of this remote peer,
    /// or if it is signed by the current public key.
    /// Called from the p2p network thread.
    /// Panics if this message is not a handshake (caller should check)
    pub fn handle_handshake(&mut self, local_peer: &LocalPeer, chain_view: &BurnchainView, message: &mut StacksMessage) -> Result<Option<StacksMessage>, net_error> {
        let res = self.validate_handshake(local_peer, chain_view, message);
        match res {
            Ok(_) => {},
            Err(net_error::InvalidHandshake) => {
                let reject = StacksMessage::from_chain_view(self.burnchain.peer_version, self.burnchain.network_id, chain_view, StacksMessageType::HandshakeReject);
                debug!("{:?}: invalid handshake", &self);
                return Ok(Some(reject));
            },
            Err(e) => {
                return Err(e);
            }
        };
        
        let handshake_data = match message.payload {
            StacksMessageType::Handshake(ref mut data) => data.clone(),
            _ => panic!("Message is not a handshake")
        };
       
        self.update_from_handshake_data(&message.preamble, &handshake_data)?;
        
        test_debug!("Handshake from {:?} public key {:?} expires at {:?}", &self,
                    &to_hex(&handshake_data.node_public_key.to_public_key().unwrap().to_bytes_compressed()), handshake_data.expire_block_height);

        let accept_data = HandshakeAcceptData::new(local_peer, self.heartbeat);
        let accept = StacksMessage::from_chain_view(self.burnchain.peer_version, self.burnchain.network_id, chain_view, StacksMessageType::HandshakeAccept(accept_data));
        Ok(Some(accept))
    }

    /// Update conversation state based on a HandshakeAccept
    /// Called from the p2p network thread.
    pub fn handle_handshake_accept(&mut self, preamble: &Preamble, handshake_accept: &HandshakeAcceptData) -> Result<Option<StacksMessage>, net_error> {
        self.update_from_handshake_data(preamble, &handshake_accept.handshake)?;
        self.peer_heartbeat = handshake_accept.heartbeat_interval;
        self.stats.last_handshake_time = get_epoch_time_secs();

        test_debug!("HandshakeAccept from {:?}: set public key to {:?} expiring at {:?} heartbeat {}s", &self,
                    &to_hex(&handshake_accept.handshake.node_public_key.to_public_key().unwrap().to_bytes_compressed()), handshake_accept.handshake.expire_block_height, self.peer_heartbeat);
        Ok(None)
    }

    /// Load data into our connection 
    pub fn recv<R: Read>(&mut self, r: &mut R) -> Result<usize, net_error> {
        let res = self.connection.recv_data(r);
        match res {
            Ok(num_recved) => {
                self.stats.last_recv_time = get_epoch_time_secs();
                self.stats.bytes_rx += num_recved as u64;
            },
            Err(_) => {}
        };
        res
    }

    /// Write data out of our conversation 
    pub fn send<W: Write>(&mut self, w: &mut W) -> Result<usize, net_error> {
        let res = self.connection.send_data(w);
        match res {
            Ok(num_sent) => {
                self.stats.last_send_time = get_epoch_time_secs();
                self.stats.bytes_tx += num_sent as u64;
            },
            Err(_) => {}
        };
        res
    }

    /// Carry on a conversation with the remote peer.
    /// Called from the p2p network thread, so no need for a network handle.
    /// Attempts to fulfill requests in other threads as a result of processing a message.
    /// Returns the list of unfulfilled Stacks messages we received -- messages not destined for
    /// any other thread in this program (i.e. "unsolicited messages"), but originating from this
    /// peer.
    /// If the peer violates the protocol, returns net_error::InvalidMessage. The caller should
    /// cease talking to this peer.
    pub fn chat(&mut self, local_peer: &LocalPeer, burndb_conn: &DBConn, burnchain_view: &BurnchainView) -> Result<Vec<StacksMessage>, net_error> {
        let num_inbound = self.connection.inbox_len();
        test_debug!("{:?}: {} messages pending", &self, num_inbound);

        let mut unsolicited = vec![];
        for i in 0..num_inbound {
            let msg_opt = self.connection.next_inbox_message();
            if msg_opt.is_none() {
                continue;
            }
            let mut msg = msg_opt.unwrap();
            let mut consume_unsolicited = false;

            // validate message preamble
            match self.is_preamble_valid(&msg, burndb_conn) {
                Ok(res) => {
                    if !res {
                        info!("{:?}: Received message with stale preamble; ignoring", &self);
                        self.stats.msgs_err += 1;
                        self.stats.add_healthpoint(false);
                        continue;
                    }
                },
                Err(e) => {
                    match e {
                        net_error::InvalidMessage => {
                            // Disconnect from this peer.  If it thinks nothing's wrong, it'll
                            // reconnect on its own.
                            // However, only count this message as error.  Drop all other queued
                            // messages.
                            info!("{:?}: Received invalid preamble; dropping connection", &self);
                            self.stats.msgs_err += 1;
                            self.stats.add_healthpoint(false);
                            return Err(e);
                        },
                        _ => {
                            // skip this message 
                            info!("{:?}: Failed to process message: {:?}", &self, &e);
                            self.stats.msgs_err += 1;
                            self.stats.add_healthpoint(false);
                            continue;
                        }
                    }
                }
            };
            
            let reply_opt_res = 
                if self.connection.has_public_key() {
                    // already have public key; match payload
                    match msg.payload {
                        StacksMessageType::Handshake(_) => {
                            test_debug!("{:?}: Got Handshake", &self);
                            self.handle_handshake(local_peer, burnchain_view, &mut msg)
                        },
                        StacksMessageType::HandshakeAccept(ref data) => {
                            test_debug!("{:?}: Got HandshakeAccept", &self);
                            self.handle_handshake_accept(&msg.preamble, data)
                        },
                        StacksMessageType::Ping(_) => {
                            test_debug!("{:?}: Got Ping", &self);

                            // consume here if unsolicited
                            consume_unsolicited = true;
                            self.handle_ping(burnchain_view, &mut msg)
                        },
                        StacksMessageType::Pong(_) => {
                            test_debug!("{:?}: Got Pong", &self);

                            // consume here if unsolicited
                            consume_unsolicited = true;
                            Ok(None)
                        },
                        _ => {
                            test_debug!("{:?}: Got a message (type {})", &self, message_type_to_str(&msg.payload));
                            Ok(None)       // nothing to reply to at this time
                        }
                    }
                }
                else {
                    // only thing we'll take right now is a handshake, as well as handshake
                    // accept/rejects and nacks.
                    //
                    // Anything else will be nack'ed -- the peer will first need to handshake.
                    match msg.payload {
                        StacksMessageType::Handshake(_) => {
                            test_debug!("{:?}: Got unauthenticated Handshake", &self);
                            self.handle_handshake(local_peer, burnchain_view, &mut msg)
                        },
                        StacksMessageType::HandshakeAccept(ref data) => {
                            test_debug!("{:?}: Got unauthenticated HandshakeAccept", &self);
                            self.handle_handshake_accept(&msg.preamble, data)
                        },
                        StacksMessageType::HandshakeReject => {
                            test_debug!("{:?}: Got unauthenticated HandshakeReject", &self);

                            // don't NACK this back just because we were rejected
                            Ok(None)
                        },
                        StacksMessageType::Nack(ref data) => {
                            test_debug!("{:?}: Got unauthenticated Nack", &self);
                            
                            // don't NACK back
                            Ok(None)
                        }
                        _ => {
                            test_debug!("{:?}: Got unauthenticated message (type {})", &self, message_type_to_str(&msg.payload));
                            let nack_payload = StacksMessageType::Nack(NackData::new(NackErrorCodes::HandshakeRequired));
                            let nack = StacksMessage::from_chain_view(self.burnchain.peer_version, self.burnchain.network_id, burnchain_view, nack_payload);

                            // unauthenticated, so don't forward 
                            consume_unsolicited = true;
                            Ok(Some(nack))
                        }
                    }
                };

            let now = get_epoch_time_secs();
            let mut reply_opt = reply_opt_res?;
            match reply_opt {
                None => {},
                Some(mut reply) => {
                    // send back this message to the remote peer
                    test_debug!("{:?}: Send automatic reply type {}", &self, message_type_to_str(&reply.payload));
                    reply.sign(msg.preamble.seq, &local_peer.private_key)?;
                    self.relay_signed_message(reply)?;
                }
            }

            // successfully got a message -- update stats
            if self.stats.first_contact_time == 0 {
                self.stats.first_contact_time = now;
            }

            let msg_id = message_type_to_id(&msg.payload);
            let count = match self.stats.msg_rx_counts.get(&msg_id) {
                None => 1,
                Some(c) => c + 1
            };
            self.stats.msg_rx_counts.insert(msg_id, count);

            self.stats.msgs_rx += 1;
            self.stats.last_recv_time = now;
            self.stats.last_contact_time = get_epoch_time_secs();
            self.stats.add_healthpoint(true);
            
            let msgtype = message_type_to_str(&msg.payload).to_owned();

            // Is there someone else waiting for this message?  If so, pass it along.
            let fulfill_opt = self.connection.fulfill_request(msg);
            match fulfill_opt {
                None => {
                    test_debug!("{:?}: Fulfilled pending message request (type {})", &self, msgtype);
                },
                Some(m) => {
                    if consume_unsolicited {
                        test_debug!("{:?}: Consuming unsolicited message (type {})", &self, msgtype);
                    }
                    else {
                        test_debug!("{:?}: Forwarding along unsolicited message (type {})", &self, msgtype);
                        unsolicited.push(m);
                    }
                }
            };
        }

        Ok(unsolicited)
    }

    /// Remove all timed-out messages, and ding the remote peer as unhealthy
    pub fn clear_timeouts(&mut self) -> () {
       let num_drained = self.connection.drain_timeouts();
       for i in 0..num_drained {
           self.stats.add_healthpoint(false);
       }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use net::*;
    use net::connection::*;
    use net::db::*;
    use net::p2p::*;
    use util::secp256k1::*;
    use burnchains::*;
    use burnchains::burnchain::*;
    use chainstate::*;
    use chainstate::burn::*;
    use chainstate::burn::db::burndb::*;

    use burnchains::bitcoin::address::BitcoinAddress;
    use burnchains::bitcoin::keys::BitcoinPublicKey;

    use std::net::SocketAddr;
    use std::net::SocketAddrV4;

    use std::io::prelude::*;
    use std::io::Read;
    use std::io::Write;

    use net::test::*;

    use core::PEER_VERSION;

    fn convo_send(convo: &mut Conversation) -> Vec<u8> {
        let mut out_buf = vec![];
        {
            let mut out_fd = NetCursor::new(&mut out_buf);
            convo.send(&mut out_fd).unwrap();
        }
        out_buf
    }

    fn convo_recv(convo: &mut Conversation, mut in_buf: Vec<u8>) -> () {
        let mut in_fd = NetCursor::new(&mut in_buf);
        convo.recv(&mut in_fd).unwrap();
    }

    fn db_setup(peerdb: &mut PeerDB, burndb: &mut BurnDB<BitcoinAddress, BitcoinPublicKey>, socketaddr: &SocketAddr, chain_view: &BurnchainView) -> () {
        {
            let mut tx = peerdb.tx_begin().unwrap();
            PeerDB::set_local_ipaddr(&mut tx, &PeerAddress::from_socketaddr(socketaddr), socketaddr.port()).unwrap();
            tx.commit().unwrap();
        }
        {
            let i_1 = (chain_view.burn_block_height & 0xff) as u8;
            let snapshot_row_1 = BlockSnapshot {
                block_height: chain_view.burn_block_height,
                burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i_1 as u8]).unwrap(),
                parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i_1 == 0 { 0xff } else { i_1 - 1 }) as u8]).unwrap(),
                consensus_hash: chain_view.burn_consensus_hash.clone(),
                ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i_1 as u8]).unwrap(),
                total_burn: i_1 as u64,
                sortition_burn: i_1 as u64,
                burn_quota: 0,
                sortition: true,
                sortition_hash: SortitionHash::initial(),
                winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                winning_block_burn_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                canonical: true
            };

            let i_2 = (chain_view.burn_stable_block_height & 0xff) as u8;
            let snapshot_row_2 = BlockSnapshot {
                block_height: chain_view.burn_stable_block_height,
                burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i_2 as u8]).unwrap(),
                parent_burn_header_hash: BurnchainHeaderHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,(if i_2 == 0 { 0xff } else { i_2 - 1 }) as u8]).unwrap(),
                consensus_hash: chain_view.burn_stable_consensus_hash.clone(),
                ops_hash: OpsHash::from_bytes(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,i_2 as u8]).unwrap(),
                total_burn: i_2 as u64,
                sortition_burn: i_2 as u64,
                burn_quota: 0,
                sortition: true,
                sortition_hash: SortitionHash::initial(),
                winning_block_txid: Txid::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                winning_block_burn_hash: BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                canonical: true
            };

            let mut tx = burndb.tx_begin().unwrap();
            BurnDB::<BitcoinAddress, BitcoinPublicKey>::insert_block_snapshot(&mut tx, &snapshot_row_1).unwrap();
            BurnDB::<BitcoinAddress, BitcoinPublicKey>::insert_block_snapshot(&mut tx, &snapshot_row_2).unwrap();
            tx.commit().unwrap();
        }
    }

    #[test]
    fn convo_handshake_accept() {
        let conn_opts = ConnectionOptions::default();
        let socketaddr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let socketaddr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8081);
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        
        let burnchain = Burnchain {
            peer_version: PEER_VERSION,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: BurnQuotaConfig {
                inc: 21000,
                dec_num: 4,
                dec_den: 5
            },
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: 12300,
            first_block_hash: first_burn_hash.clone(),
        };

        let chain_view = BurnchainView {
            burn_block_height: 12348,
            burn_consensus_hash: ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
            burn_stable_block_height: 12341,
            burn_stable_consensus_hash: ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap()
        };

        let mut peerdb_1 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        let mut peerdb_2 = PeerDB::connect_memory(0x9abcdef0, 12351, &vec![], &vec![]).unwrap();
        
        let mut burndb_1 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();
        let mut burndb_2 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();

        db_setup(&mut peerdb_1, &mut burndb_1, &socketaddr_1, &chain_view);
        db_setup(&mut peerdb_2, &mut burndb_2, &socketaddr_2, &chain_view);

        let local_peer_1 = PeerDB::get_local_peer(&peerdb_1.conn()).unwrap();
        let local_peer_2 = PeerDB::get_local_peer(&peerdb_2.conn()).unwrap();

        let mut convo_1 = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);
        let mut convo_2 = Conversation::new(&burnchain, &socketaddr_1, &conn_opts, true, 0);
       
        // no peer public keys known yet
        assert!(convo_1.connection.get_public_key().is_none());
        assert!(convo_2.connection.get_public_key().is_none());
        
        // convo_1 sends a handshake to convo_2
        let handshake_data_1 = HandshakeData::from_local_peer(&local_peer_1);
        let handshake_1 = convo_1.sign_message(&chain_view, &local_peer_1.private_key, StacksMessageType::Handshake(handshake_data_1.clone())).unwrap();
        let rh_1 = convo_1.send_signed_message(handshake_1, 1000000).unwrap();

        // convo_2 receives it and processes it, and since no one is waiting for it, will forward
        // it along to the chat caller (us)
        convo_recv(&mut convo_2, convo_send(&mut convo_1));
        let unhandled_2 = convo_2.chat(&local_peer_2, burndb_2.conn(), &chain_view).unwrap();

        // convo_1 has a handshakeaccept 
        convo_recv(&mut convo_1, convo_send(&mut convo_2));
        let unhandled_1 = convo_1.chat(&local_peer_1, burndb_1.conn(), &chain_view).unwrap();

        let reply_1 = rh_1.recv(0).unwrap();

        assert_eq!(unhandled_1.len(), 0);
        assert_eq!(unhandled_2.len(), 1);

        // convo 2 returns the handshake from convo 1
        match unhandled_2[0].payload {
            StacksMessageType::Handshake(ref data) => {
                assert_eq!(handshake_data_1, *data);
            },
            _ => {
                assert!(false);
            }
        };

        // received a valid HandshakeAccept from peer 2 
        match reply_1.payload {
            StacksMessageType::HandshakeAccept(ref data) => {
                assert_eq!(data.handshake.addrbytes, local_peer_2.addrbytes);
                assert_eq!(data.handshake.port, local_peer_2.port);
                assert_eq!(data.handshake.services, local_peer_2.services);
                assert_eq!(data.handshake.node_public_key, StacksPublicKeyBuffer::from_public_key(&Secp256k1PublicKey::from_private(&local_peer_2.private_key)));
                assert_eq!(data.handshake.expire_block_height, local_peer_2.private_key_expire); 
                assert_eq!(data.heartbeat_interval, conn_opts.heartbeat);
            },
            _ => {
                assert!(false);
            }
        };

        // convo_2 got updated with convo_1's peer info, but no heartbeat info 
        assert_eq!(convo_2.peer_heartbeat, 0);
        assert_eq!(convo_2.connection.get_public_key().unwrap(), Secp256k1PublicKey::from_private(&local_peer_1.private_key));

        // convo_1 got updated with convo_2's peer info, as well as heartbeat
        assert_eq!(convo_1.peer_heartbeat, conn_opts.heartbeat);
        assert_eq!(convo_1.connection.get_public_key().unwrap(), Secp256k1PublicKey::from_private(&local_peer_2.private_key));
    }
    
    #[test]
    fn convo_handshake_reject() {
        let conn_opts = ConnectionOptions::default();
        let socketaddr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let socketaddr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8081);
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let burnchain = Burnchain {
            peer_version: PEER_VERSION,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: BurnQuotaConfig {
                inc: 21000,
                dec_num: 4,
                dec_den: 5
            },
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: 12300,
            first_block_hash: first_burn_hash.clone(),
        };

        let chain_view = BurnchainView {
            burn_block_height: 12348,
            burn_consensus_hash: ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
            burn_stable_block_height: 12341,
            burn_stable_consensus_hash: ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap()
        };
        
        let mut peerdb_1 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        let mut peerdb_2 = PeerDB::connect_memory(0x9abcdef0, 12351, &vec![], &vec![]).unwrap();
        
        let mut burndb_1 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();
        let mut burndb_2 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();

        db_setup(&mut peerdb_1, &mut burndb_1, &socketaddr_1, &chain_view);
        db_setup(&mut peerdb_2, &mut burndb_2, &socketaddr_2, &chain_view);

        let local_peer_1 = PeerDB::get_local_peer(&peerdb_1.conn()).unwrap();
        let local_peer_2 = PeerDB::get_local_peer(&peerdb_2.conn()).unwrap();

        let mut convo_1 = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);
        let mut convo_2 = Conversation::new(&burnchain, &socketaddr_1, &conn_opts, true, 0);
       
        // no peer public keys known yet
        assert!(convo_1.connection.get_public_key().is_none());
        assert!(convo_2.connection.get_public_key().is_none());
        
        // convo_1 sends a _stale_ handshake to convo_2 (wrong public key)
        let mut handshake_data_1 = HandshakeData::from_local_peer(&local_peer_1);
        handshake_data_1.expire_block_height = 12340;
        let handshake_1 = convo_1.sign_message(&chain_view, &local_peer_1.private_key, StacksMessageType::Handshake(handshake_data_1.clone())).unwrap();

        let rh_1 = convo_1.send_signed_message(handshake_1, 1000000).unwrap();

        // convo_2 receives it and processes it, and since no one is waiting for it, will forward
        // it along to the chat caller (us)
        convo_recv(&mut convo_2, convo_send(&mut convo_1));
        let unhandled_2 = convo_2.chat(&local_peer_2, burndb_2.conn(), &chain_view).unwrap();

        // convo_1 has a handshakreject
        convo_recv(&mut convo_1, convo_send(&mut convo_2));
        let unhandled_1 = convo_1.chat(&local_peer_1, burndb_1.conn(), &chain_view).unwrap();

        let reply_1 = rh_1.recv(0).unwrap();

        assert_eq!(unhandled_1.len(), 0);
        assert_eq!(unhandled_2.len(), 1);

        // convo 2 returns the handshake from convo 1
        match unhandled_2[0].payload {
            StacksMessageType::Handshake(ref data) => {
                assert_eq!(handshake_data_1, *data);
            },
            _ => {
                assert!(false);
            }
        };

        // received a valid HandshakeReject from peer 2 
        match reply_1.payload {
            StacksMessageType::HandshakeReject => {},
            _ => {
                assert!(false);
            }
        };

        // neither peer updated their info on one another 
        assert!(convo_1.connection.get_public_key().is_none());
        assert!(convo_2.connection.get_public_key().is_none());
    }

    #[test]
    fn convo_handshake_badsignature() {
        let conn_opts = ConnectionOptions::default();
        let socketaddr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let socketaddr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8081);
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        
        let burnchain = Burnchain {
            peer_version: PEER_VERSION,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: BurnQuotaConfig {
                inc: 21000,
                dec_num: 4,
                dec_den: 5
            },
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: 12300,
            first_block_hash: first_burn_hash.clone(),
        };

        let chain_view = BurnchainView {
            burn_block_height: 12348,
            burn_consensus_hash: ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
            burn_stable_block_height: 12341,
            burn_stable_consensus_hash: ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap()
        };
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let mut peerdb_1 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        let mut peerdb_2 = PeerDB::connect_memory(0x9abcdef0, 12351, &vec![], &vec![]).unwrap();
        
        let mut burndb_1 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();
        let mut burndb_2 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();

        db_setup(&mut peerdb_1, &mut burndb_1, &socketaddr_1, &chain_view);
        db_setup(&mut peerdb_2, &mut burndb_2, &socketaddr_2, &chain_view);

        let local_peer_1 = PeerDB::get_local_peer(&peerdb_1.conn()).unwrap();
        let local_peer_2 = PeerDB::get_local_peer(&peerdb_2.conn()).unwrap();

        let mut convo_1 = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);
        let mut convo_2 = Conversation::new(&burnchain, &socketaddr_1, &conn_opts, true, 0);
       
        // no peer public keys known yet
        assert!(convo_1.connection.get_public_key().is_none());
        assert!(convo_2.connection.get_public_key().is_none());
        
        // convo_1 sends an _invalid_ handshake to convo_2 (bad signature)
        let handshake_data_1 = HandshakeData::from_local_peer(&local_peer_1);
        let mut handshake_1 = convo_1.sign_message(&chain_view, &local_peer_1.private_key, StacksMessageType::Handshake(handshake_data_1.clone())).unwrap();
        match handshake_1.payload {
            StacksMessageType::Handshake(ref mut data) => {
                data.expire_block_height += 1;
            },
            _ => panic!()
        };

        let rh_1 = convo_1.send_signed_message(handshake_1, 1000000).unwrap();

        // convo_2 receives it and processes it, and barfs
        convo_recv(&mut convo_2, convo_send(&mut convo_1));
        let unhandled_2_err = convo_2.chat(&local_peer_2, burndb_2.conn(), &chain_view);

        // convo_1 gets a nack and consumes it
        convo_recv(&mut convo_1, convo_send(&mut convo_2));
        let unhandled_1 = convo_1.chat(&local_peer_1, burndb_1.conn(), &chain_view).unwrap();

        // the waiting reply aborts on disconnect
        let reply_1_err = rh_1.recv(0);

        assert_eq!(unhandled_2_err, Err(net_error::InvalidMessage));
        assert_eq!(reply_1_err, Err(net_error::ConnectionBroken));

        assert_eq!(unhandled_1.len(), 0);

        // neither peer updated their info on one another 
        assert!(convo_1.connection.get_public_key().is_none());
        assert!(convo_2.connection.get_public_key().is_none());
    }
    
    #[test]
    fn convo_handshake_self() {
        let conn_opts = ConnectionOptions::default();
        let socketaddr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let socketaddr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8081);
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        
        let burnchain = Burnchain {
            peer_version: PEER_VERSION,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: BurnQuotaConfig {
                inc: 21000,
                dec_num: 4,
                dec_den: 5
            },
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: 12300,
            first_block_hash: first_burn_hash.clone(),
        };

        let chain_view = BurnchainView {
            burn_block_height: 12348,
            burn_consensus_hash: ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
            burn_stable_block_height: 12341,
            burn_stable_consensus_hash: ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap()
        };
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let mut peerdb_1 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        let mut peerdb_2 = PeerDB::connect_memory(0x9abcdef0, 12351, &vec![], &vec![]).unwrap();
        
        let mut burndb_1 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();
        let mut burndb_2 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();

        db_setup(&mut peerdb_1, &mut burndb_1, &socketaddr_1, &chain_view);
        db_setup(&mut peerdb_2, &mut burndb_2, &socketaddr_2, &chain_view);

        let local_peer_1 = PeerDB::get_local_peer(&peerdb_1.conn()).unwrap();
        let local_peer_2 = PeerDB::get_local_peer(&peerdb_2.conn()).unwrap();

        let mut convo_1 = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);
        let mut convo_2 = Conversation::new(&burnchain, &socketaddr_1, &conn_opts, true, 0);
       
        // no peer public keys known yet
        assert!(convo_1.connection.get_public_key().is_none());
        assert!(convo_2.connection.get_public_key().is_none());
       
        // convo_1 sends a handshake to itself (not allowed)
        let handshake_data_1 = HandshakeData::from_local_peer(&local_peer_2);
        let handshake_1 = convo_1.sign_message(&chain_view, &local_peer_2.private_key, StacksMessageType::Handshake(handshake_data_1.clone())).unwrap();
        let rh_1 = convo_1.send_signed_message(handshake_1, 1000000).unwrap();

        // convo_2 receives it and processes it, and give back a handshake reject
        convo_recv(&mut convo_2, convo_send(&mut convo_1));
        let unhandled_2 = convo_2.chat(&local_peer_2, burndb_2.conn(), &chain_view).unwrap();

        // convo_1 gets a handshake reject and consumes it
        convo_recv(&mut convo_1, convo_send(&mut convo_2));
        let unhandled_1 = convo_1.chat(&local_peer_1, burndb_1.conn(), &chain_view).unwrap();

        // get back handshake reject
        let reply_1 = rh_1.recv(0).unwrap();

        assert_eq!(unhandled_1.len(), 0);
        assert_eq!(unhandled_2.len(), 1);

        // convo 2 returns the handshake from convo 1
        match unhandled_2[0].payload {
            StacksMessageType::Handshake(ref data) => {
                assert_eq!(handshake_data_1, *data);
            },
            _ => {
                assert!(false);
            }
        };

        // received a valid HandshakeReject from peer 2 
        match reply_1.payload {
            StacksMessageType::HandshakeReject => {},
            _ => {
                assert!(false);
            }
        };

        // neither peer updated their info on one another 
        assert!(convo_1.connection.get_public_key().is_none());
        assert!(convo_2.connection.get_public_key().is_none());
    }

    #[test]
    fn convo_ping() {
        let conn_opts = ConnectionOptions::default();
        let socketaddr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let socketaddr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8081);
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let burnchain = Burnchain {
            peer_version: PEER_VERSION,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: BurnQuotaConfig {
                inc: 21000,
                dec_num: 4,
                dec_den: 5
            },
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: 12300,
            first_block_hash: first_burn_hash.clone(),
        };

        let chain_view = BurnchainView {
            burn_block_height: 12348,
            burn_consensus_hash: ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
            burn_stable_block_height: 12341,
            burn_stable_consensus_hash: ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap()
        };
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let mut peerdb_1 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        let mut peerdb_2 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        
        let mut burndb_1 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();
        let mut burndb_2 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();

        db_setup(&mut peerdb_1, &mut burndb_1, &socketaddr_1, &chain_view);
        db_setup(&mut peerdb_2, &mut burndb_2, &socketaddr_2, &chain_view);

        let local_peer_1 = PeerDB::get_local_peer(&peerdb_1.conn()).unwrap();
        let local_peer_2 = PeerDB::get_local_peer(&peerdb_2.conn()).unwrap();

        let mut convo_1 = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);
        let mut convo_2 = Conversation::new(&burnchain, &socketaddr_1, &conn_opts, true, 0);

        // convo_1 sends a handshake to convo_2
        let handshake_data_1 = HandshakeData::from_local_peer(&local_peer_1);
        let handshake_1 = convo_1.sign_message(&chain_view, &local_peer_1.private_key, StacksMessageType::Handshake(handshake_data_1.clone())).unwrap();
        let rh_handshake_1 = convo_1.send_signed_message(handshake_1, 1000000).unwrap();

        // convo_1 sends a ping to convo_2 
        let ping_data_1 = PingData::new();
        let ping_1 = convo_1.sign_message(&chain_view, &local_peer_1.private_key, StacksMessageType::Ping(ping_data_1.clone())).unwrap();
        let rh_ping_1 = convo_1.send_signed_message(ping_1, 1000000).unwrap();

        // convo_2 receives the handshake and ping and processes both, and since no one is waiting for the handshake, will forward
        // it along to the chat caller (us)
        convo_recv(&mut convo_2, convo_send(&mut convo_1));
        let unhandled_2 = convo_2.chat(&local_peer_2, burndb_2.conn(), &chain_view).unwrap();

        // convo_1 has a handshakeaccept 
        convo_recv(&mut convo_1, convo_send(&mut convo_2));
        let unhandled_1 = convo_1.chat(&local_peer_1, burndb_1.conn(), &chain_view).unwrap();

        let reply_handshake_1 = rh_handshake_1.recv(0).unwrap();
        let reply_ping_1 = rh_ping_1.recv(0).unwrap();

        assert_eq!(unhandled_1.len(), 0);
        assert_eq!(unhandled_2.len(), 1);   // only the handshake is given back.  the ping is consumed

        // convo 2 returns the handshake from convo 1
        match unhandled_2[0].payload {
            StacksMessageType::Handshake(ref data) => {
                assert_eq!(handshake_data_1, *data);
            },
            _ => {
                assert!(false);
            }
        };

        // convo 2 replied to convo 1 with a matching pong
        match reply_ping_1.payload {
            StacksMessageType::Pong(ref data) => {
                assert_eq!(data.nonce, ping_data_1.nonce);
            },
            _ => {
                assert!(false);
            }
        }
    }

    #[test]
    fn convo_handshake_ping_loop() {
        let conn_opts = ConnectionOptions::default();
        let socketaddr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let socketaddr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8081);
       
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        
        let burnchain = Burnchain {
            peer_version: PEER_VERSION,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: BurnQuotaConfig {
                inc: 21000,
                dec_num: 4,
                dec_den: 5
            },
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: 12300,
            first_block_hash: first_burn_hash.clone(),
        };

        let chain_view = BurnchainView {
            burn_block_height: 12348,
            burn_consensus_hash: ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
            burn_stable_block_height: 12341,
            burn_stable_consensus_hash: ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap()
        };
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let mut peerdb_1 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        let mut peerdb_2 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        
        let mut burndb_1 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();
        let mut burndb_2 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();

        db_setup(&mut peerdb_1, &mut burndb_1, &socketaddr_1, &chain_view);
        db_setup(&mut peerdb_2, &mut burndb_2, &socketaddr_2, &chain_view);

        let local_peer_1 = PeerDB::get_local_peer(&peerdb_1.conn()).unwrap();
        let local_peer_2 = PeerDB::get_local_peer(&peerdb_2.conn()).unwrap();

        let mut convo_1 = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);
        let mut convo_2 = Conversation::new(&burnchain, &socketaddr_1, &conn_opts, true, 0);

        for i in 0..5 {
            // do handshake/ping over and over, with different keys.
            // tests re-keying.

            // convo_1 sends a handshake to convo_2
            let handshake_data_1 = HandshakeData::from_local_peer(&local_peer_1);
            let handshake_1 = convo_1.sign_message(&chain_view, &local_peer_1.private_key, StacksMessageType::Handshake(handshake_data_1.clone())).unwrap();
            let rh_handshake_1 = convo_1.send_signed_message(handshake_1, 1000000).unwrap();

            // convo_1 sends a ping to convo_2 
            let ping_data_1 = PingData::new();
            let ping_1 = convo_1.sign_message(&chain_view, &local_peer_1.private_key, StacksMessageType::Ping(ping_data_1.clone())).unwrap();
            let rh_ping_1 = convo_1.send_signed_message(ping_1, 1000000).unwrap();

            // convo_2 receives the handshake and ping and processes both, and since no one is waiting for the handshake, will forward
            // it along to the chat caller (us)
            convo_recv(&mut convo_2, convo_send(&mut convo_1));
            let unhandled_2 = convo_2.chat(&local_peer_2, burndb_2.conn(), &chain_view).unwrap();

            // convo_1 has a handshakeaccept 
            convo_recv(&mut convo_1, convo_send(&mut convo_2));
            let unhandled_1 = convo_1.chat(&local_peer_1, burndb_1.conn(), &chain_view).unwrap();

            let reply_handshake_1 = rh_handshake_1.recv(0).unwrap();
            let reply_ping_1 = rh_ping_1.recv(0).unwrap();

            assert_eq!(unhandled_1.len(), 0);
            assert_eq!(unhandled_2.len(), 1);   // only the handshake is given back.  the ping is consumed

            // convo 2 returns the handshake from convo 1
            match unhandled_2[0].payload {
                StacksMessageType::Handshake(ref data) => {
                    assert_eq!(handshake_data_1, *data);
                },
                _ => {
                    assert!(false);
                }
            };

            // convo 2 replied to convo 1 with a matching pong
            match reply_ping_1.payload {
                StacksMessageType::Pong(ref data) => {
                    assert_eq!(data.nonce, ping_data_1.nonce);
                },
                _ => {
                    assert!(false);
                }
            }

            // received a valid HandshakeAccept from peer 2 
            match reply_handshake_1.payload {
                StacksMessageType::HandshakeAccept(ref data) => {
                    assert_eq!(data.handshake.addrbytes, local_peer_2.addrbytes);
                    assert_eq!(data.handshake.port, local_peer_2.port);
                    assert_eq!(data.handshake.services, local_peer_2.services);
                    assert_eq!(data.handshake.node_public_key, StacksPublicKeyBuffer::from_public_key(&Secp256k1PublicKey::from_private(&local_peer_2.private_key)));
                    assert_eq!(data.handshake.expire_block_height, local_peer_2.private_key_expire); 
                    assert_eq!(data.heartbeat_interval, conn_opts.heartbeat);
                },
                _ => {
                    assert!(false);
                }
            };

            // confirm that sequence numbers are increasing
            assert_eq!(reply_handshake_1.preamble.seq, 2*i);
            assert_eq!(reply_ping_1.preamble.seq, 2*i + 1);
            assert_eq!(convo_1.seq, 2*i + 2);

            // convo_2 got updated with convo_1's peer info, but no heartbeat info 
            assert_eq!(convo_2.peer_heartbeat, 0);
            assert_eq!(convo_2.connection.get_public_key().unwrap(), Secp256k1PublicKey::from_private(&local_peer_1.private_key));

            // convo_1 got updated with convo_2's peer info, as well as heartbeat
            assert_eq!(convo_1.peer_heartbeat, conn_opts.heartbeat);
            assert_eq!(convo_1.connection.get_public_key().unwrap(), Secp256k1PublicKey::from_private(&local_peer_2.private_key));

            // regenerate keys and expiries in peer 1
            let new_privkey = Secp256k1PrivateKey::new();
            {
                let mut tx = peerdb_1.tx_begin().unwrap();
                PeerDB::set_local_private_key(&mut tx, &new_privkey, (12350 + i) as u64).unwrap();
                tx.commit().unwrap();
            }
        }
    }

    #[test]
    fn convo_nack_unsolicited() {

        let conn_opts = ConnectionOptions::default();
        let socketaddr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let socketaddr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8081);
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let burnchain = Burnchain {
            peer_version: PEER_VERSION,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: BurnQuotaConfig {
                inc: 21000,
                dec_num: 4,
                dec_den: 5
            },
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: 12300,
            first_block_hash: first_burn_hash.clone(),
        };

        let chain_view = BurnchainView {
            burn_block_height: 12348,
            burn_consensus_hash: ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
            burn_stable_block_height: 12341,
            burn_stable_consensus_hash: ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap()
        };
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let mut peerdb_1 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        let mut peerdb_2 = PeerDB::connect_memory(0x9abcdef0, 12351, &vec![], &vec![]).unwrap();
        
        let mut burndb_1 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();
        let mut burndb_2 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();

        db_setup(&mut peerdb_1, &mut burndb_1, &socketaddr_1, &chain_view);
        db_setup(&mut peerdb_2, &mut burndb_2, &socketaddr_2, &chain_view);

        let local_peer_1 = PeerDB::get_local_peer(&peerdb_1.conn()).unwrap();
        let local_peer_2 = PeerDB::get_local_peer(&peerdb_2.conn()).unwrap();

        let mut convo_1 = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);
        let mut convo_2 = Conversation::new(&burnchain, &socketaddr_1, &conn_opts, true, 0);
       
        // no peer public keys known yet
        assert!(convo_1.connection.get_public_key().is_none());
        assert!(convo_2.connection.get_public_key().is_none());
        
        // convo_1 sends a ping to convo_2
        let ping_data_1 = PingData::new();
        let ping_1 = convo_1.sign_message(&chain_view, &local_peer_1.private_key, StacksMessageType::Ping(ping_data_1.clone())).unwrap();
        let rh_ping_1 = convo_1.send_signed_message(ping_1, 1000000).unwrap();

        // convo_2 will reply with a nack since peer_1 hasn't authenticated yet
        convo_recv(&mut convo_2, convo_send(&mut convo_1));
        let unhandled_2 = convo_2.chat(&local_peer_2, burndb_2.conn(), &chain_view).unwrap();

        // convo_1 has a nack 
        convo_recv(&mut convo_1, convo_send(&mut convo_2));
        let unhandled_1 = convo_1.chat(&local_peer_1, burndb_1.conn(), &chain_view).unwrap();

        let reply_1 = rh_ping_1.recv(0).unwrap();
       
        // convo_2 gives back nothing
        assert_eq!(unhandled_1.len(), 0);
        assert_eq!(unhandled_2.len(), 0);

        // convo_1 got a NACK 
        match reply_1.payload {
            StacksMessageType::Nack(ref data) => {
                assert_eq!(data.error_code, NackErrorCodes::HandshakeRequired);
            },
            _ => {
                assert!(false);
            }
        };

        // convo_2 did NOT get updated with convo_1's peer info
        assert_eq!(convo_2.peer_heartbeat, 0);
        assert!(convo_2.connection.get_public_key().is_none());

        // convo_1 did NOT get updated
        assert_eq!(convo_1.peer_heartbeat, 0);
        assert!(convo_2.connection.get_public_key().is_none());
    }

    #[test]
    fn convo_is_preamble_valid() {
        let conn_opts = ConnectionOptions::default();
        let socketaddr_1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let socketaddr_2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8081);
        
        let first_burn_hash = BurnchainHeaderHash::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap();

        let burnchain = Burnchain {
            peer_version: PEER_VERSION,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            burn_quota: BurnQuotaConfig {
                inc: 21000,
                dec_num: 4,
                dec_den: 5
            },
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height: 12300,
            first_block_hash: first_burn_hash.clone(),
        };

        let chain_view = BurnchainView {
            burn_block_height: 12348,
            burn_consensus_hash: ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
            burn_stable_block_height: 12341,
            burn_stable_consensus_hash: ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap()
        };

        let mut peerdb_1 = PeerDB::connect_memory(0x9abcdef0, 12350, &vec![], &vec![]).unwrap();
        let mut burndb_1 : BurnDB<BitcoinAddress, BitcoinPublicKey> = BurnDB::connect_memory(12300, &first_burn_hash).unwrap();
        
        db_setup(&mut peerdb_1, &mut burndb_1, &socketaddr_1, &chain_view);
        
        let local_peer_1 = PeerDB::get_local_peer(&peerdb_1.conn()).unwrap();
        
        // network ID check
        {
            let mut convo_bad = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);

            let ping_data = PingData::new();
            convo_bad.burnchain.network_id += 1;
            let ping_bad = convo_bad.sign_message(&chain_view, &local_peer_1.private_key, StacksMessageType::Ping(ping_data.clone())).unwrap();
            convo_bad.burnchain.network_id -= 1;

            assert_eq!(convo_bad.is_preamble_valid(&ping_bad, burndb_1.conn()), Err(net_error::InvalidMessage));
        }

        // stable block height check
        {
            let mut convo_bad = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);

            let ping_data = PingData::new();
            
            let mut chain_view_bad = chain_view.clone();
            chain_view_bad.burn_stable_block_height -= 1;

            let ping_bad = convo_bad.sign_message(&chain_view_bad, &local_peer_1.private_key, StacksMessageType::Ping(ping_data.clone())).unwrap();

            assert_eq!(convo_bad.is_preamble_valid(&ping_bad, burndb_1.conn()), Err(net_error::InvalidMessage));
        }

        // node is too far ahead of us
        {
            let mut convo_bad = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);

            let ping_data = PingData::new();
            
            let mut chain_view_bad = chain_view.clone();
            chain_view_bad.burn_stable_block_height += 1 + burnchain.stable_confirmations as u64;
            chain_view_bad.burn_block_height += 1 + burnchain.stable_confirmations as u64;

            let ping_bad = convo_bad.sign_message(&chain_view_bad, &local_peer_1.private_key, StacksMessageType::Ping(ping_data.clone())).unwrap();
            
            chain_view_bad.burn_stable_block_height -= 1 + burnchain.stable_confirmations as u64;
            chain_view_bad.burn_block_height -= 1 + burnchain.stable_confirmations as u64;
            
            db_setup(&mut peerdb_1, &mut burndb_1, &socketaddr_2, &chain_view_bad);
            
            assert_eq!(convo_bad.is_preamble_valid(&ping_bad, burndb_1.conn()), Ok(false));
        }

        // unstable consensus hash mismatch
        {
            let mut convo_bad = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);

            let ping_data = PingData::new();
            
            let mut chain_view_bad = chain_view.clone();
            let old = chain_view_bad.burn_consensus_hash.clone();
            chain_view_bad.burn_consensus_hash = ConsensusHash::from_hex("3333333333333333333333333333333333333333").unwrap();

            let ping_bad = convo_bad.sign_message(&chain_view_bad, &local_peer_1.private_key, StacksMessageType::Ping(ping_data.clone())).unwrap();
            
            assert_eq!(convo_bad.is_preamble_valid(&ping_bad, burndb_1.conn()), Ok(false));
        }

        // stable consensus hash mismatch 
        {
            let mut convo_bad = Conversation::new(&burnchain, &socketaddr_2, &conn_opts, true, 0);

            let ping_data = PingData::new();
            
            let mut chain_view_bad = chain_view.clone();
            let old = chain_view_bad.burn_stable_consensus_hash.clone();
            chain_view_bad.burn_stable_consensus_hash = ConsensusHash::from_hex("1111111111111111111111111111111111111112").unwrap();

            let ping_bad = convo_bad.sign_message(&chain_view_bad, &local_peer_1.private_key, StacksMessageType::Ping(ping_data.clone())).unwrap();
            
            assert_eq!(convo_bad.is_preamble_valid(&ping_bad, burndb_1.conn()), Err(net_error::InvalidMessage));
        }
    }
}
