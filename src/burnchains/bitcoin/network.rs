/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

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

use std::time::{UNIX_EPOCH, SystemTime};
use std::io;
use std::io::Write;
use std::net::SocketAddr;
use std::time;
use std::thread;

use rand::{Rng, thread_rng};

use bitcoin::blockdata::block::{BlockHeader, LoneBlockHeader};
use bitcoin::network::address as btc_network_address;
use bitcoin::network::constants as btc_constants;
use bitcoin::network::encodable::{ConsensusEncodable, ConsensusDecodable, VarInt};
use bitcoin::network::message as btc_message;
use bitcoin::network::message_network as btc_message_network;
use bitcoin::network::message_blockdata as btc_message_blockdata;
use bitcoin::network::serialize as btc_serialize;
use bitcoin::network::serialize::{RawEncoder, RawDecoder, BitcoinHash};
use bitcoin::util::hash::Sha256dHash;

use burnchains::bitcoin::Error as btc_error;
use burnchains::bitcoin::indexer::BitcoinIndexer;
use burnchains::bitcoin::spv;
use burnchains::indexer::BurnchainIndexer;
use burnchains::bitcoin::messages::BitcoinMessageHandler;

// Borrowed from Andrew Poelstra's rust-bitcoin library.
/// Lock the socket in the BitcoinIndexer's runtime state and do something with it.
///
/// $s -- BitcoinIndexer.runtime (something with .socket as Arc<Mutex<Option<net::TcpSocket>>>)
/// $sock -- name of locked socket object in $body
/// $body -- code to execute with locked $sock
macro_rules! with_socket(($s:ident, $sock:ident, $body:block) => ({
    use ::std::ops::DerefMut;
    let sock_lock = $s.socket_locked();
    match sock_lock {
        Err(_) => {
            Err(btc_error::SocketMutexPoisoned.into())
        }
        Ok(mut guard) => {
            match *guard.deref_mut() {
                Some(ref mut $sock) => {
                    $body
                }
                None => {
                    Err(btc_error::SocketNotConnectedToPeer.into())
                }
            }
        }
    }
}));

impl BitcoinIndexer {
    
    // Based on Andrew Poelstra's rust-bitcoin library.
    /// Send a Bitcoin protocol message on the wire
    pub fn send_message(&mut self, payload: btc_message::NetworkMessage) -> Result<(), btc_error> {
        let message = btc_message::RawNetworkMessage {
            magic: self.runtime.magic,
            payload: payload 
        };

        with_socket!(self, sock, {
            message.consensus_encode(&mut RawEncoder::new(&mut *sock))
                .map_err(btc_error::SerializationError)?;
            sock.flush().map_err(btc_error::Io)
        })
    }

    /// Receive a Bitcoin protocol message on the wire
    /// If this method returns Err(ConnectionBroken), then the caller should attempt to re-connect.
    pub fn recv_message(&mut self) -> Result<btc_message::NetworkMessage, btc_error> {
        let magic = self.runtime.magic;

        with_socket!(self, sock, {
            // read the message off the wire
            let mut decoder = RawDecoder::new(sock);

            let decoded: btc_message::RawNetworkMessage = ConsensusDecodable::consensus_decode(&mut decoder)
                .map_err(|e| {
                    // if we can't finish a recv(), then report that the connection is broken
                    match e {
                        btc_serialize::Error::Io(ref io_error) => {
                            if io_error.kind() == io::ErrorKind::UnexpectedEof {
                                btc_error::ConnectionBroken
                            }
                            else {
                                btc_error::Io(io::Error::new(io_error.kind(), "I/O error when processing message"))
                            }
                        }
                        _ => {
                            btc_error::SerializationError(e)
                        }
                    }
                })?;

            // sanity check -- must match our network 
            if decoded.magic != magic {
                return Err(btc_error::InvalidMagic);
            }

            Ok(decoded.payload)
        })
    }

    /// Get sender address from our socket 
    pub fn get_local_sockaddr(&mut self) -> Result<SocketAddr, btc_error> {
        with_socket!(self, sock, {
            match sock.local_addr() {
                Ok(addr) => {
                    return Ok(addr);
                }
                Err(e) => {
                    return Err(btc_error::Io(e));
                }
            }
        })
    }

    /// Get receiver address from our socket 
    pub fn get_remote_sockaddr(&mut self) -> Result<SocketAddr, btc_error> {
        with_socket!(self, sock, {
            match sock.peer_addr() {
                Ok(addr) => {
                    return Ok(addr);
                }
                Err(e) => {
                    return Err(btc_error::Io(e));
                }
            }
        })
    }

    /// Handle a message we received, if we can.
    /// Returns UnhandledMessage if we can't handle the given message.
    pub fn handle_message<T: BitcoinMessageHandler>(&mut self, message: &btc_message::NetworkMessage, handler: Option<&mut T>) -> Result<bool, btc_error> {
        match *message {
            btc_message::NetworkMessage::Version(ref msg_body) => {
                self.handle_version(message)
                    .and_then(|_r| Ok(true))
            }
            btc_message::NetworkMessage::Verack => {
                self.handle_verack(message)
                    .and_then(|_r| Ok(true))
            }
            btc_message::NetworkMessage::Ping(ref nonce) => {
                self.handle_ping(message)
                    .and_then(|_r| Ok(true))
            }
            btc_message::NetworkMessage::Pong(ref nonce) => {
                self.handle_pong(message, *nonce)
                    .and_then(|_r| Ok(true))
            }
            _ => {
                match handler {
                    Some(mut custom_handler) => {
                        custom_handler.handle_message(self, message)
                    }
                    None => {
                        Err(btc_error::UnhandledMessage)
                    }
                }
            }
        }
    }

    /// Do the initial handshake to the remote peer
    pub fn peer_handshake(&mut self) -> Result<(), btc_error> {
        debug!("Begin peer handshake to {}:{}", self.config.peer_host, self.config.peer_port);
        self.send_version()?;
        let version_reply = self.recv_message()?;
        self.handle_version(&version_reply)?;
        
        let verack_reply = self.recv_message()?;
        self.handle_verack(&verack_reply)?;

        debug!("Established connection to {}:{}", self.config.peer_host, self.config.peer_port);
        return Ok(());
    }


    /// Connect to a remote peer, do a handshake with the remote peer, and use exponential backoff until we
    /// succeed in establishing a connection.
    /// This method masks ConnectionBroken errors, but does not mask other network errors.
    pub fn connect_handshake_backoff(&mut self, network_name: &str) -> Result<(), btc_error> {
        let mut backoff: f64 = 0.0;
        let mut rng = thread_rng();

        loop {
            let connection_result = self.connect(network_name);
            match connection_result {
                Ok(()) => {
                    // connected!  now do the handshake 
                    let handshake_result = self.peer_handshake();
                    match handshake_result {
                        Ok(()) => {
                            // connected!
                            return handshake_result;
                        }
                        Err(btc_error::ConnectionBroken) => {
                            // need to try again
                            backoff = 2.0 * backoff + (backoff * rng.gen_range(0.0, 1.0));
                        }
                        Err(_) => {
                            // propagate other network error
                            return handshake_result;
                        }
                    }
                }
                Err(err_msg) => {
                    error!("Failed to connect to peer: {}", err_msg);
                    backoff = 2.0 * backoff + (backoff * rng.gen_range(0.0, 1.0));
                }
            }

            // do backoff of we get here
            warn!("Connection broken; retrying in {} sec...", backoff);

            // don't sleep more than 10 min
            if backoff > 600.0 {
                backoff = 600.0;
            }

            let sleep_sec = backoff as u64;
            let sleep_nsec = (((backoff - (sleep_sec as f64)) as u64) * 1_000_000) as u32;
            let duration = time::Duration::new(sleep_sec, sleep_nsec);
            thread::sleep(duration);
        }
    }

    /// Send a Version message 
    pub fn send_version(&mut self) -> Result<(), btc_error> {
        let timestamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(dur) => dur,
            Err(err) => err.duration(),
        }.as_secs() as i64;

        let local_addr = self.get_local_sockaddr()?;
        let remote_addr = self.get_remote_sockaddr()?;

        let sender_address = btc_network_address::Address::new(&local_addr, 0);
        let remote_address = btc_network_address::Address::new(&remote_addr, 0);

        let payload = btc_message_network::VersionMessage {
            version: btc_constants::PROTOCOL_VERSION,
            services: 0,
            timestamp: timestamp,
            receiver: remote_address,
            sender: sender_address,
            nonce: self.runtime.version_nonce,
            user_agent: self.runtime.user_agent.to_owned(),
            start_height: 0,
            relay: false
        };

        debug!("Send version (nonce={}) to {}:{}", self.runtime.version_nonce, self.config.peer_host, self.config.peer_port);
        return self.send_message(btc_message::NetworkMessage::Version(payload));
    }

    /// Receive a Version message and reply with a Verack
    pub fn handle_version(&mut self, version_message: &btc_message::NetworkMessage) -> Result<(), btc_error> {
        match *version_message {
            btc_message::NetworkMessage::Version(ref msg_body) => {
                debug!("Handle version");
                return self.send_verack();
            }
            _ => {
                error!("Did not receive version, but got {:?}", *version_message);
                return Err(btc_error::InvalidMessage);
            }
        }
    }

    /// Send a verack 
    pub fn send_verack(&mut self) -> Result<(), btc_error> {
        let payload = btc_message::NetworkMessage::Verack;

        debug!("Send verack");
        return self.send_message(payload);
    }

    /// Handle a verack we received.
    /// Does nothing.
    pub fn handle_verack(&mut self, verack_message: &btc_message::NetworkMessage) -> Result<(), btc_error> {
        match *verack_message {
            btc_message::NetworkMessage::Verack => {
                debug!("Handle verack");
                return Ok(());
            }
            _ => {
                error!("Did not receive verack, but got {:?}", *verack_message);
                return Err(btc_error::InvalidMessage);
            }
        }
    }

    /// Send a ping message 
    pub fn send_ping(&mut self, nonce: u64) -> Result<(), btc_error> {
        let payload = btc_message::NetworkMessage::Ping(nonce);

        debug!("Send ping {} to {}:{}", nonce, self.config.peer_host, self.config.peer_port);
        return self.send_message(payload);
    }

    /// Respond to a Ping message by sending a Pong message 
    pub fn handle_ping(&mut self, ping_message: &btc_message::NetworkMessage) -> Result<(), btc_error> {
        match *ping_message {
            btc_message::NetworkMessage::Ping(ref n) => {
                debug!("Handle ping {}", *n);
                let payload = btc_message::NetworkMessage::Pong(*n);
        
                debug!("Send pong {}", *n);
                return self.send_message(payload);
            }
            _ => {
                error!("Did not receive ping, but got {:?}", *ping_message);
                return Err(btc_error::InvalidMessage);
            }
        }
    }
    
    /// Respond to a Pong message.
    /// Does nothing.
    pub fn handle_pong(&mut self, pong_message: &btc_message::NetworkMessage, expected_nonce: u64) -> Result<(), btc_error> {
        match *pong_message {
            btc_message::NetworkMessage::Pong(ref n) => {
                if expected_nonce != *n {
                    return Err(btc_error::InvalidReply);
                }

                debug!("Handle pong {}", *n);
                return Ok(());
            }
            _ => {
                error!("Did not receive pong, but got {:?}", *pong_message);
                return Err(btc_error::InvalidReply);
            }
        }
    }

    /// Send a GetHeaders message
    /// Note that this isn't a generic GetHeaders message -- you should use this only to ask
    /// for a batch of 2,000 block hashes after this given hash.
    pub fn send_getheaders(&mut self, prev_block_hash: Sha256dHash) -> Result<(), btc_error> {
        let getheaders = btc_message_blockdata::GetHeadersMessage::new(vec![prev_block_hash], prev_block_hash);
        let payload = btc_message::NetworkMessage::GetHeaders(getheaders);

        debug!("Send GetHeaders {} to {}:{}", prev_block_hash.be_hex_string(), self.config.peer_host, self.config.peer_port);
        return self.send_message(payload);
    }
}
