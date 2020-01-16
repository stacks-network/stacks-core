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

use std::net;
use std::io;
use std::io::{Read, Write};
use std::io::ErrorKind as IoErrorKind;
use std::ops::Deref;
use std::ops::DerefMut;
use std::time::Duration;
use std::collections::VecDeque;

use std::sync::mpsc::sync_channel;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError;
use std::sync::mpsc::RecvError;
use std::sync::mpsc::RecvTimeoutError;

use mio;
use mio::net as mio_net;

use net::Error as net_error;
use net::StacksMessageCodec;
use net::Preamble;
use net::HttpRequestPreamble;
use net::HttpResponsePreamble;
use net::NetworkPreamble;
use net::RelayData;
use net::PeerAddress;
use net::ProtocolFamily;
use net::StacksP2P;
use net::MessageSequence;
use net::codec::*;
use net::MAX_MESSAGE_LEN;

use chainstate::burn::ConsensusHash;

use util::log;
use util::secp256k1::Secp256k1PublicKey;
use util::get_epoch_time_secs;
use util::sleep_ms;
use util::hash::to_hex;

/// Receiver notification handle.
/// When a message with the expected `seq` value arrives, send it to an expected receiver (possibly
/// in another thread) via the given `receiver_input` channel.
#[derive(Debug)]
struct ReceiverNotify<P: ProtocolFamily> {
    expected_seq: u32,
    receiver_input: SyncSender<P::Message>,
    ttl: u64        // absolute deadline by which this message needs a reply (in seconds since the epoch)
}

impl<P: ProtocolFamily> ReceiverNotify<P> {
    pub fn new(seq: u32, input: SyncSender<P::Message>, ttl: u64) -> ReceiverNotify<P> {
        ReceiverNotify {
            expected_seq: seq,
            receiver_input: input,
            ttl: ttl
        }
    }

    /// Send this message to the waiting receiver, consuming this notification handle.
    /// May fail silently.
    pub fn send(self, msg: P::Message) -> () {
        match self.receiver_input.send(msg) {
            Ok(_) => {},
            Err(e) => {}
        }
    }
}

/// Opaque structure for waiting or a reply.  Contains the other end of a ReceiverNotify.
#[derive(Debug)]
pub struct NetworkReplyHandle<P: ProtocolFamily> {
    receiver_output: Receiver<P::Message>
}

impl<P: ProtocolFamily> NetworkReplyHandle<P> {
    pub fn new(output: Receiver<P::Message>) -> NetworkReplyHandle<P> {
        NetworkReplyHandle {
            receiver_output: output
        }
    }

    /// Poll on this handle.
    /// Consumes this handle if it succeeds in getting a message.
    /// Returns itself if there is no pending message.
    pub fn try_recv(self) -> Result<P::Message, Result<NetworkReplyHandle<P>, net_error>> {
        let res = self.receiver_output.try_recv();
        match res {
            Ok(message) => Ok(message),
            Err(TryRecvError::Empty) => Err(Ok(self)),      // try again,
            Err(TryRecvError::Disconnected) => Err(Err(net_error::ConnectionBroken))
        }
    }

    /// Receive the outstanding message from our peer within the allotted time (pass -1 for "wait forever").
    /// Destroys the NetworkReplyHandle in the process.  You can only call this once!
    /// Timeout is in seconds.
    pub fn recv(self, timeout: i64) -> Result<P::Message, net_error> {
        if timeout < 0 {
            self.receiver_output.recv()
                .map_err(|_e| net_error::ConnectionBroken)
        }
        else {
            self.receiver_output.recv_timeout(Duration::new(timeout as u64, 0))
                .map_err(|_e| net_error::ConnectionBroken)
        } 
    }
}

/// In-flight message to a remote peer.
/// When a reply is received, it may be forwarded along to an optional ReceiverNotify.
#[derive(Debug)]
struct InflightMessage<P: ProtocolFamily> {
    message: P::Message,
    notify: Option<ReceiverNotify<P>>
}

#[derive(Debug)]
struct ConnectionInbox<P: ProtocolFamily> {
    public_key: Option<Secp256k1PublicKey>,

    // completely-parsed incoming messages that do _not_ get sent out to a waiting receiver 
    inbox: VecDeque<P::Message>,
    inbox_maxlen: usize,    // this is a _soft_ limit -- it's possible for inbox to exceed this by a fixed quantity

    // partially-parsed incoming messages
    preamble: Option<NetworkPreamble>,
    preamble_data: Vec<u8>,
    message_data: Vec<u8>,
}

#[derive(Debug)]
struct ConnectionOutbox<P: ProtocolFamily> {
    // message to send
    outbox: VecDeque<InflightMessage<P>>,
    outbox_maxlen: usize,
    socket_out_buf: Vec<u8>,
    socket_out_ptr: u32,

    // in-flight messages 
    inflight: VecDeque<ReceiverNotify<P>>
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionOptions {
    pub keepalive: u64,
    pub nodelay: bool,
    pub inbox_maxlen: usize,
    pub outbox_maxlen: usize,
    pub timeout: u64,
    pub heartbeat: u32,
    pub private_key_lifetime: u64,
    pub num_neighbors: u64,
    pub num_clients: u64,
    pub soft_num_neighbors: u64,
    pub soft_num_clients: u64,
    pub max_neighbors_per_host: u64,
    pub max_clients_per_host: u64,
    pub soft_max_neighbors_per_host: u64,
    pub soft_max_neighbors_per_org: u64,
    pub soft_max_clients_per_host: u64,
    pub walk_interval: u64,
}

impl std::default::Default for ConnectionOptions {
    fn default() -> ConnectionOptions {
        ConnectionOptions {
            keepalive: 60,
            nodelay: true,
            inbox_maxlen: 5,
            outbox_maxlen: 5,
            timeout: 30,
            heartbeat: 2592000,
            private_key_lifetime: 4302,
            num_neighbors: 32,              // how many outbound connections we can have, full-stop
            num_clients: 256,               // how many inbound connections we can have, full-stop
            soft_num_neighbors: 20,         // how many outbound connections we can have, before we start pruning them
            soft_num_clients: 128,          // how many inbound connections we can have, before we start pruning them
            max_neighbors_per_host: 10,     // how many outbound connections we can have per IP address, full-stop
            max_clients_per_host: 10,       // how many inbound connections we can have per IP address, full-stop
            soft_max_neighbors_per_host: 10,     // how many outbound connections we can have per IP address, before we start pruning them
            soft_max_neighbors_per_org: 10,      // how many outbound connections we can have per AS-owning organization, before we start pruning them
            soft_max_clients_per_host: 10,       // how many inbound connections we can have per IP address, before we start pruning them,
            walk_interval: 300,             // how often to do a neighbor walk
        }
    }
}

#[derive(Debug)]
pub struct NetworkConnection<P: ProtocolFamily> {
    pub options: ConnectionOptions,

    inbox: ConnectionInbox<P>,
    outbox: ConnectionOutbox<P>
}

impl<P: ProtocolFamily> ConnectionInbox<P> {
    pub fn new(max_messages: usize, public_key_opt: Option<Secp256k1PublicKey>) -> ConnectionInbox<P> {
        ConnectionInbox {
            public_key: public_key_opt,
            inbox: VecDeque::with_capacity(max_messages),
            inbox_maxlen: max_messages,
            preamble: None,
            preamble_data: vec![],
            message_data: vec![]
        }
    }

    /// Fill up the preamble buffer, up to P::preamble_size_hint().
    /// Return the number of bytes consumed.
    fn buffer_preamble_bytes(&mut self, bytes: &[u8]) -> usize {
        let max_preamble_len = P::preamble_size_hint();
        if self.preamble_data.len() >= max_preamble_len {
            return 0;
        }

        let to_consume = 
            if self.preamble_data.len() + bytes.len() <= max_preamble_len {
                bytes.len()
            }
            else {
                max_preamble_len - self.preamble_data.len() 
            };

        self.preamble_data.extend_from_slice(&bytes[0..to_consume]);
        to_consume
    }

    /// try to consume buffered data to form a message preamble.
    /// returns an option of the preamble consumed and the number of bytes used from the bytes slice
    fn consume_preamble(&mut self, bytes: &[u8]) -> Result<(Option<NetworkPreamble>, usize), net_error> {
        let bytes_consumed = self.buffer_preamble_bytes(bytes);
        let preamble_opt = match P::read_preamble(&self.preamble_data) {
            Ok((preamble, preamble_len)) => {
                assert!((preamble_len as u32) < MAX_MESSAGE_LEN);
                if preamble.payload_length() as u32 >= MAX_MESSAGE_LEN - (preamble_len as u32) {
                    // message would be too big
                    return Err(net_error::DeserializeError(format!("Preamble payload length {} is too big", preamble.payload_length())));
                }

                // buffer up next message 
                self.message_data.extend_from_slice(&self.preamble_data[preamble_len..]);
                self.preamble_data.clear();
                Some(preamble)
            },
            Err(net_error::DeserializeError(errmsg)) => {
                // will never be valid
                debug!("Invalid message preamble: {}", &errmsg);
                return Err(net_error::InvalidMessage);
            },
            Err(net_error::UnderflowError(_)) => {
                // not enough data to form a preamble
                if bytes_consumed == 0 {
                    // preamble is too long
                    return Err(net_error::DeserializeError("Preamble size would exceed maximum allowed size".to_string()));
                }

                None
            },
            Err(e) => {
                // other
                return Err(e);
            }
        };
        Ok((preamble_opt, bytes_consumed))
    }

    /// buffer up bytes for a message
    fn buffer_message_bytes(&mut self, bytes: &[u8], message_len: usize) -> usize {
        let to_consume = 
            if self.message_data.len() + bytes.len() <= message_len {
                bytes.len()
            }
            else {
                message_len - self.message_data.len()
            };

        self.message_data.extend_from_slice(&bytes[0..to_consume]);
        to_consume
    }

    /// Try to consume bufferred data to form a message
    fn consume_payload(&mut self, preamble: &mut NetworkPreamble, bytes: &[u8]) -> Result<(Option<P::Message>, usize), net_error> {
        let bytes_consumed = self.buffer_message_bytes(bytes, preamble.payload_length());
        assert!(self.message_data.len() <= preamble.payload_length());

        if self.message_data.len() == preamble.payload_length() {
            if let Some(ref pubk) = self.public_key {
                preamble.verify_payload(&self.message_data[0..preamble.payload_length()], pubk)?;
            }
            let message = match P::read_payload(preamble, &self.message_data) {
                Ok(message) => {
                    self.message_data.clear();
                    message
                },
                Err(e) => {
                    // will never be valid, even if underflowed, since the premable ought to have
                    // told us the message length
                    debug!("Invalid message payload: {:?}", &e);
                    return Err(net_error::InvalidMessage);
                }
            };
            Ok((Some(message), bytes_consumed))
        }
        else {
            // not enough data yet
            Ok((None, bytes_consumed))
        }
    }

    /// Consume messages while we have space in our inbox.
    /// It is possible for this method to append more messages to the inbox than inbox_maxsize.
    /// However, since only so many messages can fit into buf, the number of messages that can be
    /// inserted into the inbox beyond inbox_maxsize is still limited.  Subsequent calls to
    /// recv_bytes() will prevent more data from being read from the socket until the messages are
    /// dequeued.
    ///
    /// Returns nothing on success, and enqueues zero or more messages into our inbox.
    /// Returns net_error::InvalidMessage if a message could not be parsed or authenticated.
    fn consume_messages(&mut self, buf: &[u8]) -> Result<(), net_error> {
        let mut offset = 0;
        loop {
            if self.inbox.len() > self.inbox_maxlen {
                return Err(net_error::InboxOverflow);
            }

            let bytes_consumed_preamble = 
                if self.preamble.is_none() {
                    let (preamble_opt, bytes_consumed) = self.consume_preamble(&buf[offset..])?;
                    self.preamble = preamble_opt;
                    bytes_consumed
                }
                else {
                    0
                };
            
            offset += bytes_consumed_preamble;
            if offset == buf.len() {
                break;
            }

            let mut consumed_message = false;
            let bytes_consumed_message = {
                let mut preamble_opt = self.preamble.take();
                let bytes_consumed =
                    if let Some(ref mut preamble) = preamble_opt {
                        let (message_opt, bytes_consumed) = self.consume_payload(preamble, &buf[offset..])?;
                        match message_opt {
                            Some(message) => {
                                // queue up
                                self.inbox.push_back(message);
                                consumed_message = true;
                            },
                            None => {}
                        };
                        
                        bytes_consumed
                    }
                    else {
                        0
                    };

                self.preamble = preamble_opt;
                bytes_consumed
            };

            if consumed_message {
                self.preamble = None;
            }

            offset += bytes_consumed_message;
            if offset == buf.len() {
                break;
            }
        }
        Ok(())
    }

    /// Read bytes from an input stream, and enqueue them into our inbox.
    /// Importantly, this method can be tested with non-sockets.
    /// Returns net_error::RecvError if we couldn't read from the fd 
    fn recv_bytes<R: Read>(&mut self, fd: &mut R) -> Result<usize, net_error> {
        if self.inbox.len() > self.inbox_maxlen {
            return Err(net_error::InboxOverflow);
        }

        let mut blocked = false;
        let mut total_read = 0;

        while !blocked {
            // get the next bytes
            let mut buf = [0u8; 4096];
            let num_read = match fd.read(&mut buf) {
                Ok(0) => {
                    // remote fd is closed
                    Err(net_error::RecvError(format!("Remote endpoint is closed")))
                },
                Ok(count) => Ok(count),
                Err(e) => {
                    if e.kind() == IoErrorKind::WouldBlock {
                        Ok(0)
                    }
                    else {
                        debug!("Failed to read from fd: {:?}", &e);
                        Err(net_error::RecvError(format!("Failed to read: {:?}", &e)))
                    }
                }
            }?;

            total_read += num_read;
            test_debug!("read {} bytes; {} total", num_read, total_read);
            if num_read == 0 {
                // can stop
                blocked = true;
            }
            else {
                // decode into message stream
                self.consume_messages(&buf[0..num_read])?;
            }
        }
        Ok(total_read)
    }

    /// Get the oldest message received in the inbox 
    pub fn next_message(&mut self) -> Option<P::Message> {
        self.inbox.pop_front()
    }

    /// How many queued messsages do we have?
    pub fn num_messages(&self) -> usize {
        self.inbox.len()
    }
}

impl<P: ProtocolFamily> ConnectionOutbox<P> {
    pub fn new(outbox_maxlen: usize) -> ConnectionOutbox<P> {
        ConnectionOutbox {
            outbox: VecDeque::with_capacity(outbox_maxlen),
            outbox_maxlen: outbox_maxlen,
            socket_out_buf: vec![],
            socket_out_ptr: 0,
            inflight: VecDeque::new()
        }
    }

    /// queue up a message to be sent 
    fn queue_message(&mut self, m: P::Message, r: Option<ReceiverNotify<P>>) -> Result<(), net_error> {
        if self.outbox.len() > self.outbox_maxlen {
            test_debug!("Outbox is full! has {} items", self.outbox.len());
            return Err(net_error::OutboxOverflow);
        }

        test_debug!("Push to outbox: {:?}", &m);
        self.outbox.push_back(InflightMessage {
            message: m,
            notify: r
        });
        Ok(())
    }

    /// Write messages into a write stream.
    /// Importantly, this can be used without a socket (for testing purposes).
    /// Getting back net_error::SendError indicates that the fd is bad and should be closed
    fn send_bytes<W: Write>(&mut self, fd: &mut W) -> Result<usize, net_error> {
        if self.outbox.len() == 0 {
            // nothing to do 
            // test_debug!("send bytes, but outbox is empty!");
            return Ok(0);
        }
        
        // test_debug!("send bytes!");
        let mut blocked = false;
        let mut num_sent = 0;
        while !blocked {
            // next message?
            if self.socket_out_buf.len() == 0 {
                if self.outbox.len() == 0 {
                    // outbox empty, and all pending data sent.  we're done!
                    // test_debug!("outbox is now empty!");
                    break;
                }

                // fill in the next message (but don't pop it yet -- need its notification to
                // persist until we're done sending it).
                let message = &self.outbox.get(0).unwrap().message;
                let mut serialized_message = message.consensus_serialize();
                self.socket_out_buf.append(&mut serialized_message);
                self.socket_out_ptr = 0;
                test_debug!("Queue next message ({} seq {}): socket_buf_ptr = {}, socket_out_buf.len() = {}", 
                            message.get_message_name(), message.request_id(), self.socket_out_ptr, self.socket_out_buf.len());
            }

            // send as many bytes as we can
            // test_debug!("Write up to {} bytes", self.socket_out_buf.len() - (self.socket_out_ptr as usize));

            let num_written_res = fd.write(&self.socket_out_buf[(self.socket_out_ptr as usize)..]);
            let num_written =
                match num_written_res {
                    Ok(count) => Ok(count),
                    Err(e) => {
                        if e.kind() == IoErrorKind::WouldBlock {
                            Ok(0)
                        }
                        else {
                            debug!("Failed to write to fd: {:?}", &e);
                            Err(net_error::SendError(format!("Failed to send {} bytes", (self.socket_out_buf.len() as u32) - self.socket_out_ptr)))
                        }
                    }
                }?;

            // test_debug!("Write bytes: socket_buf_ptr = {}, socket_out_buf.len() = {}, num_written = {}", self.socket_out_ptr, self.socket_out_buf.len(), num_written);

            if num_written == 0 {
                blocked = true;
            }

            self.socket_out_ptr += num_written as u32;
            if self.socket_out_buf.len() > 0 && self.socket_out_ptr == (self.socket_out_buf.len() as u32) {
                // finished sending a message!
                // remember to wake up any receivers when (if) we get a reply
                let mut inflight_message = self.outbox.pop_front();
                let receiver_notify_opt = inflight_message.take();
                
                // test_debug!("Notify blocked threads: socket_buf_ptr = {}, socket_out_buf.len() = {}", self.socket_out_ptr, self.socket_out_buf.len());
                
                match receiver_notify_opt {
                    None => {},
                    Some(receiver_notify) => {
                        if receiver_notify.notify.is_some() {
                            self.inflight.push_back(receiver_notify.notify.unwrap());
                        }
                    }
                }

                self.socket_out_buf.clear();
                self.socket_out_ptr = 0;
            }

            num_sent += num_written;
        }
        Ok(num_sent)
    }
    
    /// How many queued messsages do we have?
    pub fn num_messages(&self) -> usize {
        self.outbox.len()
    }
}

impl<P: ProtocolFamily> NetworkConnection<P> {
    pub fn new(options: &ConnectionOptions, public_key_opt: Option<Secp256k1PublicKey>) -> NetworkConnection<P> {
        NetworkConnection {
            options: (*options).clone(),

            inbox: ConnectionInbox::new(options.inbox_maxlen, public_key_opt),
            outbox: ConnectionOutbox::new(options.outbox_maxlen)
        }
    }

    /// Determine if a (possibly unauthenticated) message was solicited 
    pub fn is_solicited(&self, msg: &P::Message) -> bool {
        let mut solicited = false;
        for i in 0..self.outbox.inflight.len() {
            let inflight = self.outbox.inflight.get(i).unwrap();
            if inflight.expected_seq == msg.request_id() {
                // this message is in reply to this inflight message
                solicited = true;
                break;
            }
        }

        solicited
    }

    /// Fulfill an outstanding request with a message.
    /// Return the message itself if the message was unsolicited
    pub fn fulfill_request(&mut self, msg: P::Message) -> Option<P::Message> {
        // relay to next waiting receiver 
        let mut outbox_index = 0;
        let mut solicited = false;
        for i in 0..self.outbox.inflight.len() {
            let inflight = self.outbox.inflight.get(i).unwrap();
            if inflight.expected_seq == msg.request_id() {
                // this message is in reply to this inflight message
                outbox_index = i;
                solicited = true;
                break;
            }
        }

        if solicited {
            let fulfilled = self.outbox.inflight.remove(outbox_index).unwrap();
            fulfilled.send(msg);
            None
        }
        else {
            Some(msg)
        }
    }

    /// Send any messages we got to waiting receivers.
    /// Used mainly for testing.
    /// Return the list of unsolicited messages (such as blocks and transactions).
    pub fn drain_inbox(&mut self) -> Vec<P::Message> {
        let inflight_index = 0;
        let mut unsolicited = vec![];
        loop {
            let in_msg_opt = self.inbox.next_message();
            match in_msg_opt {
                None => {
                    // drained
                    break;
                }
                Some(msg) => {
                    // relay to next waiting receiver
                    let out_msg_opt = self.fulfill_request(msg);
                    match out_msg_opt {
                        None => {},
                        Some(m) => unsolicited.push(m)
                    };
                }
            }
        }

        return unsolicited;
    }

    /// Clear out timed-out requests.
    /// Called from the p2p main loop.
    /// Returns number of messages drained.
    pub fn drain_timeouts(&mut self) -> usize {
        let now = get_epoch_time_secs();
        let mut to_remove = vec![];
        for i in 0..self.outbox.inflight.len() {
            match self.outbox.inflight.get_mut(i) {
                None => {
                    to_remove.push(i);
                    continue;
                }
                Some(inflight) => {
                    if inflight.ttl < now {
                        // expired
                        test_debug!("Request timed out: seq={} ttl={} now={}", inflight.expected_seq, inflight.ttl, now); 
                        to_remove.push(i);
                    }
                }
            }
        }

        let res = to_remove.len();

        to_remove.reverse();
        for i in to_remove {
            // destroy the channel, causing anyone waiting for a reply to get an error.
            self.outbox.inflight.remove(i);
        }

        res
    } 

    /// Send a signed message and expect a reply.
    pub fn send_signed_message(&mut self, message: P::Message, ttl: u64) -> Result<NetworkReplyHandle<P>, net_error> {
        let (send_ch, recv_ch) = sync_channel(1);
        let recv_notify = ReceiverNotify::new(message.request_id(), send_ch, ttl);
        let recv_handle = NetworkReplyHandle::new(recv_ch);

        self.outbox.queue_message(message, Some(recv_notify))?;
        Ok(recv_handle)
    }

    /// Forward a signed message to a peer, expecting no reply 
    pub fn relay_signed_message(&mut self, message: P::Message) -> Result<(), net_error> {
        self.outbox.queue_message(message, None)?;
        Ok(())
    }

    /// Send data 
    pub fn send_data<W: Write>(&mut self, fd: &mut W) -> Result<usize, net_error> {
        self.outbox.send_bytes(fd)
    }

    /// Receive data 
    pub fn recv_data<R: Read>(&mut self, fd: &mut R) -> Result<usize, net_error> {
        self.inbox.recv_bytes(fd)
    }

    /// how many inbox messages pending?
    pub fn inbox_len(&self) -> usize {
        self.inbox.num_messages()
    }
    
    /// how many outbox messages pending?
    pub fn outbox_len(&self) -> usize {
        self.outbox.num_messages()
    }

    /// get the next inbox message 
    pub fn next_inbox_message(&mut self) -> Option<P::Message> {
        self.inbox.next_message()
    }
    
    /// set the public key 
    pub fn set_public_key(&mut self, pubk: Option<Secp256k1PublicKey>) -> () {
        self.inbox.public_key = pubk;
    }

    /// Get the public key 
    pub fn get_public_key(&self) -> Option<Secp256k1PublicKey> {
        match self.inbox.public_key {
            Some(pubk) => Some(pubk.clone()),
            None => None
        }
    }

    /// do we have a public key 
    pub fn has_public_key(&self) -> bool {
        self.inbox.public_key.is_some()
    }
}

pub type ConnectionP2P = NetworkConnection<StacksP2P>;
pub type ReplyHandleP2P = NetworkReplyHandle<StacksP2P>;

#[cfg(test)]
mod test {
    use super::*;
    use net::*;
    use util::secp256k1::*;
    use util::*;
    use std::io;

    use net::test::NetCursor;

    #[test]
    fn connection_relay_send() {
        let neighbor = Neighbor {
            addr: NeighborKey {
                peer_version: 0x12345678,
                network_id: 0x9abcdef0,
                addrbytes: PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]),
                port: 12345,
            },
            public_key: Secp256k1PublicKey::from_hex("02fa66b66f8971a8cd4d20ffded09674e030f0f33883f337f34b95ad4935bac0e3").unwrap(),
            expire_block: 23456,
            last_contact_time: 1552509642,
            whitelisted: -1,
            blacklisted: -1,
            asn: 34567,
            org: 45678,
            in_degree: 0,
            out_degree: 0
        };

        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5;
        conn_opts.outbox_maxlen = 5;

        let mut conn = ConnectionP2P::new(&conn_opts, None);

        // send
        let mut ping = StacksMessage::new(0x12345678, 0x9abcdef0,
                                          12345,
                                          &ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
                                          12339,
                                          &ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
                                          StacksMessageType::Ping(PingData { nonce: 0x01020304 }));

        let privkey = Secp256k1PrivateKey::new();
        ping.sign(1, &privkey).unwrap();

        conn.relay_signed_message(ping.clone()).unwrap();
        conn.relay_signed_message(ping.clone()).unwrap();
        conn.relay_signed_message(ping.clone()).unwrap();
        conn.relay_signed_message(ping.clone()).unwrap();
        conn.relay_signed_message(ping.clone()).unwrap();

        // 5 ping messages queued; no one expecting a reply
        for i in 0..5 {
            assert_eq!(conn.outbox.outbox.get(i).unwrap().message, ping);
            assert!(conn.outbox.outbox.get(i).unwrap().notify.is_none());
        }

        // size of one ping 
        let ping_size = ping.consensus_serialize().len();
        let mut ping_vec = vec![0; ping_size];

        let mut write_buf = NetCursor::new(ping_vec.as_mut_slice());

        // send one ping 
        conn.send_data(&mut write_buf).unwrap();
        
        // 4 messages queued
        assert_eq!(conn.outbox.outbox.len(), 4);
        for i in 0..4 {
            assert_eq!(conn.outbox.outbox.get(i).unwrap().message, ping);
        }

        // buffer is loaded up with the next message 
        assert_eq!(conn.outbox.socket_out_buf.len(), ping_size);
        assert_eq!(conn.outbox.socket_out_ptr, 0);

        // 1 message serialized and bufferred out, and it should be our ping.
        let mut index = 0;
        assert_eq!(StacksMessage::consensus_deserialize(&write_buf.get_ref().to_vec(), &mut index, write_buf.get_ref().len() as u32).unwrap(), ping);

        // relay 1.5 pings
        let mut ping_buf_15 = vec![0; ping_size + (ping_size/2)];
        let mut write_buf_15 = NetCursor::new(ping_buf_15.as_mut_slice());
        conn.send_data(&mut write_buf_15).unwrap();

        // 3 messages still queued (the one partially-sent)
        assert_eq!(conn.outbox.outbox.len(), 3);
        for i in 0..3 {
            assert_eq!(conn.outbox.outbox.get(i).unwrap().message, ping);
        }

        // buffer is partially full, with (ping_size / 2) bytes (the first half of a ping)
        assert_eq!(conn.outbox.socket_out_buf.len(), ping_size);
        assert_eq!(conn.outbox.socket_out_ptr, (ping_size / 2) as u32);

        // the (ping_size / 2) bytes should be half a ping 
        let serialized_ping = ping.consensus_serialize();
        assert_eq!(conn.outbox.socket_out_buf[0..(conn.outbox.socket_out_ptr as usize)], serialized_ping[0..(conn.outbox.socket_out_ptr as usize)]);

        let mut half_ping = conn.outbox.socket_out_buf.clone()[0..(conn.outbox.socket_out_ptr as usize)].to_vec();
        let mut ping_buf_05 = vec![0; 2*ping_size - (ping_size + ping_size/2)];

        // flush the remaining half-ping 
        let mut write_buf_05 = NetCursor::new(ping_buf_05.as_mut_slice());
        conn.send_data(&mut write_buf_05).unwrap();

        // 2 messages still queued 
        assert_eq!(conn.outbox.outbox.len(), 2);
        assert_eq!(conn.outbox.outbox.get(0).unwrap().message, ping);

        // buffer is now empty, but a message is queued up for sending
        assert_eq!(conn.outbox.socket_out_buf.len(), ping_size);
        assert_eq!(conn.outbox.socket_out_ptr, 0);

        // the combined ping buffers should be the serialized ping 
        let mut combined_ping_buf = vec![];
        combined_ping_buf.append(&mut half_ping);
        combined_ping_buf.extend_from_slice(&write_buf_05.get_mut());
        
        assert_eq!(combined_ping_buf, serialized_ping);
    }

    #[test]
    fn connection_relay_send_recv() {
        let privkey = Secp256k1PrivateKey::new();
        let pubkey = Secp256k1PublicKey::from_private(&privkey);

        let neighbor = Neighbor {
            addr: NeighborKey {
                peer_version: 0x12345678,
                network_id: 0x9abcdef0,
                addrbytes: PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]),
                port: 12345,
            },
            public_key: pubkey.clone(),
            expire_block: 23456,
            last_contact_time: 1552509642,
            whitelisted: -1,
            blacklisted: -1,
            asn: 34567,
            org: 45678,
            in_degree: 0,
            out_degree: 0
        };

        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5;
        conn_opts.outbox_maxlen = 5;

        let mut conn = ConnectionP2P::new(&conn_opts, Some(neighbor.public_key));

        // send
        let mut ping_vec = vec![];
        let mut ping_size = 0;
        for i in 0..5 {
            let mut ping = StacksMessage::new(0x12345678, 0x9abcdef0,
                                              12345 + i,
                                              &ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
                                              12339 + i,
                                              &ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
                                              StacksMessageType::Ping(PingData { nonce: 0x01020304 }));

            ping.sign(i as u32, &privkey).unwrap();
            ping_size = ping.consensus_serialize().len();

            conn.relay_signed_message(ping.clone()).unwrap();
            ping_vec.push(ping);
        }
        
        // buffer to send/receive everything
        let mut ping_buf = vec![0u8; 5*ping_size];

        {
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let num_sent = conn.send_data(&mut ping_fd).unwrap();
            assert_eq!(num_sent, ping_size * 5);
        }
        
        {
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let num_read = conn.recv_data(&mut ping_fd).unwrap();
            assert_eq!(num_read, 5*ping_size);
        }

        // all messages received? note that they are all unsolicited
        let msgs = conn.drain_inbox();
        assert_eq!(msgs, ping_vec);
    }

    #[test]
    fn connection_send_recv() {
        let privkey = Secp256k1PrivateKey::new();
        let pubkey = Secp256k1PublicKey::from_private(&privkey);

        let neighbor = Neighbor {
            addr: NeighborKey {
                peer_version: 0x12345678,
                network_id: 0x9abcdef0,
                addrbytes: PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]),
                port: 12345,
            },
            public_key: pubkey.clone(),
            expire_block: 23456,
            last_contact_time: 1552509642,
            whitelisted: -1,
            blacklisted: -1,
            asn: 34567,
            org: 45678,
            in_degree: 0,
            out_degree: 0
        };

        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5;
        conn_opts.outbox_maxlen = 5;
        
        let mut conn = ConnectionP2P::new(&conn_opts, Some(neighbor.public_key));

        // send
        let mut ping_vec = vec![];
        let mut handle_vec = vec![];
        let mut ping_size = 0;
        for i in 0..5 {
            let mut ping = StacksMessage::new(0x12345678, 0x9abcdef0,
                                              12345 + i,
                                              &ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
                                              12339 + i,
                                              &ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
                                              StacksMessageType::Ping(PingData { nonce: (0x01020304 + i) as u32 }));

            ping.sign(i as u32, &privkey).unwrap();
            
            ping_size = ping.consensus_serialize().len();
            let handle = conn.send_signed_message(ping.clone(), get_epoch_time_secs() + 60).unwrap();
            handle_vec.push(handle);
            ping_vec.push(ping);
        }
        
        // buffer to send/receive everything
        let mut ping_buf = vec![0u8; 5*ping_size];

        {
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let num_sent = conn.send_data(&mut ping_fd).unwrap();
            assert_eq!(num_sent, ping_size * 5);
        }
        
        {
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let num_read = conn.recv_data(&mut ping_fd).unwrap();
            assert_eq!(num_read, 5*ping_size);
        }

        // all messages are solicited, so inbox should be empty
        let msgs = conn.drain_inbox();
        assert_eq!(msgs, vec![]);

        // all handles should have messages
        let mut recved = vec![];
        for h in handle_vec {
            let res = h.recv(0).unwrap();
            recved.push(res);
        }

        assert_eq!(recved, ping_vec);
    }

    #[test]
    fn connection_send_recv_timeout() {
        let privkey = Secp256k1PrivateKey::new();
        let pubkey = Secp256k1PublicKey::from_private(&privkey);

        let neighbor = Neighbor {
            addr: NeighborKey {
                peer_version: 0x12345678,
                network_id: 0x9abcdef0,
                addrbytes: PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]),
                port: 12345,
            },
            public_key: pubkey.clone(),
            expire_block: 23456,
            last_contact_time: 1552509642,
            whitelisted: -1,
            blacklisted: -1,
            asn: 34567,
            org: 45678,
            in_degree: 0,
            out_degree: 0
        };

        let mut conn_opts = ConnectionOptions::default();
        conn_opts.inbox_maxlen = 5;
        conn_opts.outbox_maxlen = 5;
        
        let mut conn = ConnectionP2P::new(&conn_opts, Some(neighbor.public_key));

        // send
        let mut ping_vec = vec![];
        let mut handle_vec = vec![];
        let mut ping_size = 0;
        for i in 0..5 {
            let mut ping = StacksMessage::new(0x12345678, 0x9abcdef0,
                                              12345 + i,
                                              &ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
                                              12339 + i,
                                              &ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
                                              StacksMessageType::Ping(PingData { nonce: (0x01020304 + i) as u32 }));

            ping.sign(i as u32, &privkey).unwrap();
            ping_size = ping.consensus_serialize().len();
            
            let handle = conn.send_signed_message(ping.clone(), get_epoch_time_secs() + 1).unwrap();
            handle_vec.push(handle);
            ping_vec.push(ping);
        }
        
        // buffer to send/receive everything
        let mut ping_buf = vec![0u8; 5*ping_size];

        {
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let num_sent = conn.send_data(&mut ping_fd).unwrap();
            assert_eq!(num_sent, ping_size * 5);
        }

        // wait 3 seconds 
        test_debug!("Wait 3 seconds for Pings to time out");
        sleep_ms(3000);
        conn.drain_timeouts();

        // all messages timed out
        assert_eq!(conn.outbox.inflight.len(), 0);
        
        {
            let mut ping_fd = NetCursor::new(ping_buf.as_mut_slice());
            let num_read = conn.recv_data(&mut ping_fd).unwrap();

            // data can still be received, but it won't be relayed.
            assert_eq!(num_read, ping_size * 5);
        }

        // messages not relayed, so they'll show up as queued in the inbox instead
        let msgs = conn.drain_inbox();
        assert_eq!(msgs, ping_vec);

        // all handles should be closed with the ConnectionBroken error
        for h in handle_vec {
            let res = h.recv(0);
            assert_eq!(res, Err(net_error::ConnectionBroken));
        }
    }
}
