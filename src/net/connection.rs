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
use std::io::{Read, Write};
use std::io::ErrorKind as IoErrorKind;
use std::ops::Deref;
use std::ops::DerefMut;
use std::time::Duration;
use std::collections::VecDeque;

use std::sync::mpsc::sync_channel;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::RecvError;
use std::sync::mpsc::RecvTimeoutError;

use mio;
use mio::net as mio_net;

use net::Error as net_error;
use net::StacksMessageCodec;
use net::Preamble;
use net::RelayData;
use net::StacksMessage;
use net::StacksMessageType;
use net::StacksMessageID;
use net::PeerAddress;
use net::Neighbor;
use net::NeighborKey;
use net::codec::*;
use net::PREAMBLE_ENCODED_SIZE;

use chainstate::burn::ConsensusHash;

use util::log;
use util::secp256k1::Secp256k1PublicKey;

/// Receiver notification handle.
/// When a message with the expected `seq` value arrives, send it to an expected receiver (possibly
/// in another thread) via the given `receiver_input` channel.
#[derive(Debug)]
struct ReceiverNotify {
    expected_seq: u32,
    receiver_input: SyncSender<StacksMessage>,
}

impl ReceiverNotify {
    pub fn new(seq: u32, input: SyncSender<StacksMessage>) -> ReceiverNotify {
        ReceiverNotify {
            expected_seq: seq,
            receiver_input: input
        }
    }

    /// Send this message to the waiting receiver, consuming this notification handle.
    pub fn send(self, msg: StacksMessage) -> () {
        self.receiver_input.send(msg);
    }
}

/// Opaque structure for waiting or a reply.  Contains the other end of a ReceiverNotify.
#[derive(Debug)]
pub struct NetworkReplyHandle {
    receiver_output: Receiver<StacksMessage>
}

impl NetworkReplyHandle {
    pub fn new(output: Receiver<StacksMessage>) -> NetworkReplyHandle {
        NetworkReplyHandle {
            receiver_output: output
        }
    }

    /// Receive the outstanding message from our peer within the allotted time (pass -1 for "wait forever").
    /// Destroys the NetworkReplyHandle in the process.  You can only call this once!
    /// Timeout is in seconds.
    pub fn recv(self, timeout: i64) -> Result<StacksMessage, net_error> {
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
struct InflightMessage {
    message: StacksMessage,
    notify: Option<ReceiverNotify>
}

#[derive(Debug)]
struct ConnectionInbox {
    // gleaned from the neighbor struct this connection is for
    addr: NeighborKey,
    expire_block_height: u64,
    public_key: Secp256k1PublicKey,

    // completely-parsed incoming messages that do _not_ get sent out to a waiting receiver 
    inbox: VecDeque<StacksMessage>,
    inbox_maxlen: usize,    // this is a _soft_ limit -- it's possible for inbox to exceed this by a fixed quantity

    // partially-parsed incoming messages
    preamble: Option<Preamble>,
    payload_data: Vec<u8>,
    preamble_buf: Vec<u8>,
}

#[derive(Debug)]
struct ConnectionOutbox {
    addr: NeighborKey,

    // message to send
    outbox: VecDeque<InflightMessage>,
    outbox_maxlen: usize,
    socket_out_buf: Vec<u8>,
    socket_out_ptr: u32,

    // in-flight messages 
    inflight: VecDeque<ReceiverNotify>
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionOptions {
    pub keepalive: u64,
    pub nodelay: bool,
    pub inbox_maxlen: usize,
    pub outbox_maxlen: usize
}

#[derive(Debug)]
pub struct Connection {
    pub addr: NeighborKey,
    pub options: ConnectionOptions,

    inbox: ConnectionInbox,
    outbox: ConnectionOutbox
}

impl ConnectionInbox {
    pub fn new(neighbor: &Neighbor, max_messages: usize) -> ConnectionInbox {
        ConnectionInbox {
            expire_block_height: neighbor.expire_block,
            public_key: neighbor.public_key.clone(),
            addr: neighbor.addr.clone(),
            inbox: VecDeque::with_capacity(max_messages),
            inbox_maxlen: max_messages,
            preamble: None,
            payload_data: vec![],
            preamble_buf: vec![],
        }
    }

    /// Is this connection's key expired, given the block height?
    pub fn is_expired(&self, block_height: u64) -> bool {
        self.expire_block_height <= block_height
    }

    /// Disconnect from the remote peer 
    pub fn disconnect(&mut self) -> () {
        self.inbox.clear();
        self.preamble = None;
        self.payload_data.clear();
        self.preamble_buf.clear();
    }
    
    /// Disconnect and reconnect
    pub fn reconnect(&mut self, neighbor: &Neighbor) -> () {
        self.disconnect();

        self.expire_block_height = neighbor.expire_block;
        self.public_key = neighbor.public_key.clone();
        self.addr = neighbor.addr.clone();
    }

    /// consume data to form a message preamble.
    /// Returns how many bytes were consumed from buf.
    fn consume_preamble(&mut self, buf: &[u8]) -> Result<usize, net_error> {
        if self.preamble.is_none() {
            let data_to_read = 
                if self.preamble_buf.len() + buf.len() < (PREAMBLE_ENCODED_SIZE as usize) {
                    buf.len()
                }
                else {
                    (PREAMBLE_ENCODED_SIZE as usize) - self.preamble_buf.len()
                };

            let data_left = buf.len() - data_to_read;

            test_debug!("preamble_buf.len() = {}, buf.len() = {}", self.preamble_buf.len(), buf.len());
            test_debug!("Consume {} bytes for preamble, leaving {} bytes for payload", data_to_read, data_left);

            self.preamble_buf.extend_from_slice(&buf[0..data_to_read]);

            // enough to parse a preamble?
            if self.preamble_buf.len() >= (PREAMBLE_ENCODED_SIZE as usize) {
                
                let mut index = 0;
                let preamble_res = Preamble::deserialize(&self.preamble_buf, &mut index, PREAMBLE_ENCODED_SIZE);
                match preamble_res {
                    Ok(preamble) => {
                        // got a preamble!
                        self.preamble = Some(preamble);
                        self.preamble_buf.clear();

                        test_debug!("Consumed {} bytes for preamble", index);
                    },
                    Err(_) => {
                        // invalid message
                        debug!("Invalid message preamble from {:?}:{}", &self.addr.addrbytes, self.addr.port);
                        return Err(net_error::InvalidMessage);
                    }
                }
            }
            return Ok(data_to_read);
        }
        else {
            // nothing to do -- already have a preamble
            test_debug!("Already have preamble; leaving {} bytes for payload", buf.len());
            return Ok(0);
        }
    }
    
    /// consume data to form a payload buffer 
    /// Returns how many bytes were consumed from buf 
    fn consume_payload(&mut self, buf: &[u8]) -> Result<usize, net_error> {
        let mut got_message = false;
        let mut data_to_read = 0;
        match self.preamble {
            Some(ref mut preamble) => {
                // how much data to save?
                data_to_read =
                    if self.payload_data.len() + buf.len() < (preamble.payload_len as usize) {
                        buf.len()
                    }
                    else {
                        (preamble.payload_len as usize) - self.payload_data.len()
                    };

                let data_left = buf.len() - data_to_read;

                test_debug!("Consume {} bytes for payload, leaving {} bytes for next message", data_to_read, data_left);

                self.payload_data.extend_from_slice(&buf[0..data_to_read]);

                if self.payload_data.len() >= (preamble.payload_len as usize) {
                    let mut index = 0;
                    let max_len = preamble.payload_len;
                    let message_res = StacksMessage::payload_deserialize(&self.public_key, preamble, &self.payload_data, &mut index, max_len);
                    match message_res {
                        Ok(message) => {
                            // got a message!
                            self.inbox.push_back(message);
                            got_message = true;

                            test_debug!("Consumed {} bytes to form message", index);
                        },
                        Err(e) => {
                            // invalid message 
                            test_debug!("Failed to deserialize: {:?}", e);
                            debug!("Invalid message payload from {:?}:{}", &self.addr.addrbytes, self.addr.port);
                            return Err(net_error::InvalidMessage);
                        }
                    }
                }
            },
            None => {
                // nothing to do -- no preamble 
                test_debug!("Leaving {} bytes for next preamble", buf.len());
            }
        }

        if got_message {
            self.preamble = None;
            self.payload_data.clear();
        }

        return Ok(data_to_read);
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
    fn consume_messages(&mut self, buf: &[u8]) -> Result<usize, net_error> {
        let mut offset = 0;
        loop {
            let num_bytes_preamble_remaining = self.consume_preamble(&buf[offset..])?;
            if num_bytes_preamble_remaining == 0 {
                break;
            }
            
            offset += num_bytes_preamble_remaining;
            let num_bytes_payload_remaining = self.consume_payload(&buf[offset..])?;
            if num_bytes_payload_remaining == 0 {
                break;
            }

            offset += num_bytes_payload_remaining;
        }
        return Ok(offset);
    }

    /// Read bytes from an input stream, and enqueue them into our inbox.
    /// Importantly, this method can be tested with non-sockets.
    fn recv_bytes<R: Read>(&mut self, fd: &mut R) -> Result<usize, net_error> {
        if self.inbox.len() > self.inbox_maxlen {
            return Err(net_error::InboxOverflow);
        }

        let mut blocked = false;
        let mut total_read = 0;

        while !blocked {
            // get the next bytes
            let mut buf = [0u8; 4096];

            let num_read_res = fd.read(&mut buf);
            let num_read =
                match num_read_res {
                    Ok(count) => Ok(count),
                    Err(e) => {
                        if e.kind() == IoErrorKind::WouldBlock {
                            Ok(0)
                        }
                        else {
                            Err(net_error::RecvError(format!("Failed to read from {:?}:{}", &self.addr.addrbytes, self.addr.port)))
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

    /// Work on receiving the next messages from our socket.
    pub fn recv(&mut self, socket: &mut Option<mio_net::TcpStream>) -> Result<usize, net_error> {
        match socket {
            None => {
                Err(net_error::SocketNotConnectedToPeer)
            },
            Some(ref mut s) => {
                self.recv_bytes(s)
            }
        }
    }

    /// Get the oldest message received in the inbox 
    pub fn next_message(&mut self) -> Option<StacksMessage> {
        self.inbox.pop_front()
    }
}

impl ConnectionOutbox {
    pub fn new(neighbor: &Neighbor, outbox_maxlen: usize) -> ConnectionOutbox {
        ConnectionOutbox {
            addr: neighbor.addr.clone(),
            outbox: VecDeque::with_capacity(outbox_maxlen),
            outbox_maxlen: outbox_maxlen,
            socket_out_buf: vec![],
            socket_out_ptr: 0,
            inflight: VecDeque::new()
        }
    }

    /// Disconnect
    fn disconnect(&mut self) -> () {
        self.outbox.clear();
        self.inflight.clear();
        self.socket_out_buf.clear();
        self.socket_out_ptr = 0;
    }

    /// Disconnect and reconnect
    fn reconnect(&mut self, neighbor: &Neighbor) -> () {
        self.disconnect();
        self.addr = neighbor.addr.clone();
    }

    /// queue up a message to be sent 
    fn queue_message(&mut self, m: StacksMessage, r: Option<ReceiverNotify>) -> Result<(), net_error> {
        if self.outbox.len() > self.outbox_maxlen {
            return Err(net_error::OutboxOverflow);
        }
        self.outbox.push_back(InflightMessage {
            message: m,
            notify: r
        });
        Ok(())
    }

    /// Write messages into a write stream.
    /// Importantly, this can be used without a socket (for testing purposes)
    fn send_bytes<W: Write>(&mut self, fd: &mut W) -> Result<usize, net_error> {
        test_debug!("send bytes!");
        if self.outbox.len() == 0 {
            // nothing to do 
            return Ok(0);
        }
        let mut blocked = false;
        let mut num_sent = 0;
        while !blocked {
            // next message?
            if self.socket_out_buf.len() == 0 {
                if self.outbox.len() == 0 {
                    // outbox empty, and all pending data sent.  we're done!
                    break;
                }

                // fill in the next message 
                let mut serialized_message = self.outbox.get(0).unwrap().message.serialize();
                self.socket_out_buf.append(&mut serialized_message);
                self.socket_out_ptr = 0;
                test_debug!("Queue next message: socket_buf_ptr = {}, socket_out_buf.len() = {}", self.socket_out_ptr, self.socket_out_buf.len());
            }

            // send as many bytes as we can
            let num_written_res = fd.write(&self.socket_out_buf[(self.socket_out_ptr as usize)..]);
            let num_written =
                match num_written_res {
                    Ok(count) => Ok(count),
                    Err(e) => {
                        if e.kind() == IoErrorKind::WouldBlock {
                            Ok(0)
                        }
                        else {
                            Err(net_error::SendError(format!("Failed to send {} bytes to {:?}:{}", (self.socket_out_buf.len() as u32) - self.socket_out_ptr, &self.addr.addrbytes, self.addr.port)))
                        }
                    }
                }?;

            test_debug!("Write bytes: socket_buf_ptr = {}, socket_out_buf.len() = {}, num_written = {}", self.socket_out_ptr, self.socket_out_buf.len(), num_written);

            if num_written == 0 {
                blocked = true;
            }

            self.socket_out_ptr += (num_written as u32);
            if self.socket_out_buf.len() > 0 && self.socket_out_ptr == (self.socket_out_buf.len() as u32) {
                // finished sending a message!
                // remember to wake up any receivers when (if) we get a reply
                let mut inflight_message = self.outbox.pop_front();
                let receiver_notify_opt = inflight_message.take();
                
                test_debug!("Notify blocked threads: socket_buf_ptr = {}, socket_out_buf.len() = {}", self.socket_out_ptr, self.socket_out_buf.len());
                
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

    /// work on sending the next message.
    /// Send as many bytes as we can.
    pub fn send(&mut self, socket: &mut Option<mio_net::TcpStream>) -> Result<usize, net_error> {
        match socket {
            None => {
                Err(net_error::SocketNotConnectedToPeer)
            },
            Some(ref mut s) => {
                self.send_bytes(s)
            }
        }
    }
}

impl Connection {
    pub fn new(neighbor: &Neighbor, options: &ConnectionOptions) -> Connection {
        Connection {
            addr: neighbor.addr.clone(),
            options: (*options).clone(),

            inbox: ConnectionInbox::new(neighbor, options.inbox_maxlen),
            outbox: ConnectionOutbox::new(neighbor, options.outbox_maxlen)
        }
    }

    /// Connect to the neighbor, and (re)set the inbox and outbox.
    /// Blows away all outstanding messages and invalidates all NetworkReplyHandles -- attempting to
    /// recieve a message from one will result in an error.
    /// Returns the new socket on success.
    /// Returns an error if we fail to connect.
    fn reconnect(&mut self, neighbor: &Neighbor) -> Result<mio_net::TcpStream, net_error> {
        let addr = neighbor.addr.addrbytes.to_socketaddr(neighbor.addr.port);
        match mio_net::TcpStream::connect(&addr) {
            Ok(s) => {
                s.set_keepalive(Some(Duration::new(self.options.keepalive, 0)))
                    .map_err(|_e| net_error::ConnectionError)?;

                s.set_nodelay(self.options.nodelay)
                    .map_err(|_e| net_error::ConnectionError)?;

                self.addr = neighbor.addr.clone();
                self.inbox.reconnect(neighbor);
                self.outbox.reconnect(neighbor);
                Ok(s)
            },
            Err(_e) => {
                Err(net_error::ConnectionError)
            }
        }
    }

    /// Send any messages we got to waiting receivers.
    /// Return the list of unsolicited messages (such as blocks and transactions).
    fn drain_inbox(&mut self) -> Vec<StacksMessage> {
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
                    let mut outbox_index = 0;
                    let mut solicited = false;
                    for i in 0..self.outbox.inflight.len() {
                        let inflight = self.outbox.inflight.get(i).unwrap();
                        if inflight.expected_seq == msg.preamble.seq {
                            // this message is in reply to this inflight message
                            outbox_index = i;
                            solicited = true;
                            break;
                        }
                    }

                    if solicited {
                        let fulfilled = self.outbox.inflight.remove(outbox_index).unwrap();
                        fulfilled.send(msg);
                    }
                    else {
                        unsolicited.push(msg);
                    }
                }
            }
        }

        return unsolicited;
    }

    /// Send a signed message and expect a reply.
    pub fn send_signed_message(&mut self, message: StacksMessage) -> Result<NetworkReplyHandle, net_error> {
        let (send_ch, recv_ch) = sync_channel(1);
        let recv_notify = ReceiverNotify::new(message.preamble.seq, send_ch);
        let recv_handle = NetworkReplyHandle::new(recv_ch);

        self.outbox.queue_message(message, Some(recv_notify))?;
        Ok(recv_handle)
    }

    /// Forward a signed message to a peer, expecting no reply 
    pub fn relay_signed_message(&mut self, message: StacksMessage) -> Result<(), net_error> {
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
}

#[cfg(test)]
mod test {
    use super::*;
    use util::secp256k1::*;
    use std::io;

    #[test]
    fn connection_relay_send() {
        let neighbor = Neighbor {
            addr: NeighborKey {
                peer_version: 0x12345678,
                network_id: 0x9abcdef01,
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

        let conn_opts = ConnectionOptions {
            keepalive: 60,
            nodelay: true,
            inbox_maxlen: 5,
            outbox_maxlen: 5
        };

        let mut conn = Connection::new(&neighbor, &conn_opts);

        // send
        let mut ping = StacksMessage::new(0x9abcdef01,
                                          12345,
                                          &ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
                                          12339,
                                          &ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
                                          StacksMessageType::Ping);

        let privkey = Secp256k1PrivateKey::new();
        ping.sign(1, &privkey);

        conn.relay_signed_message(ping.clone());
        conn.relay_signed_message(ping.clone());
        conn.relay_signed_message(ping.clone());
        conn.relay_signed_message(ping.clone());
        conn.relay_signed_message(ping.clone());

        // 5 ping messages queued; no one expecting a reply
        for i in 0..5 {
            assert_eq!(conn.outbox.outbox.get(i).unwrap().message, ping);
            assert!(conn.outbox.outbox.get(i).unwrap().notify.is_none());
        }

        // size of one ping 
        let ping_size = (PREAMBLE_ENCODED_SIZE + 4 + 1) as usize;
        let mut ping_vec = vec![0; ping_size];

        let mut write_buf = io::Cursor::new(ping_vec.as_mut_slice());

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
        assert_eq!(StacksMessage::deserialize(&write_buf.get_ref().to_vec(), &mut index, write_buf.get_ref().len() as u32).unwrap(), ping);

        // relay 1.5 pings
        let mut ping_buf_15 = vec![0; ping_size + (ping_size/2)];
        let mut write_buf_15 = io::Cursor::new(ping_buf_15.as_mut_slice());
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
        let serialized_ping = ping.serialize();
        assert_eq!(conn.outbox.socket_out_buf[0..(conn.outbox.socket_out_ptr as usize)], serialized_ping[0..(conn.outbox.socket_out_ptr as usize)]);

        let mut half_ping = conn.outbox.socket_out_buf.clone()[0..(conn.outbox.socket_out_ptr as usize)].to_vec();
        let mut ping_buf_05 = vec![0; 2*ping_size - (ping_size + ping_size/2)];

        // flush the remaining half-ping 
        let mut write_buf_05 = io::Cursor::new(ping_buf_05.as_mut_slice());
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
                network_id: 0x9abcdef01,
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

        let conn_opts = ConnectionOptions {
            keepalive: 60,
            nodelay: true,
            inbox_maxlen: 5,
            outbox_maxlen: 5
        };

        let mut conn = Connection::new(&neighbor, &conn_opts);

        // send
        let mut ping_vec = vec![];
        for i in 0..5 {
            let mut ping = StacksMessage::new(0x9abcdef01,
                                              12345 + i,
                                              &ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
                                              12339 + i,
                                              &ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
                                              StacksMessageType::Ping);

            ping.sign(i as u32, &privkey);
            
            conn.relay_signed_message(ping.clone());
            ping_vec.push(ping);
        }
        
        // buffer to send/receive everything
        let ping_size = (PREAMBLE_ENCODED_SIZE + 4 + 1) as usize;
        let mut ping_buf = vec![0u8; 5*ping_size];

        {
            let mut ping_fd = io::Cursor::new(ping_buf.as_mut_slice());
            let num_sent = conn.send_data(&mut ping_fd).unwrap();
            assert_eq!(num_sent, ping_size * 5);
        }
        
        {
            let mut ping_fd = io::Cursor::new(ping_buf.as_mut_slice());
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
                network_id: 0x9abcdef01,
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

        let conn_opts = ConnectionOptions {
            keepalive: 60,
            nodelay: true,
            inbox_maxlen: 5,
            outbox_maxlen: 5
        };

        let mut conn = Connection::new(&neighbor, &conn_opts);

        // send
        let mut ping_vec = vec![];
        let mut handle_vec = vec![];
        for i in 0..5 {
            let mut ping = StacksMessage::new(0x9abcdef01,
                                              12345 + i,
                                              &ConsensusHash::from_hex("1111111111111111111111111111111111111111").unwrap(),
                                              12339 + i,
                                              &ConsensusHash::from_hex("2222222222222222222222222222222222222222").unwrap(),
                                              StacksMessageType::Ping);

            ping.sign(i as u32, &privkey);
            
            let handle = conn.send_signed_message(ping.clone()).unwrap();
            handle_vec.push(handle);
            ping_vec.push(ping);
        }
        
        // buffer to send/receive everything
        let ping_size = (PREAMBLE_ENCODED_SIZE + 4 + 1) as usize;
        let mut ping_buf = vec![0u8; 5*ping_size];

        {
            let mut ping_fd = io::Cursor::new(ping_buf.as_mut_slice());
            let num_sent = conn.send_data(&mut ping_fd).unwrap();
            assert_eq!(num_sent, ping_size * 5);
        }
        
        {
            let mut ping_fd = io::Cursor::new(ping_buf.as_mut_slice());
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
}
