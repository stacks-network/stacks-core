/*
 copyright: (c) 2013-2020 by Blockstack PBC, a public benefit corporation.

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

use std::collections::{HashMap, HashSet};
use std::str;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::io::prelude::*;
use std::io;
use std::io::{Read, Write};
use std::mem;

use serde_json;
use serde::{Serialize, Deserialize};

use net::codec::{read_next, write_next};
use net::PeerAddress;
use net::PeerHost;
use net::StacksMessageCodec;
use net::Error as net_error;
use net::HttpRequestPreamble;
use net::HttpResponsePreamble;
use net::HttpContentType;
use net::HttpRequestType;
use net::HttpResponseType;
use net::StacksHttpPreamble;
use net::StacksHttpMessage;
use net::MessageSequence;
use net::ProtocolFamily;
use net::HttpRequestMetadata;
use net::HttpResponseMetadata;
use net::NeighborsData;
use net::NeighborAddress;
use net::HTTP_PREAMBLE_MAX_ENCODED_SIZE;
use net::MAX_MESSAGE_LEN;

use chainstate::burn::BlockHeaderHash;
use burnchains::Txid;
use chainstate::stacks::StacksTransaction;
use chainstate::stacks::StacksBlock;
use chainstate::stacks::StacksMicroblock;
use chainstate::stacks::StacksPublicKey;

use util::log;
use util::hash::hex_bytes;
use util::retry::RetryReader;

use regex::Regex;

use deps::httparse;
use time;

/// HTTP headers that we really care about
#[derive(Debug, Clone, PartialEq)]
enum HttpReservedHeader {
    ContentLength(u32),
    ContentType(HttpContentType),
    XRequestID(u32),
    XRequestPath(String),
    Host(PeerHost)
}

impl FromStr for PeerHost {
    type Err = net_error;

    fn from_str(header: &str) -> Result<PeerHost, net_error> {
        // we're looser than the RFC allows for DNS names -- anything that doesn't parse to an IP
        // address will be parsed to a DNS name.
        // try as IP:port
        match header.parse::<SocketAddr>() {
            Ok(socketaddr) => Ok(PeerHost::IP(PeerAddress::from_socketaddr(&socketaddr), socketaddr.port())),
            Err(_) => {
                // maybe missing :port
                let hostport = format!("{}:80", header);
                match hostport.parse::<SocketAddr>() {
                    Ok(socketaddr) => Ok(PeerHost::IP(PeerAddress::from_socketaddr(&socketaddr), socketaddr.port())),
                    Err(_) => {
                        // try as DNS-name:port
                        let mut host = None;
                        let mut port = None;
                        let parts : Vec<&str> = header.split(":").collect();
                        if parts.len() == 0 {
                            return Err(net_error::DeserializeError("Failed to parse PeerHost: no parts".to_string()));
                        }
                        else if parts.len() == 1 {
                            // no port 
                            host = Some(parts[0].to_string());
                            port = Some(80);
                        }
                        else {
                            let np = parts.len();
                            if parts[np-1].chars().all(char::is_numeric) {
                                // ends in :port
                                let host_str = parts[0..np-1].join(":");
                                if host_str.len() == 0 {
                                    return Err(net_error::DeserializeError("Empty host".to_string()));
                                }
                                host = Some(host_str);

                                let port_res = parts[np-1].parse::<u16>();
                                port = match port_res {
                                    Ok(p) => Some(p),
                                    Err(_) => {
                                        return Err(net_error::DeserializeError("Failed to parse PeerHost: invalid port".to_string()));
                                    }
                                };
                            }
                            else {
                                // only host
                                host = Some(header.to_string());
                                port = Some(80);
                            }
                        }

                        match (host, port) {
                            (Some(h), Some(p)) => Ok(PeerHost::DNS(h, p)),
                            (_, _) => Err(net_error::DeserializeError("Failed to parse PeerHost: failed to extract host and/or port".to_string()))      // I don't think this is reachable
                        }
                    }
                }
            }
        }
    }
}

impl HttpReservedHeader {
    pub fn is_reserved(header: &str) -> bool {
        let hdr = header.to_string();
        match hdr.as_str() {
            "content-length" | "content-type" | "x-request-id" | "x-request-path" | "host" => true,
            _ => false
        }
    }
        
    pub fn try_from_str(header: &str, value: &str) -> Option<HttpReservedHeader> {
        let hdr = header.to_string().to_lowercase();
        match hdr.as_str() {
            "content-length" => match value.parse::<u32>() {
                Ok(cl) => Some(HttpReservedHeader::ContentLength(cl)),
                Err(_) => None
            },
            "content-type" => match value.parse::<HttpContentType>() {
                Ok(ct) => Some(HttpReservedHeader::ContentType(ct)),
                Err(_) => None
            },
            "x-request-id" => match value.parse::<u32>() {
                Ok(rid) => Some(HttpReservedHeader::XRequestID(rid)),
                Err(_) => None
            },
            "x-request-path" => Some(HttpReservedHeader::XRequestPath(value.to_string())),
            "host" => match value.parse::<PeerHost>() {
                Ok(ph) => Some(HttpReservedHeader::Host(ph)),
                Err(_) => None
            },
            _ => None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Copy)]
enum HttpChunkedTransferParseMode {
    ChunkBoundary,
    Chunk,
    ChunkTrailer,
    EOF
}

#[derive(Debug, Clone, PartialEq, Copy)]
struct HttpChunkedTransferReaderState {
    parse_step: HttpChunkedTransferParseMode,
    chunk_size: u64,
    chunk_read: u64,
    max_size: u64,
    total_size: u64,
    last_chunk_size: u64,

    // for parsing a chunk boundary
    // (we don't use extensions, so 16 bytes for size + 2 for \r\n delimiter ought to be enough)
    chunk_buffer: [u8; 18],
    i: usize,
}

impl HttpChunkedTransferReaderState {
    pub fn new(max_size: u64) -> HttpChunkedTransferReaderState {
        HttpChunkedTransferReaderState {
            parse_step: HttpChunkedTransferParseMode::ChunkBoundary,
            chunk_size: 0,
            chunk_read: 0,
            max_size: max_size,
            total_size: 0,
            last_chunk_size: u64::max_value(),      // if this ever becomes 0, then we should expect chunk boundary '0\r\n\r\n' and EOF
            chunk_buffer: [0u8; 18],
            i: 0,
        }
    }

    pub fn is_eof(&self) -> bool {
        self.parse_step == HttpChunkedTransferParseMode::EOF
    }
}


/// read adapter for chunked transfer encoding 
struct HttpChunkedTransferReader<'a, R: Read> {
    fd: &'a mut R,
    state: HttpChunkedTransferReaderState
}

impl<'a, R: Read> HttpChunkedTransferReader<'a, R> {
    pub fn from_reader(r: &'a mut R, max_size: u64) -> HttpChunkedTransferReader<'a, R> {
        HttpChunkedTransferReader {
            fd: r,
            state: HttpChunkedTransferReaderState::new(max_size)
        }
    }

    pub fn from_state(r: &'a mut R, state: HttpChunkedTransferReaderState) -> HttpChunkedTransferReader<'a, R> {
        HttpChunkedTransferReader {
            fd: r,
            state: state
        }
    }
}

impl HttpChunkedTransferReaderState {
    /// Read until we have a chunk marker we can parse completely.
    /// Interruptable -- call repeatedly on EINTR.
    /// Reads at most one byte.
    fn read_chunk_boundary<R: Read>(&mut self, fd: &mut R) -> io::Result<usize> {
        assert_eq!(self.parse_step, HttpChunkedTransferParseMode::ChunkBoundary);

        // next byte
        let mut b = [0u8; 1];

        trace!("Read {} bytes", b.len());
        let nr = fd.read(&mut b)?;
        if nr == 0 {
            return Ok(nr);
        }
        trace!("Got {} bytes", nr);

        self.chunk_buffer[self.i] = b[0];
        self.i += 1;

        if self.i >= self.chunk_buffer.len() {
            // don't allow ridiculous extension lengths
            return Err(io::Error::new(io::ErrorKind::InvalidData, net_error::DeserializeError("Invalid HTTP chunk boundary: too long".to_string())));
        }

        let (offset, chunk_len) = match httparse::parse_chunk_size(&self.chunk_buffer[0..self.i]) {
            Ok(httparse::Status::Partial) => {
                return Ok(nr);
            },
            Ok(httparse::Status::Complete((offset, chunk_len))) => (offset, chunk_len),
            Err(e) => {
                test_debug!("Invalid chunk boundary: {:?}", self.chunk_buffer[0..self.i].to_vec());
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid HTTP chunk boundary: could not parse".to_string()));
            }
        };

        trace!("chunk offset: {}. chunk len: {}", offset, chunk_len);
        if chunk_len > MAX_MESSAGE_LEN as u64 {
            trace!("chunk buffer: {:?}", &self.chunk_buffer[0..self.i]);
            return Err(io::Error::new(io::ErrorKind::InvalidData, net_error::DeserializeError("Invalid HTTP chunk: too big".to_string())));
        }

        // got an offset/len.
        // offset ought to equal the number of bytes taken by the encoded chunk boundary.
        assert_eq!(offset, self.i);

        // reset buffers
        self.i = 0;
        self.chunk_size = chunk_len;
        self.chunk_read = 0;

        // begin reading chunk
        trace!("begin reading chunk");
        self.parse_step = HttpChunkedTransferParseMode::Chunk;
        Ok(nr)
    }

    /// Read a chunk -- read up to self.chunk_size bytes over successive calls.
    /// Reads at most self.chunk_size bytes.
    fn read_chunk_bytes<R: Read>(&mut self, fd: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        assert_eq!(self.parse_step, HttpChunkedTransferParseMode::Chunk);

        if self.total_size >= self.max_size && self.chunk_size > 0 {
            return Err(io::Error::new(io::ErrorKind::Other, net_error::OverflowError("HTTP body exceeds maximum expected length".to_string())));
        }

        let remaining = 
            if self.chunk_size - self.chunk_read <= (self.max_size - self.total_size) as u64 {
                self.chunk_size - self.chunk_read
            }
            else {
                (self.max_size - self.total_size) as u64
            };

        let nr = 
            if (buf.len() as u64) < remaining {
                // can fill buffer
                trace!("Read {} bytes (fill buffer)", buf.len());
                fd.read(buf)? as u64
            }
            else {
                // will read up to a chunk boundary
                trace!("Read {} bytes (fill remainder)", remaining);
                fd.read(&mut buf[0..(remaining as usize)])? as u64
            };

        trace!("Got {} bytes", nr);

        self.chunk_read += nr;

        if self.chunk_read >= self.chunk_size {
            // done reading; proceed to consume trailer
            trace!("begin reading trailer ({} >= {})", self.chunk_read, self.chunk_size);
            self.parse_step = HttpChunkedTransferParseMode::ChunkTrailer;
        }
        
        self.total_size += nr;
        Ok(nr as usize)
    }

    /// Read chunk trailer -- read end-of-chunk \r\n
    /// Returns number of bytes read on success
    /// Reads at most 2 bytes.
    fn read_chunk_trailer<R: Read>(&mut self, fd: &mut R) -> io::Result<usize> {
        assert_eq!(self.parse_step, HttpChunkedTransferParseMode::ChunkTrailer);

        let mut nr = 0;

        // read trailer
        if self.i < 2 {
            let mut trailer_buf = [0u8; 2];

            trace!("Read at most {} bytes", 2 - self.i);
            nr = fd.read(&mut trailer_buf[self.i..2])?;
            if nr == 0 {
                return Ok(nr);
            }

            self.chunk_buffer[self.i..2].copy_from_slice(&trailer_buf[self.i..2]);
            self.i += nr;
        }

        if self.i == 2 {
            // expect '\r\n'
            if &self.chunk_buffer[0..2] != &[0x0d, 0x0a] {
                return Err(io::Error::new(io::ErrorKind::InvalidData, net_error::DeserializeError("Invalid chunk trailer".to_string())));
            }

            // end of chunk 
            self.last_chunk_size = self.chunk_size;
            self.i = 0;

            trace!("begin reading boundary");
            self.parse_step = HttpChunkedTransferParseMode::ChunkBoundary;
        }

        trace!("Consumed {} bytes of chunk boundary (i = {})", nr, self.i);
        Ok(nr)
    }

    /// Read from a Read.
    /// Returns (number of bytes decoded, number of bytes consumed from the Read)
    fn do_read<R: Read>(&mut self, fd: &mut R, buf: &mut [u8]) -> io::Result<(usize, usize)> {
        let mut decoded = 0;
        let mut consumed = 0;
        while decoded < buf.len() {
            match self.parse_step {
                HttpChunkedTransferParseMode::ChunkBoundary => {
                    let count = self.read_chunk_boundary(fd)?;
                    if count == 0 {
                        break;
                    }
                    consumed += count;
                },
                HttpChunkedTransferParseMode::Chunk => {
                    let nr = self.read_chunk_bytes(fd, &mut buf[decoded..])?;
                    if nr == 0 && self.parse_step == HttpChunkedTransferParseMode::Chunk {
                        // still trying to read the chunk, but got 0 bytes
                        break;
                    }
                    decoded += nr;
                    consumed += nr;
                }
                HttpChunkedTransferParseMode::ChunkTrailer => {
                    let count = self.read_chunk_trailer(fd)?;
                    if count == 0 {
                        break;
                    }
                    consumed += count;
                    if self.last_chunk_size == 0 {
                        // we're done
                        trace!("finished last chunk");
                        self.parse_step = HttpChunkedTransferParseMode::EOF;
                        break;
                    }
                },
                HttpChunkedTransferParseMode::EOF => {
                    break;
                }
            }
        } 
        Ok((decoded, consumed))
    }
}
    
impl<'a, R: Read> Read for HttpChunkedTransferReader<'a, R> {
    /// Read a HTTP chunk-encoded stream.
    /// Returns number of decoded bytes (i.e. number of bytes copied to buf, as expected)
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.state.do_read(self.fd, buf).and_then(|(decoded, _)| Ok(decoded))
    }
}

struct HttpChunkedTransferWriter<'a, W: Write> {
    fd: &'a mut W,
    chunk_size: usize,
    chunk_buf: Vec<u8>,
}

impl<'a, W: Write> HttpChunkedTransferWriter<'a, W> {
    pub fn from_writer(fd: &'a mut W, chunk_size: usize) -> HttpChunkedTransferWriter<'a, W> {
        HttpChunkedTransferWriter {
            fd: fd,
            chunk_size: chunk_size,
            chunk_buf: vec![],
        }
    }

    fn send_chunk(fd: &mut W, chunk_size: usize, bytes: &[u8]) -> io::Result<usize> {
        let to_send = 
            if chunk_size < bytes.len() {
                chunk_size
            }
            else {
                bytes.len()
            };

        fd.write_all(format!("{:x}\r\n", to_send).as_bytes())?;
        fd.write_all(&bytes[0..to_send])?;
        fd.write_all("\r\n".as_bytes())?;
        Ok(to_send)
    }

    fn flush_chunk(&mut self) -> io::Result<usize> {
        let sent = HttpChunkedTransferWriter::send_chunk(&mut self.fd, self.chunk_size, &self.chunk_buf)?;
        self.chunk_buf.clear();
        Ok(sent)
    }

    fn buf_chunk(&mut self, buf: &[u8]) -> usize {
        let to_copy = 
            if self.chunk_size - self.chunk_buf.len() < buf.len() {
                self.chunk_size - self.chunk_buf.len()
            }
            else {
                buf.len()
            };

        self.chunk_buf.extend_from_slice(&buf[0..to_copy]);
        to_copy
    }
}

impl<'a, W: Write> Write for HttpChunkedTransferWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            if self.chunk_buf.len() > 0 {
                if self.chunk_buf.len() < self.chunk_size {
                    let nw = self.buf_chunk(&buf[written..]);
                    written += nw;
                }
                if self.chunk_buf.len() >= self.chunk_size {
                    self.flush_chunk()?;
                }
            }
            else { 
                if written + self.chunk_size < buf.len() {
                    let nw = HttpChunkedTransferWriter::send_chunk(&mut self.fd, self.chunk_size, &buf[written..(written + self.chunk_size)])?;
                    written += nw;
                }
                else {
                    let nw = self.buf_chunk(&buf[written..]);
                    written += nw;
                }
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        // send out any bufferred chunk data
        self.flush_chunk()
            .and_then(|nw| {
                if nw > 0 {
                    // send empty chunk
                    self.fd.write_all(format!("0\r\n\r\n").as_bytes())
                        .and_then(|_nw| Ok(()))
                }
                else {
                    Ok(())
                }
            })
    }
}

impl<'a, W: Write> Drop for HttpChunkedTransferWriter<'a, W> {
    fn drop(&mut self) -> () {
        let _ = self.flush();
    }
}

/// A Read that will only read up to a given number of bytes before EOF'ing.
struct BoundReader<'a, R: Read> {
    fd: &'a mut R,
    max_len: u64,
    read_so_far: u64
}

impl<'a, R: Read> BoundReader<'a, R> {
    pub fn from_reader(reader: &'a mut R, max_len: u64) -> BoundReader<'a, R> {
        BoundReader {
            fd: reader,
            max_len: max_len,
            read_so_far: 0
        }
    }

    pub fn num_read(&self) -> u64 {
        self.read_so_far
    }
}

impl <'a, R: Read> Read for BoundReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_so_far.checked_add(buf.len() as u64).is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, net_error::OverflowError("Read would overflow u64".to_string())));
        }
        let max_read = 
            if self.read_so_far + (buf.len() as u64) > self.max_len {
                self.max_len - self.read_so_far
            }
            else {
                buf.len() as u64
            };

        let nr = self.fd.read(&mut buf[0..(max_read as usize)])?;
        self.read_so_far += nr as u64;
        Ok(nr)
    }
}

impl HttpRequestPreamble {
    pub fn new(verb: String, path: String, hostname: String, port: u16, request_id: u32) -> HttpRequestPreamble {
        HttpRequestPreamble {
            verb: verb,
            path: path,
            host: PeerHost::from_host_port(hostname, port),
            request_id: request_id,
            content_type: None,
            content_length: None,
            headers: HashMap::new()
        }
    }

    pub fn new_serialized<W: Write>(fd: &mut W, verb: &str, path: &str, host: &PeerHost, request_id: u32, content_length: Option<u32>, content_type: Option<&HttpContentType>, headers: &str) -> Result<(), net_error> {
        // TODO: can we avoid allocating these?
        let content_type_header = match content_type {
            Some(ref c) => format!("Content-Type: {}\r\n", c),
            None => "".to_string()
        };
        let content_length_header = match content_length {
            Some(l) => format!("Content-Length: {}\r\n", l),
            None => "".to_string()
        };

        let txt = format!("{} {} HTTP/1.1\r\nUser-Agent: stacks/2.0\r\nHost: {}\r\n{}\r\n{}{}X-Request-Id: {}{}\r\n\r\n", 
                          verb, path,
                          host,
                          default_accept_header(),
                          content_type_header,
                          content_length_header,
                          request_id,
                          headers);
        fd.write_all(txt.as_bytes()).map_err(net_error::WriteError)
    }

    #[cfg(test)]
    pub fn from_headers(verb: String, path: String, hostname: String, port: u16, request_id: u32, mut keys: Vec<String>, values: Vec<String>) -> HttpRequestPreamble {
        assert_eq!(keys.len(), values.len());
        let mut req = HttpRequestPreamble::new(verb, path, hostname, port, request_id);
        for (k, v) in keys.drain(..).zip(values) {
            req.add_header(k, v);
        }
        req
    }

    pub fn add_header(&mut self, key: String, value: String) -> () {
        let hdr = key.to_lowercase();
        if HttpReservedHeader::is_reserved(&key) {
            match HttpReservedHeader::try_from_str(&key, &value) {
                Some(h) => match h {
                    HttpReservedHeader::Host(ph) => self.host = ph,
                    HttpReservedHeader::XRequestID(rid) => self.request_id = rid,
                    HttpReservedHeader::ContentType(ct) => self.content_type = Some(ct),
                    _ => {}     // can just fall through and insert
                },
                None => {
                    return;
                }
            }
        }

        self.headers.insert(hdr, value);
    }

    pub fn set_request_id(&mut self, id: u32) -> () {
        self.request_id = id;
    }

    /// Content-Length for this request.
    /// If there is no valid Content-Length header, then 
    /// the Content-Length is 0
    pub fn get_content_length(&self) -> u32 {
        self.content_length.unwrap_or(0)
    }

    /// Set the content-length for this request
    pub fn set_content_length(&mut self, len: u32) -> () {
        self.content_length = Some(len);
    }

    /// Set the content-type for this request
    pub fn set_content_type(&mut self, content_type: HttpContentType) -> () {
        self.content_type = Some(content_type)
    }
}

fn headers_to_string(headers: &HashMap<String, String>) -> String {
    let mut headers_list : Vec<String> = Vec::with_capacity(headers.len());
    for (ref key, ref value) in headers.iter() {
        let hdr = format!("{}: {}", key, value);
        headers_list.push(hdr);
    }
    if headers_list.len() == 0 {
        "".to_string()
    }
    else {
        format!("\r\n{}", headers_list.join("\r\n"))
    }
}

fn default_accept_header() -> String {
    format!("Accept: {}, {}, {}", HttpContentType::Bytes, HttpContentType::JSON, HttpContentType::Text)
}

/// Read from a stream until we see '\r\n\r\n', with the purpose of reading an HTTP preamble.
/// It's gonna be important here that R does some bufferring, since this reads byte by byte.
/// EOF if we read 0 bytes.
fn read_to_crlf2<R: Read>(fd: &mut R) -> Result<Vec<u8>, net_error> {
    let mut ret = Vec::with_capacity(HTTP_PREAMBLE_MAX_ENCODED_SIZE as usize);
    while ret.len() < HTTP_PREAMBLE_MAX_ENCODED_SIZE as usize {
        let mut b = [0u8];
        fd.read_exact(&mut b).map_err(net_error::ReadError)?;
        ret.push(b[0]);

        if ret.len() > 4 {
            let last_4 = &ret[(ret.len()-4)..ret.len()];

            // '\r\n\r\n' is [0x0d, 0x0a, 0x0d, 0x0a]
            if last_4 == &[0x0d, 0x0a, 0x0d, 0x0a] {
                break;
            }
        }
    }
    Ok(ret)      
}

impl StacksMessageCodec for HttpRequestPreamble {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), net_error> {
        HttpRequestPreamble::new_serialized(fd, &self.verb, &self.path, &self.host, self.request_id, self.content_length.clone(), self.content_type.as_ref(), &headers_to_string(&self.headers))
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<HttpRequestPreamble, net_error> {
        // realistically, there won't be more than 16 headers
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);

        let buf_read = read_to_crlf2(fd)?;

        // consume request
        match req.parse(&buf_read).map_err(|e| net_error::DeserializeError(format!("Failed to parse HTTP request: {:?}", &e)))? {
            httparse::Status::Partial => {
                return Err(net_error::UnderflowError("Not enough bytes to form an HTTP request preamble".to_string()));
            },
            httparse::Status::Complete(body_offset) => {
                // consumed all headers.  body_offset points to the start of the request body
                let verb = req.method.ok_or(net_error::DeserializeError("No HTTP method".to_string()))?.to_string();
                let path = req.path.ok_or(net_error::DeserializeError("No HTTP path".to_string()))?.to_string();
                
                let mut peerhost = None;
                let mut content_type = None;
                let mut content_length = None;
                let mut request_id = 0;

                let mut headers : HashMap<String, String> = HashMap::new();
                let mut all_headers : HashSet<String> = HashSet::new();

                for i in 0..req.headers.len() {
                    let value = String::from_utf8(req.headers[i].value.to_vec()).map_err(|_e| net_error::DeserializeError("Invalid HTTP header value: not utf-8".to_string()))?;
                    if !value.is_ascii() {
                        return Err(net_error::DeserializeError(format!("Invalid HTTP request: header value is not ASCII-US")));
                    }
                    let key = req.headers[i].name.to_string().to_lowercase();
                    if headers.contains_key(&key) || all_headers.contains(&key) {
                        return Err(net_error::DeserializeError(format!("Invalid HTTP request: duplicate header \"{}\"", key)));
                    }
                    all_headers.insert(key.clone());

                    if key == "host" {
                        peerhost = match value.parse::<PeerHost>() {
                            Ok(ph) => Some(ph),
                            Err(_) => None
                        };
                    }
                    else if key == "x-request-id" {
                        // parse 
                        request_id = value.parse::<u32>().unwrap_or(request_id);
                    }
                    else if key == "content-type" {
                        // parse
                        let ctype = value.parse::<HttpContentType>()?;
                        content_type = Some(ctype);
                    }
                    else if key == "content-length" {
                        // parse 
                        content_length = match value.parse::<u32>() {
                            Ok(len) => Some(len),
                            Err(_) => None
                        }
                    }
                    else {
                        headers.insert(key, value);
                    }
                }

                if peerhost.is_none() {
                    return Err(net_error::DeserializeError("Missing Host header".to_string()));
                };

                Ok(HttpRequestPreamble {
                    verb: verb,
                    path: path,
                    host: peerhost.unwrap(),
                    request_id: request_id,
                    content_type: content_type,
                    content_length: content_length,
                    headers: headers
                })
            }
        }
    }
}

impl HttpResponsePreamble {
    pub fn new(status_code: u16, reason: String, content_length_opt: Option<u32>, content_type: HttpContentType, request_id: u32, request_path: String) -> HttpResponsePreamble {
        HttpResponsePreamble {
            status_code: status_code,
            reason: reason,
            content_length: content_length_opt,
            content_type: content_type,
            request_id: request_id,
            request_path: request_path,
            headers: HashMap::new()
        }
    }
    
    pub fn new_serialized<W: Write>(fd: &mut W, status_code: u16, reason: &str, content_length: Option<u32>, content_type: &HttpContentType, request_id: u32, request_path: &str, headers: &str) -> Result<(), net_error> {
        // TODO: can we avoid allocating these?
        let content_header = match content_length {
            Some(len) => format!("Content-Length: {}", len),
            None => format!("Transfer-Encoding: chunked")
        };

        let txt = format!("HTTP/1.1 {} {}\r\nServer: stacks/2.0\r\nDate: {}\r\nContent-Type: {}\r\n{}\r\nX-Request-Id: {}\r\nX-Request-Path: {}{}\r\n\r\n",
                          status_code, reason,
                          rfc7231_now(),
                          content_type,
                          content_header,
                          request_id,
                          request_path,
                          headers);

        fd.write_all(txt.as_bytes()).map_err(net_error::WriteError)
    }

    pub fn new_error(status_code: u16, request_id: u32, request_path: String, error_message: Option<String>) -> HttpResponsePreamble {
        HttpResponsePreamble {
            status_code: status_code,
            reason: HttpResponseType::error_reason(status_code).to_string(),
            content_length: Some(error_message.unwrap_or("".to_string()).len() as u32),
            content_type: HttpContentType::Text,
            request_id: request_id, 
            request_path: request_path,
            headers: HashMap::new()
        }
    }

    #[cfg(test)]
    pub fn from_headers(status_code: u16, reason: String, content_length: Option<u32>, content_type: HttpContentType, request_id: u32, request_path: String, mut keys: Vec<String>, values: Vec<String>) -> HttpResponsePreamble {
        assert_eq!(keys.len(), values.len());
        let mut res = HttpResponsePreamble::new(status_code, reason, content_length, content_type, request_id, request_path);
        for (k, v) in keys.drain(..).zip(values) {
            res.add_header(k, v);
        }
        res.set_request_id(request_id);
        res
    }

    pub fn add_header(&mut self, key: String, value: String) -> () {
        let hdr = key.to_lowercase();
        if HttpReservedHeader::is_reserved(&key) {
            match HttpReservedHeader::try_from_str(&key, &value) {
                Some(h) => match h {
                    HttpReservedHeader::XRequestID(rid) => self.request_id = rid,
                    HttpReservedHeader::XRequestPath(p) => self.request_path = p,
                    HttpReservedHeader::ContentLength(cl) => self.content_length = Some(cl),
                    HttpReservedHeader::ContentType(ct) => self.content_type = ct,
                    _ => {}     // can just fall through and insert
                },
                None => {
                    return;
                }
            }
        }

        self.headers.insert(hdr, value);
    }

    pub fn set_request_id(&mut self, request_id: u32) -> () {
        self.request_id = request_id;
    }

    pub fn set_request_path(&mut self, request_path: String) -> () {
        self.request_path = request_path;
    }

    pub fn add_CORS_headers(&mut self) -> () {
        self.headers.insert("Access-Control-Allow-Origin".to_string(), "*".to_string());
    }

    // do we have Transfer-Encoding: chunked?
    pub fn is_chunked(&self) -> bool {
        self.content_length.is_none()
    }
}

/// Get an RFC 7231 date that represents the current time
fn rfc7231_now() -> String {
    let now = time::PrimitiveDateTime::now();
    now.format("%a, %b %-d %-Y %-H:%M:%S GMT")
}

impl StacksMessageCodec for HttpResponsePreamble {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), net_error> {
        HttpResponsePreamble::new_serialized(fd, self.status_code, &self.reason, self.content_length, &self.content_type, self.request_id, &self.request_path, &headers_to_string(&self.headers))
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<HttpResponsePreamble, net_error> {
        // realistically, there won't be more than 16 headers
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);

        let buf_read = read_to_crlf2(fd)?;

        // consume response
        match resp.parse(&buf_read).map_err(|e| net_error::DeserializeError(format!("Failed to parse HTTP response: {:?}", &e)))? {
            httparse::Status::Partial => {
                // try again
                return Err(net_error::UnderflowError("Not enough bytes to form an HTTP response preamble".to_string()));
            },
            httparse::Status::Complete(body_offset) => {
                // consumed all headers.  body_offset points to the start of the response body
                let status_code = resp.code.ok_or(net_error::DeserializeError("No HTTP status code".to_string()))?;
                let reason = resp.reason.ok_or(net_error::DeserializeError("No HTTP status reason".to_string()))?.to_string();

                let mut headers : HashMap<String, String> = HashMap::new();
                let mut all_headers : HashSet<String> = HashSet::new();

                let mut content_type = None;
                let mut content_length = None;
                let mut request_id = None;
                let mut request_path = None;
                let mut chunked_encoding = false;

                for i in 0..resp.headers.len() {
                    let value = String::from_utf8(resp.headers[i].value.to_vec()).map_err(|_e| net_error::DeserializeError("Invalid HTTP header value: not utf-8".to_string()))?;
                    if !value.is_ascii() {
                        return Err(net_error::DeserializeError(format!("Invalid HTTP request: header value is not ASCII-US")));
                    }

                    let key = resp.headers[i].name.to_string().to_lowercase();
                    if headers.contains_key(&key) || all_headers.contains(&key) {
                        return Err(net_error::DeserializeError(format!("Invalid HTTP request: duplicate header \"{}\"", key)));
                    }
                    all_headers.insert(key.clone());

                    if key == "content-type" {
                        let ctype = value.parse::<HttpContentType>()?;
                        content_type = Some(ctype);
                    }
                    else if key == "content-length" {
                        let len = value.parse::<u32>().map_err(|_e| net_error::DeserializeError("Invalid Content-Length header value".to_string()))?;
                        content_length = Some(len);
                    }
                    else if key == "x-request-id" {
                        match value.parse::<u32>() {
                            Ok(i) => {
                                request_id = Some(i);
                            }
                            Err(e) => {}
                        }
                    }
                    else if key == "x-request-path" {
                        request_path = Some(value.to_string());
                    }
                    else if key == "transfer-encoding" {
                        if value == "chunked" {
                            chunked_encoding = true;
                        }
                        else {
                            return Err(net_error::DeserializeError(format!("Unsupported transfer-encoding '{}'", value)));
                        }
                    }
                    else {
                        headers.insert(key, value);
                    }
                }

                if content_length.is_some() && chunked_encoding {
                    return Err(net_error::DeserializeError("Invalid HTTP response: incompatible transfer-encoding and content-length".to_string()));
                }

                if content_type.is_none() || request_path.is_none() || request_id.is_none() || (content_length.is_none() && !chunked_encoding) {
                    return Err(net_error::DeserializeError("Invalid HTTP response: missing Content-Type, Content-Length || Transfer-Encoding: chunked, X-Request-ID, and/or X-Request-Path".to_string()));
                }

                Ok(HttpResponsePreamble {
                    status_code: status_code,
                    reason: reason,
                    content_type: content_type.unwrap(),
                    content_length: content_length,
                    request_id: request_id.unwrap(),
                    request_path: request_path.unwrap(),
                    headers: headers
                })
            }
        }
    }
}

impl HttpRequestType {
    fn try_parse<R: Read, F>(protocol: &mut StacksHttp, verb: &str, regex: &Regex, preamble: &HttpRequestPreamble, fd: &mut R, parser: F) -> Result<Option<HttpRequestType>, net_error>
    where
        F: Fn(&mut StacksHttp, &HttpRequestPreamble, &Regex, &mut R) -> Result<HttpRequestType, net_error>
    {
        if preamble.verb == verb && regex.is_match(&preamble.path) {
            let payload = parser(protocol, preamble, regex, fd)?;
            Ok(Some(payload))
        }
        else {
            Ok(None)
        }
    }

    pub fn parse<R: Read>(protocol: &mut StacksHttp, preamble: &HttpRequestPreamble, fd: &mut R) -> Result<HttpRequestType, net_error> {
        // TODO: make this static somehow
        let REQUEST_METHODS : [(&str, &Regex, &dyn Fn(&mut StacksHttp, &HttpRequestPreamble, &Regex, &mut R) -> Result<HttpRequestType, net_error>); 4] = [
            ("GET", &PATH_GETNEIGHBORS, &HttpRequestType::parse_getneighbors),
            ("GET", &PATH_GETBLOCK, &HttpRequestType::parse_getblock),
            ("GET", &PATH_GETMICROBLOCKS, &HttpRequestType::parse_getmicroblocks),
            ("POST", &PATH_POSTTRANSACTION, &HttpRequestType::parse_posttransaction)
        ];

        for (verb, regex, parser) in REQUEST_METHODS.iter() {
            match HttpRequestType::try_parse(protocol, verb, regex, preamble, fd, parser) {
                Ok(Some(request)) => {
                    return Ok(request);
                },
                Ok(None) => {
                    continue;
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }

        return Err(net_error::DeserializeError("Http request could not be parsed".to_string()));
    }
    
    fn parse_getneighbors<R: Read>(protocol: &mut StacksHttp, preamble: &HttpRequestPreamble, _regex: &Regex, _fd: &mut R) -> Result<HttpRequestType, net_error> {
        if preamble.get_content_length() != 0 {
            return Err(net_error::DeserializeError("Invalid Http request: expected 0-length body for GetNeighbors".to_string()));
        }

        Ok(HttpRequestType::GetNeighbors(HttpRequestMetadata::from_preamble(preamble)))
    }

    fn parse_getblock<R: Read>(protocol: &mut StacksHttp, preamble: &HttpRequestPreamble, regex: &Regex, _fd: &mut R) -> Result<HttpRequestType, net_error> {
        if preamble.get_content_length() != 0 {
            return Err(net_error::DeserializeError("Invalid Http request: expected 0-length body for GetBlock".to_string()));
        }

        let block_hash_str = regex
            .captures(&preamble.path)
            .ok_or(net_error::DeserializeError("Failed to match path to block hash".to_string()))?
            .get(1)
            .ok_or(net_error::DeserializeError("Failed to match path to block hash group".to_string()))?
            .as_str();

        let block_hash = BlockHeaderHash::from_hex(block_hash_str)
            .map_err(|_e| net_error::DeserializeError("Failed to parse block hash".to_string()))?;

        Ok(HttpRequestType::GetBlock(HttpRequestMetadata::from_preamble(preamble), block_hash))
    }

    fn parse_getmicroblocks<R: Read>(protocol: &mut StacksHttp, preamble: &HttpRequestPreamble, regex: &Regex, _fd: &mut R) -> Result<HttpRequestType, net_error> {
        if preamble.get_content_length() != 0 {
            return Err(net_error::DeserializeError("Invalid Http request: expected 0-length body for GetMicrolocks".to_string()));
        }

        let block_hash_str = regex
            .captures(&preamble.path)
            .ok_or(net_error::DeserializeError("Failed to match path to microblock hash".to_string()))?
            .get(1)
            .ok_or(net_error::DeserializeError("Failed to match path to microblock hash group".to_string()))?
            .as_str();

        let block_hash = BlockHeaderHash::from_hex(block_hash_str)
            .map_err(|_e| net_error::DeserializeError("Failed to parse microblock hash".to_string()))?;

        Ok(HttpRequestType::GetMicroblocks(HttpRequestMetadata::from_preamble(preamble), block_hash))
    }

    fn parse_posttransaction<R: Read>(protocol: &mut StacksHttp, preamble: &HttpRequestPreamble, _regex: &Regex, fd: &mut R) -> Result<HttpRequestType, net_error> {
        if preamble.get_content_length() == 0 {
            return Err(net_error::DeserializeError("Invalid Http request: expected non-zero-length body for PostTransaction".to_string()));
        }

        // content-type must be given, and must be application/octet-stream
        match preamble.content_type {
            None => {
                return Err(net_error::DeserializeError("Missing Content-Type for transaction".to_string()));
            },
            Some(ref c) => {
                if *c != HttpContentType::Bytes {
                    return Err(net_error::DeserializeError("Wrong Content-Type for transaction; expected application/octet-stream".to_string()));
                }
            }
        };

        let tx = StacksTransaction::consensus_deserialize(fd)?;
        Ok(HttpRequestType::PostTransaction(HttpRequestMetadata::from_preamble(preamble), tx))
    }

    pub fn metadata(&self) -> &HttpRequestMetadata {
        match *self {
            HttpRequestType::GetNeighbors(ref md) => md,
            HttpRequestType::GetBlock(ref md, _) => md,
            HttpRequestType::GetMicroblocks(ref md, _) => md,
            HttpRequestType::PostTransaction(ref md, _) => md,
        }
    }

    pub fn send<W: Write>(&self, protocol: &mut StacksHttp, fd: &mut W) -> Result<(), net_error> {
        match *self {
            HttpRequestType::GetNeighbors(ref md) => {
                HttpRequestPreamble::new_serialized(fd, "GET", "/v2/neighbors", &md.peer, md.request_id, None, None, "")?;
            },
            HttpRequestType::GetBlock(ref md, ref block_hash) => {
                HttpRequestPreamble::new_serialized(fd, "GET", &format!("/v2/blocks/{}", block_hash.to_hex()), &md.peer, md.request_id, None, None, "")?;
            },
            HttpRequestType::GetMicroblocks(ref md, ref block_hash) => {
                HttpRequestPreamble::new_serialized(fd, "GET", &format!("/v2/microblocks/{}", block_hash.to_hex()), &md.peer, md.request_id, None, None, "")?;
            },
            HttpRequestType::PostTransaction(ref md, ref tx) => {
                let mut tx_bytes = vec![];
                write_next(&mut tx_bytes, tx)?;

                HttpRequestPreamble::new_serialized(fd, "POST", "/v2/transactions", &md.peer, md.request_id, Some(tx_bytes.len() as u32), Some(&HttpContentType::Bytes), "")?;
                fd.write_all(&tx_bytes).map_err(net_error::WriteError)?;
            }
        }
        Ok(())
    }
}

impl HttpResponseType {
    fn try_parse<R: Read, F>(protocol: &mut StacksHttp, regex: &Regex, preamble: &HttpResponsePreamble, fd: &mut R, len_hint: Option<usize>, parser: F) -> Result<Option<HttpResponseType>, net_error>
    where
        F: Fn(&mut StacksHttp, &HttpResponsePreamble, &mut R, Option<usize>) -> Result<HttpResponseType, net_error>
    {
        if regex.is_match(&preamble.request_path) {
            let payload = parser(protocol, preamble, fd, len_hint)?;
            Ok(Some(payload))
        }
        else {
            Ok(None)
        }
    }

    fn parse_error<R: Read>(protocol: &mut StacksHttp, preamble: &HttpResponsePreamble, fd: &mut R) -> Result<HttpResponseType, net_error> {
        if preamble.status_code < 400 || preamble.status_code > 599 {
            return Err(net_error::DeserializeError("Inavlid response: not an error".to_string()));
        }
        
        if preamble.content_type != HttpContentType::Text {
            return Err(net_error::DeserializeError("Invalid error response: expected text/plain".to_string()));
        }

        let mut error_text = String::new();
        fd.read_to_string(&mut error_text).map_err(net_error::ReadError)?;

        let md = HttpResponseMetadata::from_preamble(preamble);
        let resp = match preamble.status_code {
            400 => HttpResponseType::BadRequest(md, error_text),
            401 => HttpResponseType::Unauthorized(md, error_text),
            402 => HttpResponseType::PaymentRequired(md, error_text),
            403 => HttpResponseType::Forbidden(md, error_text),
            404 => HttpResponseType::NotFound(md, error_text),
            500 => HttpResponseType::ServerError(md, error_text),
            503 => HttpResponseType::ServiceUnavailable(md, error_text),
            _ => HttpResponseType::Error(md, preamble.status_code, error_text)
        };
        Ok(resp)
    }

    fn parse_bytestream<R: Read, T: StacksMessageCodec>(preamble: &HttpResponsePreamble, fd: &mut R, len_hint: Option<usize>, max_len: u64) -> Result<T, net_error> {
        // content-type has to be Bytes
        if preamble.content_type != HttpContentType::Bytes {
            return Err(net_error::DeserializeError("Invalid content-type: expected application/octet-stream".to_string()));
        }

        let item : T =
            if preamble.is_chunked() && len_hint.is_none() {
                let mut chunked_fd = HttpChunkedTransferReader::from_reader(fd, max_len);
                read_next(&mut chunked_fd)?
            }
            else {
                let content_length_opt = match (preamble.content_length, len_hint) {
                    (Some(l), _) => Some(l as u32),
                    (None, Some(l)) => Some(l as u32),
                    (None, None) => None
                };
                if let Some(content_length) = content_length_opt {
                    if (content_length as u64) > max_len {
                        return Err(net_error::DeserializeError("Invalid Content-Length header: too long".to_string()));
                    }

                    let mut bound_fd = BoundReader::from_reader(fd, content_length as u64);
                    read_next(&mut bound_fd)?
                }
                else {
                    // unsupported headers
                    trace!("preamble: {:?}", preamble);
                    return Err(net_error::DeserializeError("Invalid headers: need either Transfer-Encoding or Content-Length".to_string()));
                }
            };

        Ok(item)
    }

    fn parse_json<R: Read, T: serde::de::DeserializeOwned>(preamble: &HttpResponsePreamble, fd: &mut R, len_hint: Option<usize>, max_len: u64) -> Result<T, net_error> {
        // content-type has to be JSON
        if preamble.content_type != HttpContentType::JSON {
            return Err(net_error::DeserializeError("Invalid content-type: expected application/json".to_string()));
        }

        let item_result : Result<T, serde_json::Error> =
            if preamble.is_chunked() && len_hint.is_none() {
                let chunked_fd = HttpChunkedTransferReader::from_reader(fd, max_len);
                serde_json::from_reader(chunked_fd)
            }
            else {
                let content_length_opt = match (preamble.content_length, len_hint) {
                    (Some(l), _) => Some(l as u32),
                    (None, Some(l)) => Some(l as u32),
                    (None, None) => None
                };
                if let Some(content_length) = content_length_opt {
                    if (content_length as u64) > max_len {
                        return Err(net_error::DeserializeError("Invalid Content-Length header: too long".to_string()));
                    }
                    let bound_fd = BoundReader::from_reader(fd, content_length as u64);
                    serde_json::from_reader(bound_fd)
                }
                else {
                    // unsupported headers
                    trace!("preamble: {:?}", preamble);
                    return Err(net_error::DeserializeError("Invalid headers: need either Transfer-Encoding or Content-Length".to_string()));
                }
            };

        item_result.map_err(|e| {
            if e.is_eof() {
                net_error::UnderflowError(format!("Not enough bytes to parse Neighbors JSON"))
            }
            else {
                net_error::DeserializeError(format!("Failed to parse Neighbors JSON: {:?}", &e))
            }
        })
    }

    fn parse_text<R: Read>(preamble: &HttpResponsePreamble, fd: &mut R, len_hint: Option<usize>, max_len: u64) -> Result<Vec<u8>, net_error> {
        // content-type has to be text/plain
        if preamble.content_type != HttpContentType::Text {
            return Err(net_error::DeserializeError("Invalid content-type: expected text/plain".to_string()));
        }
        let buf =
            if preamble.is_chunked() && len_hint.is_none() {
                let mut chunked_fd = HttpChunkedTransferReader::from_reader(fd, max_len);
                let mut buf = vec![];
                chunked_fd.read_to_end(&mut buf).map_err(net_error::ReadError)?;
                buf
            }
            else {
                let content_length_opt = match (preamble.content_length, len_hint) {
                    (Some(l), _) => Some(l as u32),
                    (None, Some(l)) => Some(l as u32),
                    (None, None) => None
                };
                if let Some(len) = content_length_opt {
                    let mut buf = vec![0u8; len as usize];
                    fd.read_exact(&mut buf).map_err(net_error::ReadError)?;
                    buf
                }
                else {
                    // unsupported headers
                    trace!("preamble: {:?}", preamble);
                    return Err(net_error::DeserializeError("Invalid headers: need either Transfer-Encoding or Content-Length".to_string()));
                }
            };

        Ok(buf)
    }

    // len_hint is given by the StacksHttp protocol implementation
    pub fn parse<R: Read>(protocol: &mut StacksHttp, preamble: &HttpResponsePreamble, fd: &mut R, len_hint: Option<usize>) -> Result<HttpResponseType, net_error> {
        if preamble.status_code >= 400 {
            return HttpResponseType::parse_error(protocol, preamble, fd);
        }

        // TODO: make this static somehow
        let RESPONSE_METHODS : [(&Regex, &dyn Fn(&mut StacksHttp, &HttpResponsePreamble, &mut R, Option<usize>) -> Result<HttpResponseType, net_error>); 4] = [
            (&PATH_GETNEIGHBORS, &HttpResponseType::parse_neighbors),
            (&PATH_GETBLOCK, &HttpResponseType::parse_block),
            (&PATH_GETMICROBLOCKS, &HttpResponseType::parse_microblocks),
            (&PATH_POSTTRANSACTION, &HttpResponseType::parse_txid)
        ];

        for (regex, parser) in RESPONSE_METHODS.iter() {
            match HttpResponseType::try_parse(protocol, regex, preamble, fd, len_hint, parser) {
                Ok(Some(request)) => {
                    return Ok(request);
                },
                Ok(None) => {
                    continue;
                },
                Err(e) => {
                    return Err(e);
                }
            }
        }

        return Err(net_error::DeserializeError("Http response could not be parsed".to_string()));
    }

    fn parse_neighbors<R: Read>(protocol: &mut StacksHttp, preamble: &HttpResponsePreamble, fd: &mut R, len_hint: Option<usize>) -> Result<HttpResponseType, net_error> {
        let neighbors_data = HttpResponseType::parse_json(preamble, fd, len_hint, MAX_MESSAGE_LEN as u64)?;
        Ok(HttpResponseType::Neighbors(HttpResponseMetadata::from_preamble(preamble), neighbors_data))
    }

    fn parse_block<R: Read>(protocol: &mut StacksHttp, preamble: &HttpResponsePreamble, fd: &mut R, len_hint: Option<usize>) -> Result<HttpResponseType, net_error> {
        let block : StacksBlock = HttpResponseType::parse_bytestream(preamble, fd, len_hint, MAX_MESSAGE_LEN as u64)?;
        Ok(HttpResponseType::Block(HttpResponseMetadata::from_preamble(preamble), block))
    }

    fn parse_microblocks<R: Read>(protocol: &mut StacksHttp, preamble: &HttpResponsePreamble, fd: &mut R, len_hint: Option<usize>) -> Result<HttpResponseType, net_error> {
        let microblocks : Vec<StacksMicroblock> = HttpResponseType::parse_bytestream(preamble, fd, len_hint, MAX_MESSAGE_LEN as u64)?;
        Ok(HttpResponseType::Microblocks(HttpResponseMetadata::from_preamble(preamble), microblocks))
    }

    fn parse_txid<R: Read>(protocol: &mut StacksHttp, preamble: &HttpResponsePreamble, fd: &mut R, len_hint: Option<usize>) -> Result<HttpResponseType, net_error> {
        let txid_buf = HttpResponseType::parse_text(preamble, fd, len_hint, 64)?;
        if txid_buf.len() != 64 {
            return Err(net_error::DeserializeError("Invalid txid: expected 64 bytes".to_string()));
        }

        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&txid_buf);

        let hex_str = str::from_utf8(&bytes).map_err(|_e| net_error::DeserializeError("Failed to decode a txid".to_string()))?;
        let txid_bytes = hex_bytes(hex_str).map_err(|_e| net_error::DeserializeError("Failed to decode txid hex".to_string()))?;
        Ok(HttpResponseType::TransactionID(HttpResponseMetadata::from_preamble(preamble), Txid::from_bytes(&txid_bytes).unwrap()))
    }

    fn error_reason(code: u16) -> &'static str {
        match code {
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            503 => "Service Temporarily Unavailable",
            _ => "Error"
        }
    }

    fn error_response<W: Write>(&self, fd: &mut W, code: u16, message: &str) -> Result<(), net_error> {
        let md = self.metadata();
        HttpResponsePreamble::new_serialized(fd, code, HttpResponseType::error_reason(code), Some(message.len() as u32), &HttpContentType::Text, md.request_id, &md.request_path, "")?;
        fd.write_all(message.as_bytes()).map_err(net_error::WriteError)?;
        Ok(())
    }
    
    pub fn metadata(&self) -> &HttpResponseMetadata {
        match *self {
            HttpResponseType::Neighbors(ref md, _) => md,
            HttpResponseType::Block(ref md, _) => md,
            HttpResponseType::Microblocks(ref md, _) => md,
            HttpResponseType::TransactionID(ref md, _) => md,
            // errors
            HttpResponseType::BadRequest(ref md, _) => md,
            HttpResponseType::Unauthorized(ref md, _) => md,
            HttpResponseType::PaymentRequired(ref md, _) => md,
            HttpResponseType::Forbidden(ref md, _) => md,
            HttpResponseType::NotFound(ref md, _) => md,
            HttpResponseType::ServerError(ref md, _) => md,
            HttpResponseType::ServiceUnavailable(ref md, _) => md,
            HttpResponseType::Error(ref md, _, _) => md,
        }
    }

    fn send_bytestream<W: Write, T: StacksMessageCodec>(protocol: &mut StacksHttp, md: &HttpResponseMetadata, fd: &mut W, message: &T) -> Result<(), net_error> {
        if md.content_length.is_some() {
            // have explicit content-length, so we can send as-is
            write_next(fd, message)
        }
        else {
            // no content-length, so send as chunk-encoded
            let mut encoder = HttpChunkedTransferWriter::from_writer(fd, protocol.chunk_size);
            write_next(&mut encoder, message)
        }
    }

    fn send_text<W: Write>(protocol: &mut StacksHttp, md: &HttpResponseMetadata, fd: &mut W, text: &[u8]) -> Result<(), net_error> {
        if md.content_length.is_some() {
            // have explicit content-length, so we can send as-is
            fd.write_all(text).map_err(net_error::WriteError)
        }
        else {
            // no content-length, so send as chunk-encoded
            let mut encoder = HttpChunkedTransferWriter::from_writer(fd, protocol.chunk_size);
            encoder.write_all(text).map_err(net_error::WriteError)
        }
    }
    
    fn send_json<W: Write, T: serde::ser::Serialize>(protocol: &mut StacksHttp, md: &HttpResponseMetadata, fd: &mut W, message: &T) -> Result<(), net_error> {
        if md.content_length.is_some() {
            // have explicit content-length, so we can send as-is
            serde_json::to_writer(fd, message).map_err(|e| net_error::SerializeError(format!("Failed to send as JSON: {:?}", &e)))
        }
        else {
            // no content-length, so send as chunk-encoded
            let mut encoder = HttpChunkedTransferWriter::from_writer(fd, protocol.chunk_size);
            serde_json::to_writer(&mut encoder, message).map_err(|e| net_error::SerializeError(format!("Failed to send as chunk-encoded JSON: {:?}", &e)))
        }
    }

    pub fn send<W: Write>(&self, protocol: &mut StacksHttp, fd: &mut W) -> Result<(), net_error> {
        match *self {
            HttpResponseType::Neighbors(ref md, ref neighbor_data) => {
                HttpResponsePreamble::new_serialized(fd, 200, "OK", md.content_length.clone(), &HttpContentType::JSON, md.request_id, &md.request_path, "")?;
                HttpResponseType::send_json(protocol, md, fd, neighbor_data)?;
            },
            HttpResponseType::Block(ref md, ref block) => {
                // TODO; stream from disk using `protocol`
                HttpResponsePreamble::new_serialized(fd, 200, "OK", md.content_length.clone(), &HttpContentType::Bytes, md.request_id, &md.request_path, "")?;
                HttpResponseType::send_bytestream(protocol, md, fd, block)?;
            },
            HttpResponseType::Microblocks(ref md, ref microblocks) => {
                // TODO: stream from disk using `protocol`
                HttpResponsePreamble::new_serialized(fd, 200, "OK", md.content_length.clone(), &HttpContentType::Bytes, md.request_id, &md.request_path, "")?;
                HttpResponseType::send_bytestream(protocol, md, fd, microblocks)?;
            },
            HttpResponseType::TransactionID(ref md, ref txid) => {
                let txid_bytes = txid.to_hex().into_bytes();
                HttpResponsePreamble::new_serialized(fd, 200, "OK", md.content_length.clone(), &HttpContentType::Text, md.request_id, &md.request_path, "")?;
                HttpResponseType::send_text(protocol, md, fd, &txid_bytes)?;
            },
            HttpResponseType::BadRequest(ref md, ref msg) => self.error_response(fd, 400, msg)?,
            HttpResponseType::Unauthorized(ref md, ref msg) => self.error_response(fd, 401, msg)?,
            HttpResponseType::PaymentRequired(ref md, ref msg) => self.error_response(fd, 402, msg)?,
            HttpResponseType::Forbidden(ref md, ref msg) => self.error_response(fd, 403, msg)?,
            HttpResponseType::NotFound(ref md, ref msg) => self.error_response(fd, 404, msg)?,
            HttpResponseType::ServerError(ref md, ref msg) => self.error_response(fd, 500, msg)?,
            HttpResponseType::ServiceUnavailable(ref md, ref msg) => self.error_response(fd, 503, msg)?,
            HttpResponseType::Error(ref md, ref error_code, ref msg) => self.error_response(fd, *error_code, msg)?
        };
        Ok(())
    }
}

lazy_static! {
    static ref PATH_GETNEIGHBORS: Regex = Regex::new(r#"^/v2/neighbors$"#).unwrap();
    static ref PATH_GETBLOCK : Regex = Regex::new(r#"^/v2/blocks/([0-9a-f]{64})$"#).unwrap();
    static ref PATH_GETMICROBLOCKS : Regex = Regex::new(r#"^/v2/microblocks/([0-9a-f]{64})$"#).unwrap();
    static ref PATH_POSTTRANSACTION : Regex = Regex::new(r#"^/v2/transactions$"#).unwrap();
}

impl StacksMessageCodec for StacksHttpPreamble {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), net_error> {
        match *self {
            StacksHttpPreamble::Request(ref req) => req.consensus_serialize(fd),
            StacksHttpPreamble::Response(ref res) => res.consensus_serialize(fd),
        }
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<StacksHttpPreamble, net_error> {
        let mut retry_fd = RetryReader::new(fd);

        // the byte stream can decode to a http request or a http response, but not both.
        match HttpRequestPreamble::consensus_deserialize(&mut retry_fd) {
            Ok(request) => Ok(StacksHttpPreamble::Request(request)),
            Err(e_request) => {
                // maybe a http response?
                retry_fd.set_position(0);
                match HttpResponsePreamble::consensus_deserialize(&mut retry_fd) {
                    Ok(response) => Ok(StacksHttpPreamble::Response(response)),
                    Err(e) => {
                        // underflow?
                        match (e_request, e) {
                            (net_error::ReadError(ref ioe1), net_error::ReadError(ref ioe2)) => {
                                if ioe1.kind() == io::ErrorKind::UnexpectedEof && ioe2.kind() == io::ErrorKind::UnexpectedEof {
                                    // out of bytes
                                    Err(net_error::UnderflowError("Not enough bytes to form a HTTP request or response".to_string()))
                                }
                                else {
                                    Err(net_error::DeserializeError(format!("Neither a HTTP request ({:?}) or HTTP response ({:?})", ioe1, ioe2)))
                                }
                            },
                            (_, _) => Err(net_error::DeserializeError("Failed to decode HTTP request or HTTP response".to_string()))
                        }
                    }
                }
            }
        }
    }
}

impl MessageSequence for StacksHttpMessage {
    fn request_id(&self) -> u32 {
        match *self {
            StacksHttpMessage::Request(ref req) => req.metadata().request_id,
            StacksHttpMessage::Response(ref res) => res.metadata().request_id,
        }
    }

    fn get_message_name(&self) -> &'static str {
        match *self {
            StacksHttpMessage::Request(ref req) => match req {
                HttpRequestType::GetNeighbors(_) => "HTTP(GetNeighbors)",
                HttpRequestType::GetBlock(_, _) => "HTTP(GetBlock)",
                HttpRequestType::GetMicroblocks(_, _) => "HTTP(GetMicroblocks)",
                HttpRequestType::PostTransaction(_, _) => "HTTP(PostTransaction)"
            },
            StacksHttpMessage::Response(ref res) => match res {
                HttpResponseType::Neighbors(_, _) => "HTTP(Neighbors)",
                HttpResponseType::Block(_, _) => "HTTP(Block)",
                HttpResponseType::Microblocks(_, _) => "HTTP(Microbloks)",
                HttpResponseType::TransactionID(_, _) => "HTTP(Transaction)",
                HttpResponseType::BadRequest(_, _) => "HTTP(400)",
                HttpResponseType::Unauthorized(_, _) => "HTTP(401)",
                HttpResponseType::PaymentRequired(_, _) => "HTTP(402)",
                HttpResponseType::Forbidden(_, _) => "HTTP(403)",
                HttpResponseType::NotFound(_, _) => "HTTP(404)",
                HttpResponseType::ServerError(_, _) => "HTTP(500)",
                HttpResponseType::ServiceUnavailable(_, _) => "HTTP(503)",
                HttpResponseType::Error(_, _, _) => "HTTP(other)"
            }
        }
    }
}


/// A partially-decoded, streamed HTTP message (response).
/// Internally used by StacksHttp to keep track of chunk-decoding state.
#[derive(Debug, Clone, PartialEq)]
struct HttpMessageStream {
    state: HttpChunkedTransferReaderState,
    data: Vec<u8>,
    total_consumed: usize,      // number of *encoded* bytes consumed
}

impl HttpMessageStream {
    pub fn new(max_size: u64) -> HttpMessageStream {
        HttpMessageStream {
            state: HttpChunkedTransferReaderState::new(max_size),
            data: vec![],
            total_consumed: 0
        }
    }

    /// Feed data into our chunked transfer reader state.  If we finish reading a stream, return
    /// the decoded bytes (as Some(Vec<u8>) and the total number of encoded bytes consumed).
    /// Always returns the number of bytes consumed.
    pub fn consume_data<R: Read>(&mut self, fd: &mut R) -> Result<(Option<(Vec<u8>, usize)>, usize), net_error> {
        let mut consumed = 0;
        let mut blocked = false;
        while !blocked {
            let mut decoded_buf = vec![0u8; 8192];
            let (read_pass, consumed_pass) = match self.state.do_read(fd, &mut decoded_buf) {
                Ok((0, num_consumed)) => {
                    trace!("consume_data blocked on 0 decoded bytes ({} consumed)", num_consumed);
                    blocked = true;
                    (0, num_consumed)
                },
                Ok((num_read, num_consumed)) => {
                    (num_read, num_consumed)
                },
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                        trace!("consume_data blocked on read error");
                        blocked = true;
                        (0, 0)
                    },
                    _ => {
                        return Err(net_error::ReadError(e));
                    }
                }
            };

            consumed += consumed_pass;
            if read_pass > 0 {
                self.data.extend_from_slice(&decoded_buf[0..read_pass]);
            }
        }
        
        self.total_consumed += consumed;

        // did we get a message?
        if self.state.is_eof() {
            // reset
            let message_data = mem::replace(&mut self.data, vec![]);
            let total_consumed = self.total_consumed;

            self.state = HttpChunkedTransferReaderState::new(self.state.max_size);
            self.total_consumed = 0;

            Ok((Some((message_data, total_consumed)), consumed))
        }
        else {
            Ok((None, consumed))
        }
    }
}

/// Stacks HTTP implementation, for bufferring up data
#[derive(Debug, Clone, PartialEq)]
pub struct StacksHttp {
    /// Partially-received chunk-encoded messages, keyed by request ID and path
    pending: HashMap<(u32, String), HttpMessageStream>,
    /// Size of HTTP chunks to write
    chunk_size: usize
}

impl StacksHttp {
    // TODO; link this to the stacks chain state, peer db, and so on.
    pub fn new() -> StacksHttp {
        StacksHttp {
            pending: HashMap::new(),
            chunk_size: 8192
        }
    }

    pub fn set_chunk_size(&mut self, size: usize) -> () {
        self.chunk_size = size;
    }

    /// Used for processing chunk-encoded streams.
    /// Given the preamble and a Read, stream the bytes into a chunk-decoder.  Return the decoded
    /// bytes if we decode an entire stream.  Always return the number of bytes consumed.
    pub fn consume_data<R: Read>(&mut self, preamble: &HttpResponsePreamble, fd: &mut R) -> Result<(Option<(Vec<u8>, usize)>, usize), net_error> {
        assert!(preamble.is_chunked());
        let key = (preamble.request_id, preamble.request_path.clone());
        if !self.pending.contains_key(&key) {
            self.pending.insert(key.clone(), HttpMessageStream::new(MAX_MESSAGE_LEN as u64));
        }

        match self.pending.get_mut(&key) {
            Some(ref mut stream) => stream.consume_data(fd),
            None => {
                unreachable!()
            }
        }
    }
}

impl ProtocolFamily for StacksHttp {
    type Preamble = StacksHttpPreamble;
    type Message = StacksHttpMessage;

    /// how big can a preamble get?
    fn preamble_size_hint(&mut self) -> usize {
        HTTP_PREAMBLE_MAX_ENCODED_SIZE as usize
    }

    /// how big is this message?  Might not know if we're dealing with chunked encoding.
    fn payload_len(&mut self, preamble: &StacksHttpPreamble) -> Option<usize> {
        match *preamble {
            StacksHttpPreamble::Request(ref http_request_preamble) => Some(http_request_preamble.get_content_length() as usize),
            StacksHttpPreamble::Response(ref http_response_preamble) => match http_response_preamble.content_length {
                Some(len) => Some(len as usize),
                None => None
            }
        }
    }

    /// StacksHttpMessage deals with HttpRequestPreambles and HttpResponsePreambles
    fn read_preamble(&mut self, buf: &[u8]) -> Result<(StacksHttpPreamble, usize), net_error> {
        let mut cursor = io::Cursor::new(buf);
        let preamble : StacksHttpPreamble = read_next(&mut cursor)?;
        let preamble_len = cursor.position() as usize;
        Ok((preamble, preamble_len))
    }

    /// Stream a payload of unknown length.  Only gets called if payload_len() returns None.
    /// Returns the message if we get enough data to form one.
    /// Always returns the number of bytes consumed.
    fn stream_payload<R: Read>(&mut self, preamble: &StacksHttpPreamble, fd: &mut R) -> Result<(Option<(StacksHttpMessage, usize)>, usize), net_error> {
        assert!(self.payload_len(preamble).is_none());
        match preamble {
            StacksHttpPreamble::Request(ref http_request_preamble) => {
                // HTTP requests can't be chunk-encoded, so this should never be reached
                unreachable!()
            },
            StacksHttpPreamble::Response(ref http_response_preamble) => {
                assert!(http_response_preamble.is_chunked());

                // message of unknown length.  Buffer up and maybe we can parse it.
                let (message_bytes_opt, num_read) = self.consume_data(http_response_preamble, fd)?;
                match message_bytes_opt {
                    Some((message_bytes, total_bytes_consumed)) => {
                        // can parse!
                        trace!("read http response payload of {} bytes (bufferred {})", message_bytes.len(), num_read);

                        // we now know the content-length, so pass it into the parser.
                        let len_hint = message_bytes.len();
                        let mut cursor = io::Cursor::new(message_bytes);
                        match HttpResponseType::parse(self, http_response_preamble, &mut cursor, Some(len_hint)) {
                            Ok(data_response) => Ok((Some((StacksHttpMessage::Response(data_response), total_bytes_consumed)), num_read)),
                            Err(e) => Err(e)
                        }
                    },
                    None => {
                        // need more data
                        trace!("did not read http response payload, but bufferred {}", num_read);
                        Ok((None, num_read))
                    }
                }
            }
        }
    }

    /// Parse a payload of known length.
    /// Only gets called if payload_len() returns Some(...)
    fn read_payload(&mut self, preamble: &StacksHttpPreamble, buf: &[u8]) -> Result<(StacksHttpMessage, usize), net_error> {
        match preamble {
            StacksHttpPreamble::Request(ref http_request_preamble) => {
                // all requests have a known length
                let len = http_request_preamble.get_content_length() as usize;
                assert!(len <= buf.len(), "{} > {}", len, buf.len());
        
                trace!("read http request payload of {} bytes", len);

                let mut cursor = io::Cursor::new(buf);
                match HttpRequestType::parse(self, http_request_preamble, &mut cursor) {
                    Ok(data_request) => Ok((StacksHttpMessage::Request(data_request), cursor.position() as usize)),
                    Err(e) => Err(e)
                }
            },
            StacksHttpPreamble::Response(ref http_response_preamble) => {
                assert!(!http_response_preamble.is_chunked());
                // message of known length
                trace!("read http response payload of {} bytes", buf.len());
                
                let mut cursor = io::Cursor::new(buf);
                match HttpResponseType::parse(self, http_response_preamble, &mut cursor, None) {
                    Ok(data_response) => Ok((StacksHttpMessage::Response(data_response), cursor.position() as usize)),
                    Err(e) => Err(e)
                }
            }
        }
    }

    fn verify_payload_bytes(&mut self, _key: &StacksPublicKey, _preamble: &StacksHttpPreamble, _bytes: &[u8]) -> Result<(), net_error> {
        // not defined for HTTP messages, but maybe we could add a signature header at some point
        // in the future if needed.
        Ok(())
    }
    
    fn write_message<W: Write>(&mut self, fd: &mut W, message: &StacksHttpMessage) -> Result<(), net_error> {
        match *message {
            StacksHttpMessage::Request(ref req) => req.send(self, fd),
            StacksHttpMessage::Response(ref resp) => resp.send(self, fd)
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::error::Error;
    use net::test::*;
    use net::codec::test::check_codec_and_corruption;

    use chainstate::burn::BlockHeaderHash;
    use burnchains::Txid;
    use chainstate::stacks::test::make_codec_test_block;
    use chainstate::stacks::db::blocks::test::make_sample_microblock_stream;
    use chainstate::stacks::StacksTransaction;
    use chainstate::stacks::StacksBlockHeader;
    use chainstate::stacks::StacksBlock;
    use chainstate::stacks::StacksMicroblock;
    use chainstate::stacks::TransactionVersion;
    use chainstate::stacks::TransactionPayload;
    use chainstate::stacks::TransactionPostConditionMode;
    use chainstate::stacks::TransactionAuth;
    use chainstate::stacks::StacksAddress;
    use chainstate::stacks::TokenTransferMemo;

    use chainstate::stacks::StacksPrivateKey;

    use util::hash::Hash160;
    use util::hash::Sha512Trunc256Sum;
    use util::hash::MerkleTree;
    use util::hash::to_hex;

    use rand;
    use rand::RngCore;

    /// Simulate reading variable-length segments
    struct SegmentReader {
        segments: Vec<Vec<u8>>,
        i: usize,       // which segment
        j: usize,       // which offset in segment
    }

    impl SegmentReader {
        pub fn new(segments: Vec<Vec<u8>>) -> SegmentReader {
            SegmentReader {
                segments: segments,
                i: 0,
                j: 0
            }
        }
    }    

    impl Read for SegmentReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.i >= self.segments.len() {
                return Ok(0);
            }
            let mut written = 0;
            while written < buf.len() {
                let to_copy = 
                    if self.segments[self.i][self.j..].len() < buf[written..].len() {
                        self.segments[self.i][self.j..].len()
                    }
                    else {
                        buf[written..].len()
                    };

                buf[written..(written + to_copy)].copy_from_slice(&self.segments[self.i][self.j..(self.j + to_copy)]);

                self.j += to_copy;
                written += to_copy;

                if self.j >= self.segments[self.i].len() {
                    self.i += 1;
                    self.j = 0;
                }
            }
            Ok(written)
        }
    }

    fn vec_u8(mut v: Vec<&str>) -> Vec<Vec<u8>> {
        let mut ret = vec![];
        for s_vec in v.drain(..) {
            let v_u8 = s_vec.as_bytes().to_vec();
            ret.push(v_u8);
        }
        ret
    }

    #[test]
    fn test_segment_reader() {
        let mut tests = vec![
            (vec_u8(vec!["a", "b"]), "ab"),
            (vec_u8(vec!["aa", "bbb", "cccc"]), "aabbbcccc"),
            (vec_u8(vec!["aaaa", "bbb", "cc", "d", ""]), "aaaabbbccd"),
            (vec_u8(vec!["", "a", "", "b", ""]), "ab"),
            (vec_u8(vec![""]), "")
        ];
        for (input_vec, expected) in tests.drain(..) {
            let num_segments = input_vec.len();
            let mut segment_io = SegmentReader::new(input_vec);
            let mut output = vec![0u8; expected.len()];
            let mut offset = 0;
            for i in 0..num_segments {
                let nw = segment_io.read(&mut output[offset..]).unwrap();
                offset += nw;
            }
            assert_eq!(output, expected.as_bytes().to_vec());
        }
    }

    #[test]
    fn test_http_chunked_encode() {
        let tests = vec![
            // (chunk size, byte string, expected encoding)
            (10, "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd", "a\r\naaaaaaaaaa\r\na\r\nbbbbbbbbbb\r\na\r\ncccccccccc\r\na\r\ndddddddddd\r\n0\r\n\r\n"),
            (10, "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddde", "a\r\naaaaaaaaaa\r\na\r\nbbbbbbbbbb\r\na\r\ncccccccccc\r\na\r\ndddddddddd\r\n1\r\ne\r\n0\r\n\r\n"),
            (10, "aaaaaaaaaabbbbbbbbbbccccccccccddddddddddeeeee", "a\r\naaaaaaaaaa\r\na\r\nbbbbbbbbbb\r\na\r\ncccccccccc\r\na\r\ndddddddddd\r\n5\r\neeeee\r\n0\r\n\r\n"),
            (1, "abcd", "1\r\na\r\n1\r\nb\r\n1\r\nc\r\n1\r\nd\r\n0\r\n\r\n"),
            (3, "abcd", "3\r\nabc\r\n1\r\nd\r\n0\r\n\r\n"),
            (10, "", "0\r\n\r\n")
        ];
        for (chunk_size, input_bytes, encoding) in tests.iter() {
            let mut bytes = vec![];
            {
                let mut encoder = HttpChunkedTransferWriter::from_writer(&mut bytes, *chunk_size);
                encoder.write_all(input_bytes.as_bytes()).unwrap();
            }

            assert_eq!(bytes, encoding.as_bytes().to_vec());
        }
    }

    #[test]
    fn test_http_chunked_encode_multi() {
        let tests = vec![
            // chunk size, sequence of writes, expected encoding
            (10, vec!["aaaaaaaaaa", "bbbbb", "bbbbb", "ccc", "ccc", "ccc", "c", "dd", "ddddd", "ddd"], "a\r\naaaaaaaaaa\r\na\r\nbbbbbbbbbb\r\na\r\ncccccccccc\r\na\r\ndddddddddd\r\n0\r\n\r\n"),
            (10, vec!["a", "a", "a", "a", "a", "a", "a", "a", "a", "a"], "a\r\naaaaaaaaaa\r\n0\r\n\r\n"),
            (10, vec!["a", "", "a", "", "a", "", "a", "", "a", "", "a", "", "a", "", "a", "", "a", "", "a", ""], "a\r\naaaaaaaaaa\r\n0\r\n\r\n"),
        ];

        for (chunk_size, input_vec, encoding) in tests.iter() {
            let mut bytes = vec![];
            {
                let mut encoder = HttpChunkedTransferWriter::from_writer(&mut bytes, *chunk_size);
                for input in input_vec.iter() {
                    encoder.write_all(input.as_bytes()).unwrap();
                }
            }

            assert_eq!(bytes, encoding.as_bytes().to_vec());
        }
    }
    
    #[test]
    fn test_http_chunked_decode() {
        let tests = vec![
            ("a\r\naaaaaaaaaa\r\na\r\nbbbbbbbbbb\r\na\r\ncccccccccc\r\na\r\ndddddddddd\r\n0\r\n\r\n", "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd"),
            ("A\r\naaaaaaaaaa\r\nA\r\nbbbbbbbbbb\r\nA\r\ncccccccccc\r\nA\r\ndddddddddd\r\n0\r\n\r\n", "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd"),
            ("1\r\na\r\n2\r\nbb\r\n3\r\nccc\r\n4\r\ndddd\r\n0\r\n\r\n", "abbcccdddd"),
            ("1\r\na\r\n0\r\n\r\n", "a"),
            ("1\r\na\r\n0\r\n\r\n1\r\nb\r\n0\r\n\r\n", "a"),     // stop reading after the first 0-length chunk encountered
            ("1; a; b\r\na\r\n0; c\r\n\r\n", "a"),                          // ignore short extensions
            ("1  ; a ; b \r\na\r\n0     ; extension003\r\n\r\n", "a"),      // ignore short extensions
            ("1 \t; a\t;\tb ;\r\na\r\n0\t\t;c\r\n\r\n", "a"),               // ignore short extensions
        ];
        for (encoded, expected) in tests.iter() {
            let mut cursor = io::Cursor::new(encoded.as_bytes());
            let mut decoder = HttpChunkedTransferReader::from_reader(&mut cursor, 50);
            let mut output = vec![0u8; expected.len()];
            decoder.read_exact(&mut output).unwrap();
            
            assert_eq!(output, expected.as_bytes().to_vec());
        }
    }

    #[test]
    fn test_http_chunked_decode_multi() {
        let tests = vec![
            (vec_u8(vec!["1\r\na", "\r\n", "0\r\n\r\n"]), "a"),
            (vec_u8(vec!["1\r\na\r", "\n0\r\n\r\n"]), "a"),
            (vec_u8(vec!["1\r\na\r\n", "0\r\n\r", "\n"]), "a"),
            (vec_u8(vec!["1\r\na\r\n0\r\n", "\r\n"]), "a"),
            (vec_u8(vec!["1\r\na\r\n0\r", "\n\r\n"]), "a"),
            (vec_u8(vec!["1\r\na\r\n0\r", "\n", "\r\n"]), "a"),
            (vec_u8(vec!["1\r\na\r\n0\r", "\n\r", "\n"]), "a"),
            (vec_u8(vec!["1\r\na\r\n0\r", "\n", "\r", "\n"]), "a"),
            (vec_u8(vec!["1", "\r", "\n", "a", "\r", "\n", "0", "\r", "\n", "\r", "\n"]), "a"),
            (vec_u8(vec!["a\r", "\n", "aaaa", "aaaaa", "a", "\r\n", "a\r\n", "bbbbbbbbbb\r", "\na\r\nccc", "ccccccc", "\r", "\na\r", "\ndddddd", "dddd", "\r\n0\r", "\n", "\r", "\n"]), "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd"),
            (vec_u8(vec!["a\r\naaaaaaaaaa", "\r", "\n", "a\r\nbbbbbbbbbb\r", "\n", "a\r\ncccccccccc\r", "\na\r\nddddd", "ddddd\r", "\n0\r", "\n\r", "\n"]), "aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd"),
            (vec_u8(vec!["1", "\r", "\n", "", "a", "\r", "\n", "2", "\r\n", "bb", "\r\n", "3\r\n", "ccc\r", "\n4\r\n", "dddd\r\n", "0\r\n\r\n"]), "abbcccdddd"),
        ];
        for (encoded_vec, expected) in tests.iter() {
            test_debug!("expect {:?}", &expected);

            let mut output = vec![];
            let mut cursor = SegmentReader::new((*encoded_vec).clone());
            let mut decoder = HttpChunkedTransferReader::from_reader(&mut cursor, 50);

            for encoded in encoded_vec.iter() {
                let mut tmp = vec![0u8; encoded.len()];
                let nr = decoder.read(&mut tmp).unwrap();

                output.extend_from_slice(&tmp[0..nr]);
            }

            assert_eq!(output, expected.as_bytes().to_vec());
        }
    }

    #[test]
    fn test_http_chunked_decode_err() {
        let tests = vec![
            ("1; reallyreallyreallyreallylongextension;\r\na\r\n0\r\n\r\n", 1, "too long"),
            ("ffffffff\r\n", 1, "too big"),
            ("nope\r\n", 1, "could not parse"),
            ("1\na\r\n0\r\n\r\n",1,  "could not parse"),
            ("a\r\naaaaaaaaaa", 11, "failed to fill whole buffer"),
            ("1\r\nab\r\n0\r\n\r\n", 2, "Invalid chunk trailer"),
            ("15\r\naaaaaaaaaabbbbbbbbbbb\r\n0\r\n\r\n", 21, "HTTP body exceeds maximum expected length"),
            ("7\r\naaaaaaa\r\n8\r\nbbbbbbbb\r\n6\r\ncccccc\r\n0\r\n\r\n", 21, "HTTP body exceeds maximum expected length")
        ];
        for (encoded, expected_len, expected) in tests.iter() {
            test_debug!("expect '{}'", expected);
            let mut cursor = io::Cursor::new(encoded.as_bytes());
            let mut decoder = HttpChunkedTransferReader::from_reader(&mut cursor, 20);
            let mut output = vec![0u8; *expected_len as usize];
            
            let err = decoder.read_exact(&mut output).unwrap_err();
            let errstr = format!("{:?}", &err);

            assert!(errstr.find(expected).is_some(), "Expected '{}' in '{:?}'", expected, errstr);
        }
    }

    #[test]
    fn test_http_chunked_encode_decode_roundtrip() {
        let mut rng = rand::thread_rng();
        for i in 0..100 {
            let mut data = vec![0u8; 256];
            rng.fill_bytes(&mut data);

            let mut encoded_data = vec![];
            {
                let mut encoder = HttpChunkedTransferWriter::from_writer(&mut encoded_data, i+1);
                encoder.write_all(&data).unwrap();
            }

            let mut decoded_data = vec![0u8; 256];
            {
                let mut decode_fd = io::Cursor::new(&mut encoded_data);
                let mut decoder = HttpChunkedTransferReader::from_reader(&mut decode_fd, 256);
                decoder.read_exact(&mut decoded_data).unwrap();
            }

            assert_eq!(data, decoded_data);
        }
    }

    #[test]
    fn test_bound_reader() {
        let tests = [
            ("aaaaaaaaaa", 10, "aaaaaaaaaa"),
            ("bbbbbbbbbb", 9,  "bbbbbbbbb"),
            ("cccccccccc", 1,  "c"),
            ("dddddddddd", 0,  ""),
        ];
        // read_to_end
        for (data, len, expected) in tests.iter() {
            let mut cursor = io::Cursor::new(data.as_bytes());
            let mut reader = BoundReader::from_reader(&mut cursor, *len as u64);
            let mut buf = vec![];
            reader.read_to_end(&mut buf).unwrap();
            assert_eq!(buf.len(), *len);
            assert_eq!(buf, expected.as_bytes().to_vec());

            // should EOF once length is exceeded
            let mut buf2 = vec![0u8; *len];
            let nr = reader.read(&mut buf2).unwrap();
            assert_eq!(nr, 0);
            assert_eq!(buf2, vec![0u8; *len]);
        }

        // read piecemeal
        for (data, len, expected) in tests.iter() {
            let mut cursor = io::Cursor::new(data.as_bytes());
            let mut reader = BoundReader::from_reader(&mut cursor, *len as u64);
            let mut buf = vec![];
            
            for i in 0..*len {
                let mut tmp = [0u8; 1];
                let nr = reader.read(&mut tmp).unwrap();
                assert_eq!(nr, 1);
                buf.extend_from_slice(&tmp);
            }

            assert_eq!(buf.len(), *len);
            assert_eq!(buf, expected.as_bytes().to_vec());

            // should EOF once length is exceeded
            let mut buf2 = vec![0u8; *len];
            let nr = reader.read(&mut buf2).unwrap();
            assert_eq!(nr, 0);
            assert_eq!(buf2, vec![0u8; *len]);
        }
    }

    #[test]
    fn test_parse_reserved_header() {
        let tests = vec![
            ("Content-Length", "123", Some(HttpReservedHeader::ContentLength(123))),
            ("Content-Type", "text/plain", Some(HttpReservedHeader::ContentType(HttpContentType::Text))),
            ("Content-Type", "application/octet-stream", Some(HttpReservedHeader::ContentType(HttpContentType::Bytes))),
            ("Content-Type", "application/json", Some(HttpReservedHeader::ContentType(HttpContentType::JSON))),
            ("X-Request-Id", "123", Some(HttpReservedHeader::XRequestID(123))),
            ("X-Request-path", "/foo/bar", Some(HttpReservedHeader::XRequestPath("/foo/bar".to_string()))),
            ("Host", "foo:123", Some(HttpReservedHeader::Host(PeerHost::DNS("foo".to_string(), 123)))),
            ("Host", "1.2.3.4:123", Some(HttpReservedHeader::Host(PeerHost::IP(PeerAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04]), 123)))),
            // errors
            ("Content-Length", "-1", None),
            ("Content-Length", "asdf", None),
            ("Content-Length", "4294967296", None),
            ("Content-Type", "blargh", None),
            ("X-Request-Id", "-1", None),
            ("X-Request-Id", "asdf", None),
            ("X-Request-Id", "4294967296", None),
            ("Unrecognized", "header", None)
        ];

        for (key, value, expected_result) in tests {
            let result = HttpReservedHeader::try_from_str(key, value);
            assert_eq!(result, expected_result);
        }
    }

    #[test]
    fn test_parse_http_request_preamble_ok() {
        let tests = vec![
            ("GET /foo HTTP/1.1\r\nHost: localhost:6270\r\n\r\n",
             HttpRequestPreamble::from_headers("GET".to_string(), "/foo".to_string(), "localhost".to_string(), 6270, 0, vec![], vec![])),
            ("POST asdf HTTP/1.1\r\nHost: core.blockstack.org\r\nFoo: Bar\r\n\r\n",
             HttpRequestPreamble::from_headers("POST".to_string(), "asdf".to_string(), "core.blockstack.org".to_string(), 80, 0, vec!["foo".to_string()], vec!["Bar".to_string()])),
            ("POST asdf HTTP/1.1\r\nHost: core.blockstack.org\r\nFoo: Bar\r\nX-Request-Id: 123\r\n\r\n",
             HttpRequestPreamble::from_headers("POST".to_string(), "asdf".to_string(), "core.blockstack.org".to_string(), 80, 123, vec!["foo".to_string()], vec!["Bar".to_string()])) 
        ];

        for (data, request) in tests.iter() {
            let req = HttpRequestPreamble::consensus_deserialize(&mut io::Cursor::new(data));
            assert!(req.is_ok(), format!("{:?}", &req));
            assert_eq!(req.unwrap(), *request);

            let sreq = StacksHttpPreamble::consensus_deserialize(&mut io::Cursor::new(data));
            assert!(sreq.is_ok(), format!("{:?}", &sreq));
            assert_eq!(sreq.unwrap(), StacksHttpPreamble::Request((*request).clone()));
        }
    }

    #[test]
    fn test_parse_http_request_preamble_err() {
        let tests = vec![
            ("GET /foo HTTP/1.1\r\n",
            "failed to fill whole buffer"),
            ("GET /foo HTTP/1.1\r\n\r\n",
             "Missing Host header"),
            ("GET /foo HTTP/1.1\r\nFoo: Bar\r\n\r\n",
             "Missing Host header"),
            ("GET /foo HTTP/\r\n\r\n",
             "Failed to parse HTTP request"),
            ("GET /foo HTTP/1.1\r\nHost:",
             "failed to fill whole buffer"),
            ("GET /foo HTTP/1.1\r\nHost: foo:80\r\nHost: bar:80\r\n\r\n",
            "duplicate header"),
            ("GET /foo HTTP/1.1\r\nHost: localhost:6270\r\nfoo: \u{2764}\r\n\r\n",
            "header value is not ASCII-US"),
            ("Get /foo HTTP/1.1\r\nHost: localhost:666666\r\n\r\n",
             "Missing Host header")
        ];

        for (data, errstr) in tests.iter() {
            let res = HttpRequestPreamble::consensus_deserialize(&mut io::Cursor::new(data));
            test_debug!("Expect '{}'", errstr);
            let expected_errstr = format!("{:?}", &res);
            assert!(res.is_err(), expected_errstr);
            assert!(res.unwrap_err().description().find(errstr).is_some(), expected_errstr);
        }
    }

    #[test]
    fn test_parse_stacks_http_preamble_request_err() {
        let tests = vec![
            ("GET /foo HTTP/1.1\r\n",
             "Not enough bytes to form a HTTP request or response"),
            ("GET /foo HTTP/1.1\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("GET /foo HTTP/1.1\r\nFoo: Bar\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("GET /foo HTTP/\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("GET /foo HTTP/1.1\r\nHost:",
             "Not enough bytes to form a HTTP request or response"),
            ("GET /foo HTTP/1.1\r\nHost: foo:80\r\nHost: bar:80\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("GET /foo HTTP/1.1\r\nHost: localhost:6270\r\nfoo: \u{2764}\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("Get /foo HTTP/1.1\r\nHost: localhost:666666\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
        ];

        for (data, errstr) in tests.iter() {
            let sres = StacksHttpPreamble::consensus_deserialize(&mut io::Cursor::new(data));
            let expected_serrstr = format!("{:?}", &sres);
            test_debug!("Expect '{}'", errstr);
            assert!(sres.is_err(), expected_serrstr);
            assert!(sres.unwrap_err().description().find(errstr).is_some(), expected_serrstr);
        }
    }

    #[test]
    fn test_http_request_preamble_headers() {
        let mut req = HttpRequestPreamble::new("GET".to_string(), "/foo".to_string(), "localhost".to_string(), 6270, 0);
        assert_eq!(req.request_id, 0);

        req.set_request_id(123);
        assert_eq!(req.request_id, 123);

        req.add_header("foo".to_string(), "bar".to_string());

        assert_eq!(req.content_type, None);
        req.set_content_type(HttpContentType::JSON);
        assert_eq!(req.content_type, Some(HttpContentType::JSON));
        
        req.add_header("content-type".to_string(), "application/octet-stream".to_string());
        assert_eq!(req.content_type, Some(HttpContentType::Bytes));

        let mut bytes = vec![];
        req.consensus_serialize(&mut bytes).unwrap();
        let txt = String::from_utf8(bytes).unwrap();
        assert!(txt.find("User-Agent: stacks/2.0\r\n").is_some(), "User-Agnet header is missing");
        assert!(txt.find("Host: localhost:6270\r\n").is_some(), "Host header is missing");
        assert!(txt.find("X-Request-Id: 123\r\n").is_some(), "X-Request-Id is missing");
        assert!(txt.find("foo: bar\r\n").is_some(), "foo header is missing");
        assert!(txt.find("Content-Type: application/octet-stream\r\n").is_some(), "content-type is missing");
    }

    #[test]
    fn test_parse_http_response_preamble_ok() {
        let tests = vec![
            ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 123\r\nX-Request-ID: 0\r\nX-Request-Path: /foo\r\n\r\n",
             HttpResponsePreamble::from_headers(200, "OK".to_string(), Some(123), HttpContentType::Bytes, 0, "/foo".to_string(), vec![], vec![])),
            ("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 456\r\nFoo: Bar\r\nX-Request-ID: 0\r\nX-Request-Path: /foo\r\n\r\n",
             HttpResponsePreamble::from_headers(400, "Bad Request".to_string(), Some(456), HttpContentType::JSON, 0, "/foo".to_string(), vec!["foo".to_string()], vec!["Bar".to_string()])),
            ("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 456\r\nX-Request-Id: 123\r\nX-Request-path: /foo\r\nFoo: Bar\r\n\r\n",
             HttpResponsePreamble::from_headers(400, "Bad Request".to_string(), Some(456), HttpContentType::JSON, 123, "/foo".to_string(), vec!["foo".to_string()], vec!["Bar".to_string()])),
            ("HTTP/1.1 200 Ok\r\nContent-Type: application/octet-stream\r\nTransfer-encoding: chunked\r\nX-Request-ID: 0\r\nX-Request-Path: /foo\r\n\r\n",
             HttpResponsePreamble::from_headers(200, "Ok".to_string(), None, HttpContentType::Bytes, 0, "/foo".to_string(), vec![], vec![])),
        ];

        for (data, response) in tests.iter() {
            test_debug!("Try parsing:\n{}\n", data);
            let res = HttpResponsePreamble::consensus_deserialize(&mut io::Cursor::new(data));
            assert!(res.is_ok(), format!("{:?}", &res));
            assert_eq!(res.unwrap(), *response);
            
            let sres = StacksHttpPreamble::consensus_deserialize(&mut io::Cursor::new(data));
            assert!(sres.is_ok(), format!("{:?}", &sres));
            assert_eq!(sres.unwrap(), StacksHttpPreamble::Response((*response).clone()));
        }
    }

    #[test]
    fn test_http_response_preamble_headers() {
        let mut res = HttpResponsePreamble::new(200, "OK".to_string(), Some(123), HttpContentType::JSON, 123, "/bar".to_string());
        assert_eq!(res.request_id, 123);
        assert_eq!(res.request_path, "/bar".to_string());

        res.set_request_id(456);
        assert_eq!(res.request_id, 456);

        res.set_request_path("/foo".to_string());
        assert_eq!(res.request_path, "/foo".to_string());

        res.add_header("foo".to_string(), "bar".to_string());
        res.add_CORS_headers();

        let mut bytes = vec![];
        res.consensus_serialize(&mut bytes).unwrap();
        let txt = String::from_utf8(bytes).unwrap();
        assert!(txt.find("Server: stacks/2.0\r\n").is_some(), "Server header is missing");
        assert!(txt.find("Content-Length: 123\r\n").is_some(), "Content-Length is missing");
        assert!(txt.find("Content-Type: application/json\r\n").is_some(), "Content-Type is missing");
        assert!(txt.find("Date: ").is_some(), "Date header is missing");
        assert!(txt.find("foo: bar\r\n").is_some(), "foo header is missing");
        assert!(txt.find("X-Request-Id: 456\r\n").is_some(), "X-Request-Id is missing");
        assert!(txt.find("X-Request-Path: /foo\r\n").is_some(), "X-Request-Path is missing");
        assert!(txt.find("Access-Control-Allow-Origin: *\r\n").is_some(), "CORS header is missing");
    }

    #[test]
    fn test_parse_http_response_preamble_err() {
        let tests = vec![
            ("HTTP/1.1 200",
            "failed to fill whole buffer"),
            ("HTTP/1.1 200 OK\r\nfoo: \u{2764}\r\n\r\n",
            "header value is not ASCII-US"),
            ("HTTP/1.1 200 OK\r\nfoo: bar\r\nfoo: bar\r\n\r\n",
             "duplicate header"),
            ("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n",
             "Unsupported HTTP content type"),
            ("HTTP/1.1 200 OK\r\nContent-Length: foo\r\n\r\n",
             "Invalid Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 123\r\nX-Request-Id: 123\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nX-Request-Id: 123\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 123\r\nX-Request-Path: /foo\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nX-Request-Path: /foo\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 123\r\nTransfer-Encoding: chunked\r\nX-Request-Path: /foo\r\n\r\n",
             "incompatible transfer-encoding and content-length"),
        ];

        for (data, errstr) in tests.iter() {
            let res = HttpResponsePreamble::consensus_deserialize(&mut io::Cursor::new(data));
            test_debug!("Expect '{}', got: {:?}", errstr, &res);
            assert!(res.is_err(), format!("{:?}", &res));
            assert!(res.unwrap_err().description().find(errstr).is_some());
        }
    }

    #[test]
    fn test_parse_stacks_http_preamble_response_err() {
        let tests = vec![
            ("HTTP/1.1 200",
            "Not enough bytes to form a HTTP request or response"),
            ("HTTP/1.1 200 OK\r\nfoo: \u{2764}\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nfoo: bar\r\nfoo: bar\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Length: foo\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 123\r\nX-Request-Id: 123\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nX-Request-Id: 123\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 123\r\nX-Request-Path: /foo\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nX-Request-Path: /foo\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 123\r\nTransfer-Encoding: chunked\r\nX-Request-Path: /foo\r\n\r\n",
             "Failed to decode HTTP request or HTTP response"),
        ];

        for (data, errstr) in tests.iter() {
            let sres = StacksHttpPreamble::consensus_deserialize(&mut io::Cursor::new(data));
            let expected_serrstr = format!("{:?}", &sres);
            test_debug!("Expect '{}', got: {:?}", errstr, &sres);
            assert!(sres.is_err(), expected_serrstr);
            assert!(sres.unwrap_err().description().find(errstr).is_some(), expected_serrstr);
        }
    }

    fn make_test_transaction() -> StacksTransaction {
        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let recv_addr = StacksAddress { version: 1, bytes: Hash160([0xff; 20]) };

        let mut tx_stx_transfer = StacksTransaction::new(TransactionVersion::Testnet,
                                                         auth.clone(),
                                                         TransactionPayload::TokenTransfer(recv_addr.clone(), 123, TokenTransferMemo([0u8; 34])));
        tx_stx_transfer.chain_id = 0x80000000;
        tx_stx_transfer.post_condition_mode = TransactionPostConditionMode::Allow;
        tx_stx_transfer.set_fee_rate(0);
        tx_stx_transfer
    }

    #[test]
    fn test_http_parse_host_header_value() {
        let hosts = vec![
            "1.2.3.4",
            "1.2.3.4:5678",
            "[1:203:405:607:809:a0b:c0d:e0f]",
            "[1:203:405:607:809:a0b:c0d:e0f]:12345",
            "www.foo.com",
            "www.foo.com:12345",
            // invalid IP addresses will be parsed to DNS names
            "1.2.3.4.5",
            "[1:203:405:607:809:a0b:c0d:e0f:1011]",
            // these won't parse at all, since the port is invalid
            "1.2.3.4:1234567",
            "1.2.3.4.5:1234567",
            "[1:203:405:607:809:a0b:c0d:e0f]:1234567",
            "[1:203:405:607:809:a0b:c0d:e0f:1011]:1234567",
            "www.foo.com:1234567",
            ":",
            ":123",
        ];

        let peerhosts = vec![
            Some(PeerHost::IP(PeerAddress([0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4]), 80)),
            Some(PeerHost::IP(PeerAddress([0,0,0,0,0,0,0,0,0,0,0xff,0xff,1,2,3,4]), 5678)),
            Some(PeerHost::IP(PeerAddress([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]), 80)),
            Some(PeerHost::IP(PeerAddress([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]), 12345)),
            Some(PeerHost::DNS("www.foo.com".to_string(), 80)),
            Some(PeerHost::DNS("www.foo.com".to_string(), 12345)),
            Some(PeerHost::DNS("1.2.3.4.5".to_string(), 80)),
            Some(PeerHost::DNS("[1:203:405:607:809:a0b:c0d:e0f:1011]".to_string(), 80)),
            None,
            None,
            None,
            None,
            None,
            None,
            None
        ];

        for (host, expected_host) in hosts.iter().zip(peerhosts.iter()) {
            let peerhost = match host.parse::<PeerHost>() {
                Ok(ph) => Some(ph),
                Err(_) => None
            };

            match (peerhost, expected_host) {
                (Some(ref ph), Some(ref expected_ph)) => assert_eq!(*ph, *expected_ph),
                (None, None) => {},
                (Some(ph), None) => {
                    eprintln!("Parsed {} successfully to {:?}, but expected error", host, ph);
                    assert!(false);
                }
                (None, Some(expected_ph)) => {
                    eprintln!("Failed to parse {} successfully", host);
                    assert!(false);
                }
            }
        }
    }

    #[test]
    fn test_http_request_type_codec() {
        let http_request_metadata_ip = HttpRequestMetadata {
            peer: PeerHost::IP(PeerAddress([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]), 12345),
            request_id: 123
        };
        let http_request_metadata_dns = HttpRequestMetadata {
            peer: PeerHost::DNS("www.foo.com".to_string(), 80),
            request_id: 456
        };

        let tests = vec![
            HttpRequestType::GetNeighbors(http_request_metadata_ip.clone()),
            HttpRequestType::GetBlock(http_request_metadata_dns.clone(), BlockHeaderHash([2u8; 32])),
            HttpRequestType::GetMicroblocks(http_request_metadata_ip.clone(), BlockHeaderHash([3u8; 32])),
            HttpRequestType::PostTransaction(http_request_metadata_dns.clone(), make_test_transaction())
        ];

        let mut tx_body = vec![];
        make_test_transaction().consensus_serialize(&mut tx_body).unwrap();

        let mut post_transaction_preamble = HttpRequestPreamble::new("POST".to_string(), "/v2/transactions".to_string(), http_request_metadata_dns.peer.hostname(), http_request_metadata_dns.peer.port(), http_request_metadata_dns.request_id);
        post_transaction_preamble.set_content_type(HttpContentType::Bytes);
        post_transaction_preamble.set_content_length(tx_body.len() as u32);

        // all of these should parse
        let expected_http_preambles = vec![
            HttpRequestPreamble::new("GET".to_string(), "/v2/neighbors".to_string(), http_request_metadata_ip.peer.hostname(), http_request_metadata_ip.peer.port(), http_request_metadata_ip.request_id),
            HttpRequestPreamble::new("GET".to_string(), format!("/v2/blocks/{}", BlockHeaderHash([2u8; 32]).to_hex()), http_request_metadata_dns.peer.hostname(), http_request_metadata_dns.peer.port(), http_request_metadata_dns.request_id),
            HttpRequestPreamble::new("GET".to_string(), format!("/v2/microblocks/{}", BlockHeaderHash([3u8; 32]).to_hex()), http_request_metadata_ip.peer.hostname(), http_request_metadata_ip.peer.port(), http_request_metadata_ip.request_id),
            post_transaction_preamble,
        ];

        let expected_http_bodies = vec![
            vec![],
            vec![],
            vec![],
            tx_body,
        ];

        for (test, (expected_http_preamble, expected_http_body)) in tests.iter().zip(expected_http_preambles.iter().zip(expected_http_bodies.iter())) {
            let mut expected_bytes = vec![];
            expected_http_preamble.consensus_serialize(&mut expected_bytes).unwrap();

            test_debug!("Expected preamble:\n{}", str::from_utf8(&expected_bytes).unwrap());

            if expected_http_preamble.content_type.is_none() || expected_http_preamble.content_type != Some(HttpContentType::Bytes) {
                test_debug!("Expected http body:\n{}", str::from_utf8(&expected_http_body).unwrap());
            }
            else {
                test_debug!("Expected http body (hex):\n{}", to_hex(&expected_http_body));
            }

            expected_bytes.append(&mut expected_http_body.clone());
            
            let mut bytes = vec![];
            let mut http = StacksHttp::new();
            http.write_message(&mut bytes, &StacksHttpMessage::Request(test.clone())).unwrap();

            assert_eq!(bytes, expected_bytes);
        }
    }

    #[test]
    fn test_http_request_type_codec_err() {
        let bad_content_lengths = vec![
            "GET /v2/neighbors HTTP/1.1\r\nUser-Agent: stacks/2.0\r\nHost: bad:123\r\nX-Request-Id: 123\r\nContent-Length: 1\r\n\r\nb",
            "GET /v2/blocks/1111111111111111111111111111111111111111111111111111111111111111 HTTP/1.1\r\nUser-Agent: stacks/2.0\r\nHost: bad:123\r\nX-Request-Id: 123\r\nContent-Length: 1\r\n\r\nb",
            "GET /v2/microblocks/1111111111111111111111111111111111111111111111111111111111111111 HTTP/1.1\r\nUser-Agent: stacks/2.0\r\nHost: bad:123\r\nX-Request-Id: 123\r\nContent-Length: 1\r\n\r\nb",
            "POST /v2/transactions HTTP/1.1\r\nUser-Agent: stacks/2.0\r\nHost: bad:123\r\nX-Request-Id: 123\r\nContent-Length: 0\r\n\r\n",
        ];
        for bad_content_length in bad_content_lengths {
            let mut http = StacksHttp::new();
            let (preamble, offset) = http.read_preamble(bad_content_length.as_bytes()).unwrap();
            let e = http.read_payload(&preamble, &bad_content_length.as_bytes()[offset..]);
            let estr = format!("{:?}", &e);

            assert!(e.is_err(), estr);
            assert!(e.unwrap_err().description().find("-length body for").is_some(), estr);
        }

        let bad_content_types = vec![
            "POST /v2/transactions HTTP/1.1\r\nUser-Agent: stacks/2.0\r\nHost: bad:123\r\nX-Request-Id: 123\r\nContent-Length: 1\r\n\r\nb",
            "POST /v2/transactions HTTP/1.1\r\nUser-Agent: stacks/2.0\r\nHost: bad:123\r\nX-Request-Id: 123\r\nContent-Length: 1\r\nContent-Type: application/json\r\n\r\nb",
        ];
        for bad_content_type in bad_content_types {
            let mut http = StacksHttp::new();
            let (preamble, offset) = http.read_preamble(bad_content_type.as_bytes()).unwrap();
            let e = http.read_payload(&preamble, &bad_content_type.as_bytes()[offset..]);
            assert!(e.is_err());
            assert!(e.unwrap_err().description().find("Content-Type").is_some());
        }
    }

    #[test]
    fn test_http_response_type_codec() {
        let test_neighbors_info = NeighborsData {
            neighbors: vec![
                NeighborAddress {
                    addrbytes: PeerAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]),
                    port: 12345,
                    public_key_hash: Hash160::from_bytes(&hex_bytes("1111111111111111111111111111111111111111").unwrap()).unwrap(),
                },
                NeighborAddress {
                    addrbytes: PeerAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04]),
                    port: 23456,
                    public_key_hash: Hash160::from_bytes(&hex_bytes("2222222222222222222222222222222222222222").unwrap()).unwrap(),
                },
            ]
        };

        let privk = StacksPrivateKey::from_hex("6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001").unwrap();
        let test_block_info = make_codec_test_block(5);
        let test_microblock_info = make_sample_microblock_stream(&privk, &test_block_info.block_hash());
        
        let mut test_block_info_bytes = vec![];
        test_block_info.consensus_serialize(&mut test_block_info_bytes).unwrap();

        let mut test_microblock_info_bytes = vec![];
        test_microblock_info.consensus_serialize(&mut test_microblock_info_bytes).unwrap();

        let tests = vec![
            // length is known
            HttpResponseType::Neighbors(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(serde_json::to_string(&test_neighbors_info).unwrap().len() as u32)), test_neighbors_info.clone()),
            HttpResponseType::Block(HttpResponseMetadata::new(123, format!("/v2/blocks/{}", test_block_info.block_hash().to_hex()), Some(test_block_info_bytes.len() as u32)), test_block_info.clone()),
            HttpResponseType::Microblocks(HttpResponseMetadata::new(123, format!("/v2/microblocks/{}", test_microblock_info[0].block_hash().to_hex()), Some(test_microblock_info_bytes.len() as u32)), test_microblock_info.clone()),
            HttpResponseType::TransactionID(HttpResponseMetadata::new(123, "/v2/transactions".to_string(), Some(Txid([0x1; 32]).to_hex().len() as u32)), Txid([0x1; 32])),
            
            // length is unknown
            HttpResponseType::Neighbors(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), None), test_neighbors_info.clone()),
            HttpResponseType::Block(HttpResponseMetadata::new(123, format!("/v2/blocks/{}", test_block_info.block_hash().to_hex()), None), test_block_info.clone()),
            HttpResponseType::Microblocks(HttpResponseMetadata::new(123, format!("/v2/microblocks/{}", test_microblock_info[0].block_hash().to_hex()), None), test_microblock_info.clone()),
            HttpResponseType::TransactionID(HttpResponseMetadata::new(123, "/v2/transactions".to_string(), None), Txid([0x1; 32])),

            // errors without error messages
            HttpResponseType::BadRequest(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(0)), "".to_string()),
            HttpResponseType::Unauthorized(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(0)), "".to_string()),
            HttpResponseType::PaymentRequired(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(0)), "".to_string()),
            HttpResponseType::Forbidden(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(0)), "".to_string()),
            HttpResponseType::NotFound(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(0)), "".to_string()),
            HttpResponseType::ServerError(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(0)), "".to_string()),
            HttpResponseType::ServiceUnavailable(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(0)), "".to_string()),
            HttpResponseType::Error(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(0)), 502, "".to_string()),

            // errors with specific messages
            HttpResponseType::BadRequest(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(3)), "foo".to_string()),
            HttpResponseType::Unauthorized(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(3)), "foo".to_string()),
            HttpResponseType::PaymentRequired(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(3)), "foo".to_string()),
            HttpResponseType::Forbidden(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(3)), "foo".to_string()),
            HttpResponseType::NotFound(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(3)), "foo".to_string()),
            HttpResponseType::ServerError(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(3)), "foo".to_string()),
            HttpResponseType::ServiceUnavailable(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(3)), "foo".to_string()),
            HttpResponseType::Error(HttpResponseMetadata::new(123, "/v2/neighbors".to_string(), Some(3)), 502, "foo".to_string()),
        ];

        let expected_http_preambles = vec![
            // length is known
            HttpResponsePreamble::new(200, "OK".to_string(), Some(serde_json::to_string(&test_neighbors_info).unwrap().len() as u32), HttpContentType::JSON, 123, "/v2/neighbors".to_string()),
            HttpResponsePreamble::new(200, "OK".to_string(), Some(test_block_info_bytes.len() as u32), HttpContentType::Bytes, 123, format!("/v2/blocks/{}", test_block_info.block_hash().to_hex())),
            HttpResponsePreamble::new(200, "OK".to_string(), Some(test_microblock_info_bytes.len() as u32), HttpContentType::Bytes, 123, format!("/v2/microblocks/{}", test_microblock_info[0].block_hash().to_hex())),
            HttpResponsePreamble::new(200, "OK".to_string(), Some(Txid([0x1; 32]).to_hex().len() as u32), HttpContentType::Text, 123, "/v2/transactions".to_string()),
            
            // length is unknown
            HttpResponsePreamble::new(200, "OK".to_string(), None, HttpContentType::JSON, 123, "/v2/neighbors".to_string()),
            HttpResponsePreamble::new(200, "OK".to_string(), None, HttpContentType::Bytes, 123, format!("/v2/blocks/{}", test_block_info.block_hash().to_hex())),
            HttpResponsePreamble::new(200, "OK".to_string(), None, HttpContentType::Bytes, 123, format!("/v2/microblocks/{}", test_microblock_info[0].block_hash().to_hex())),
            HttpResponsePreamble::new(200, "OK".to_string(), None, HttpContentType::Text, 123, "/v2/transactions".to_string()),

            // errors
            HttpResponsePreamble::new_error(400, 123, "/v2/neighbors".to_string(), None),
            HttpResponsePreamble::new_error(401, 123, "/v2/neighbors".to_string(), None),
            HttpResponsePreamble::new_error(402, 123, "/v2/neighbors".to_string(), None),
            HttpResponsePreamble::new_error(403, 123, "/v2/neighbors".to_string(), None),
            HttpResponsePreamble::new_error(404, 123, "/v2/neighbors".to_string(), None),
            HttpResponsePreamble::new_error(500, 123, "/v2/neighbors".to_string(), None),
            HttpResponsePreamble::new_error(503, 123, "/v2/neighbors".to_string(), None),

            // generic error
            HttpResponsePreamble::new_error(502, 123, "/v2/neighbors".to_string(), None),

            // errors with messages
            HttpResponsePreamble::new_error(400, 123, "/v2/neighbors".to_string(), Some("foo".to_string())),
            HttpResponsePreamble::new_error(401, 123, "/v2/neighbors".to_string(), Some("foo".to_string())),
            HttpResponsePreamble::new_error(402, 123, "/v2/neighbors".to_string(), Some("foo".to_string())),
            HttpResponsePreamble::new_error(403, 123, "/v2/neighbors".to_string(), Some("foo".to_string())),
            HttpResponsePreamble::new_error(404, 123, "/v2/neighbors".to_string(), Some("foo".to_string())),
            HttpResponsePreamble::new_error(500, 123, "/v2/neighbors".to_string(), Some("foo".to_string())),
            HttpResponsePreamble::new_error(503, 123, "/v2/neighbors".to_string(), Some("foo".to_string())),
            
            HttpResponsePreamble::new_error(502, 123, "/v2/neighbors".to_string(), Some("foo".to_string())),
        ];

        let expected_http_bodies = vec![
            // with content-length
            serde_json::to_string(&test_neighbors_info).unwrap().as_bytes().to_vec(),
            test_block_info_bytes.clone(),
            test_microblock_info_bytes.clone(),
            Txid([0x1; 32]).to_hex().as_bytes().to_vec(),
            
            // with transfer-encoding: chunked
            serde_json::to_string(&test_neighbors_info).unwrap().as_bytes().to_vec(),
            test_block_info_bytes,
            test_microblock_info_bytes,
            Txid([0x1; 32]).to_hex().as_bytes().to_vec(),

            // errors
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],

            // errors with messages
            "foo".as_bytes().to_vec(),
            "foo".as_bytes().to_vec(),
            "foo".as_bytes().to_vec(),
            "foo".as_bytes().to_vec(),
            "foo".as_bytes().to_vec(),
            "foo".as_bytes().to_vec(),
            "foo".as_bytes().to_vec(),
            "foo".as_bytes().to_vec(),
        ];

        for (test, (expected_http_preamble, expected_http_body)) in tests.iter().zip(expected_http_preambles.iter().zip(expected_http_bodies.iter())) {
            let mut http = StacksHttp::new();
            let mut bytes = vec![];
            test_debug!("write body:\n{:?}\n", test);
            http.write_message(&mut bytes, &StacksHttpMessage::Response((*test).clone())).unwrap();

            let (mut preamble, offset) = http.read_preamble(&bytes).unwrap();

            test_debug!("read preamble of {} bytes\n{:?}\n", offset, preamble);

            test_debug!("read http body\n{:?}\n", &bytes[offset..].to_vec());

            let (message, total_len) = 
                if expected_http_preamble.is_chunked() {
                    let mut cursor = io::Cursor::new(&bytes[offset..]);
                    let (msg_opt, len) = http.stream_payload(&preamble, &mut cursor).unwrap();
                    (msg_opt.unwrap().0, len)
                }
                else {
                    http.read_payload(&preamble, &bytes[offset..]).unwrap()
                };
          
            test_debug!("got message\n{:?}\n", &message);

            // check everything in the parsed preamble except for the extra headers
            match preamble {
                StacksHttpPreamble::Response(ref mut req) => {
                    assert_eq!(req.headers.len(), 2);
                    assert!(req.headers.get("server").is_some());
                    assert!(req.headers.get("date").is_some());
                    req.headers.clear();
                },
                StacksHttpPreamble::Request(_) => {
                    panic!("parsed a request");
                }
            }

            assert_eq!(preamble, StacksHttpPreamble::Response((*expected_http_preamble).clone()));
            assert_eq!(message, StacksHttpMessage::Response((*test).clone()));
        }
    }
    
    #[test]
    fn test_http_response_type_codec_err() {
        let bad_request_payloads = vec![
            "HTTP/1.1 200 OK\r\nServer: stacks/v2.0\r\nX-Request-Path: /v2/transactions\r\nX-Request-Id: 123\r\nContent-Type: application/json\r\nContent-length: 2\r\n\r\nab",
            "HTTP/1.1 200 OK\r\nServer: stacks/v2.0\r\nX-Request-Path: /v2/transactions\r\nX-Request-Id: 123\r\nContent-Type: text/plain\r\nContent-length: 2\r\n\r\nab",
            "HTTP/1.1 200 OK\r\nServer: stacks/v2.0\r\nX-Request-Path: /v2/neighbors\r\nX-Request-Id: 123\r\nContent-Type: application/json\r\nContent-length: 1\r\n\r\n{",
            "HTTP/1.1 200 OK\r\nServer: stacks/v2.0\r\nX-Request-Path: /v2/neighbors\r\nX-Request-Id: 123\r\nContent-Type: application/json\r\nContent-length: 1\r\n\r\na",
            "HTTP/1.1 400 Bad Request\r\nServer: stacks/v2.0\r\nX-Request-Path: /v2/neighbors\r\nX-Request-Id: 123\r\nContent-Type: application/json\r\nContent-length: 2\r\n\r\n{}",
        ];
        let expected_bad_request_payload_errors = vec![
            "Invalid content-type",
            "Invalid txid:",
            "Not enough bytes",
            "Failed to parse",
            "expected text/plain",
        ];
        for (test, expected_error) in bad_request_payloads.iter().zip(expected_bad_request_payload_errors.iter()) {
            test_debug!("Expect failure:\n{}\nExpected error: '{}'", test, expected_error);
            
            let mut http = StacksHttp::new();
            let (preamble, offset) = http.read_preamble(test.as_bytes()).unwrap();
            let e = http.read_payload(&preamble, &test.as_bytes()[offset..]);
            let errstr = format!("{:?}", &e);
            assert!(e.is_err());
            assert!(e.unwrap_err().description().find(expected_error).is_some(), errstr);
        }
    }
}
