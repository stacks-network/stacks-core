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

use std::collections::HashMap;
use std::str;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

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
use net::StacksHttpMessage;
use net::MessageSequence;
use net::NetworkPreamble;
use net::ProtocolFamily;
use net::StacksHttp;
use net::HttpRequestMetadata;
use net::HttpResponseMetadata;
use net::NeighborsData;
use net::NeighborAddress;
use net::HTTP_PREAMBLE_MAX_ENCODED_SIZE;

use chainstate::burn::BlockHeaderHash;
use burnchains::Txid;
use chainstate::stacks::StacksTransaction;
use chainstate::stacks::StacksBlock;
use chainstate::stacks::StacksMicroblock;

use util::log;
use util::hash::hex_bytes;

use regex::Regex;

use httparse;
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
                                host = Some(parts[0..np-1].join(":"));
                                let port_res = parts[np-1].parse::<u16>();
                                port = match port_res {
                                    Ok(p) => Some(p),
                                    Err(_) => {
                                        return Err(net_error::DeserializeError("Faield to parse PeerHost: invalid port".to_string()));
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
                            (_, _) => Err(net_error::DeserializeError("Failed to parse PeerHost: failed to extract host and/or port".to_string()))
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

impl HttpRequestPreamble {
    pub fn new(verb: String, path: String, hostname: String, port: u16) -> HttpRequestPreamble {
        HttpRequestPreamble {
            verb: verb,
            path: path,
            host: PeerHost::from_host_port(hostname, port),
            request_id: 0,
            content_type: None,
            headers: HashMap::new()
        }
    }

    #[cfg(test)]
    pub fn from_headers(verb: String, path: String, hostname: String, port: u16, request_id: u32, mut keys: Vec<String>, values: Vec<String>) -> HttpRequestPreamble {
        assert_eq!(keys.len(), values.len());
        let mut req = HttpRequestPreamble::new(verb, path, hostname, port);
        for (k, v) in keys.drain(..).zip(values) {
            req.add_header(k, v);
        }
        req.set_request_id(request_id);
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

    pub fn get_host(&self) -> PeerHost {
        self.host.clone()
    }

    /// Content-Length for this request.
    /// If there is no valid Content-Length header, then 
    /// the Content-Length is 0
    pub fn get_content_length(&self) -> u32 {
        // do we have a content-length header?
        let mut len = 0;
        for (k, v) in self.headers.iter() {
            if k == "content-length" {
                len = v.parse::<u32>().unwrap_or(0);
            }
        }
        len
    }

    /// Set the content-length for this request
    pub fn set_content_length(&mut self, len: u32) -> () {
        self.headers.insert("content-length".to_string(), format!("{}", len));
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

impl StacksMessageCodec for HttpRequestPreamble {
    fn consensus_serialize(&self) -> Vec<u8> {
        let content_type_header = match self.content_type {
            Some(ref c) => format!("Content-Type: {}\r\n", c),
            None => "".to_string()
        };
        let txt = format!("{} {} HTTP/1.0\r\nUser-Agent: stacks/2.0\r\nHost: {}\r\n{}\r\n{}X-Request-Id: {}{}\r\n\r\n", 
                          &self.verb, &self.path,
                          &self.host,
                          default_accept_header(),
                          content_type_header,
                          self.request_id,
                          headers_to_string(&self.headers));
        txt.as_bytes().to_vec()
    }

    /// If you get back an UnderflowError, then try and parse again with more data
    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_len: u32) -> Result<HttpRequestPreamble, net_error> {
        let mut index = *index_ptr;
        if index >= buf.len() as u32 {
            return Err(net_error::OverflowError("Index is past the end of the buffer".to_string()));
        }

        if index > u32::max_value() - (HTTP_PREAMBLE_MAX_ENCODED_SIZE as u32) {
            return Err(net_error::OverflowError("Index would exceed u32::max_value()".to_string()));
        }

        // read from index, but only up to HTTP_PREAMBLE_MAX_ENCODED_SIZE bytes
        let buf_start = &buf[(index as usize..)];
        let max_read_len = if (buf_start.len() as u32) < max_len { buf_start.len() as u32 } else { max_len };
        let max_payload_len = if max_read_len < HTTP_PREAMBLE_MAX_ENCODED_SIZE { max_read_len } else { HTTP_PREAMBLE_MAX_ENCODED_SIZE };

        let buf_read = &buf_start[..(max_payload_len as usize)];

        // realistically, there won't be more than 16 headers
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);

        // consume request
        match req.parse(buf_read).map_err(|e| net_error::DeserializeError(format!("Failed to parse HTTP request: {:?}", &e)))? {
            httparse::Status::Partial => {
                // try again
                if buf_start.len() >= (max_len as usize) {
                    // because we'd read beyond the alloted max size
                    return Err(net_error::OverflowError("Would read beyond max_size to form an HTTP request preamble".to_string()));
                }
                else {
                    return Err(net_error::UnderflowError("Not enough bytes to form an HTTP request preamble".to_string()));
                }
            },
            httparse::Status::Complete(body_offset) => {
                // consumed all headers.  body_offset points to the start of the request body
                let verb = req.method.ok_or(net_error::DeserializeError("No HTTP method".to_string()))?.to_string();
                let path = req.path.ok_or(net_error::DeserializeError("No HTTP path".to_string()))?.to_string();
                let mut headers : HashMap<String, String> = HashMap::new();
                for i in 0..req.headers.len() {
                    let value = String::from_utf8(req.headers[i].value.to_vec()).map_err(|_e| net_error::DeserializeError("Invalid HTTP header value: not utf-8".to_string()))?;
                    if !value.is_ascii() {
                        return Err(net_error::DeserializeError(format!("Invalid HTTP request: header value is not ASCII-US")));
                    }
                    let key = req.headers[i].name.to_string().to_lowercase();
                    if headers.contains_key(&key) {
                        return Err(net_error::DeserializeError(format!("Invalid HTTP request: duplicate header \"{}\"", key)));
                    }
                    headers.insert(key, value);
                }

                let mut peerhost = None;
                let mut content_type = None;
                let mut request_id = 0;

                // must have a "host" header
                for (key, value) in headers.iter() {
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
                }

                if peerhost.is_none() {
                    return Err(net_error::DeserializeError("Missing Host header".to_string()));
                };

                index += body_offset as u32;
                *index_ptr = index;

                Ok(HttpRequestPreamble {
                    verb: verb,
                    path: path,
                    host: peerhost.unwrap(),
                    request_id: request_id,
                    content_type: content_type,
                    headers: headers
                })
            }
        }
    }
}

impl HttpResponsePreamble {
    pub fn new(status_code: u16, reason: String, content_length: u32, content_type: HttpContentType, request_id: u32, request_path: String) -> HttpResponsePreamble {
        HttpResponsePreamble {
            status_code: status_code,
            reason: reason,
            content_length: content_length,
            content_type: content_type,
            request_id: request_id,
            request_path: request_path,
            headers: HashMap::new()
        }
    }

    pub fn new_error(status_code: u16, request_id: u32, request_path: String, error_message: Option<String>) -> HttpResponsePreamble {
        HttpResponsePreamble {
            status_code: status_code,
            reason: HttpResponseType::error_reason(status_code).to_string(),
            content_length: error_message.unwrap_or("".to_string()).len() as u32,
            content_type: HttpContentType::Text,
            request_id: request_id, 
            request_path: request_path,
            headers: HashMap::new()
        }
    }

    #[cfg(test)]
    pub fn from_headers(status_code: u16, reason: String, content_length: u32, content_type: HttpContentType, request_id: u32, request_path: String, mut keys: Vec<String>, values: Vec<String>) -> HttpResponsePreamble {
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
                    HttpReservedHeader::ContentLength(cl) => self.content_length = cl,
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
}

/// Get an RFC 7231 date that represents the current time
fn rfc7231_now() -> String {
    let now = time::PrimitiveDateTime::now();
    now.format("%a, %b %-d %-Y %-H:%M:%S GMT")
}

impl StacksMessageCodec for HttpResponsePreamble {
    fn consensus_serialize(&self) -> Vec<u8> {
        let txt = format!("HTTP/1.0 {} {}\r\nServer: stacks/2.0\r\nDate: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nX-Request-Id: {}\r\nX-Request-Path: {}{}\r\n\r\n",
                          self.status_code, &self.reason,
                          rfc7231_now(),
                          &self.content_type,
                          self.content_length,
                          self.request_id,
                          self.request_path,
                          headers_to_string(&self.headers));

        txt.as_bytes().to_vec()
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_len: u32) -> Result<HttpResponsePreamble, net_error> {
        // realistically, there won't be more than 16 headers
        let mut index = *index_ptr;
        if index >= buf.len() as u32 {
            return Err(net_error::OverflowError("Index is past the end of the buffer".to_string()));
        }

        if index > u32::max_value() - (HTTP_PREAMBLE_MAX_ENCODED_SIZE as u32) {
            return Err(net_error::OverflowError("Index would exceed u32::max_value()".to_string()));
        }
        
        // read from index, but only up to HTTP_PREAMBLE_MAX_ENCODED_SIZE bytes
        let buf_start = &buf[(index as usize..)];
        let max_read_len = if (buf_start.len() as u32) < max_len { buf_start.len() as u32 } else { max_len };
        let max_payload_len = if max_read_len < HTTP_PREAMBLE_MAX_ENCODED_SIZE { max_read_len } else { HTTP_PREAMBLE_MAX_ENCODED_SIZE };

        let buf_read = &buf_start[..(max_payload_len as usize)];

        // realistically, there won't be more than 16 headers
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut resp = httparse::Response::new(&mut headers);

        // consume response
        match resp.parse(buf_read).map_err(|e| net_error::DeserializeError(format!("Failed to parse HTTP response: {:?}", &e)))? {
            httparse::Status::Partial => {
                // try again
                if buf_start.len() >= (max_len as usize) {
                    // because we'd read beyond the alloted max size
                    return Err(net_error::OverflowError("Would read beyond max_size to form an HTTP response preamble".to_string()));
                }
                else {
                    return Err(net_error::UnderflowError("Not enough bytes to form an HTTP response preamble".to_string()));
                }
            },
            httparse::Status::Complete(body_offset) => {
                // consumed all headers.  body_offset points to the start of the response body
                let status_code = resp.code.ok_or(net_error::DeserializeError("No HTTP status code".to_string()))?;
                let reason = resp.reason.ok_or(net_error::DeserializeError("No HTTP status reason".to_string()))?.to_string();

                let mut headers : HashMap<String, String> = HashMap::new();
                for i in 0..resp.headers.len() {
                    let value = String::from_utf8(resp.headers[i].value.to_vec()).map_err(|_e| net_error::DeserializeError("Invalid HTTP header value: not utf-8".to_string()))?;
                    if !value.is_ascii() {
                        return Err(net_error::DeserializeError(format!("Invalid HTTP request: header value is not ASCII-US")));
                    }

                    let key = resp.headers[i].name.to_string().to_lowercase();
                    if headers.contains_key(&key) {
                        return Err(net_error::DeserializeError(format!("Invalid HTTP request: duplicate header \"{}\"", key)));
                    }
                    headers.insert(key, value);
                }

                let mut content_type = None;
                let mut content_length = None;
                let mut request_id = None;
                let mut request_path = None;

                // must have a "content-type", "content-length", "x-request-path", and "x-request-id" header
                for (key, value) in headers.iter() {
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
                }

                if content_type.is_none() || content_length.is_none() || request_path.is_none() || request_id.is_none() {
                    return Err(net_error::DeserializeError("Invalid HTTP response: missing Content-Type, Content-Length, X-Request-ID, and/or X-Request-Path".to_string()));
                }

                index += body_offset as u32;
                *index_ptr = index;

                Ok(HttpResponsePreamble {
                    status_code: status_code,
                    reason: reason,
                    content_type: content_type.unwrap(),
                    content_length: content_length.unwrap(),
                    request_id: request_id.unwrap(),
                    request_path: request_path.unwrap(),
                    headers: headers
                })
            }
        }
    }
}

impl HttpRequestType {
    fn try_parse<F>(verb: &str, regex: &Regex, preamble: &HttpRequestPreamble, bytes: &[u8], parser: F) -> Result<Option<HttpRequestType>, net_error>
    where
        F: Fn(&HttpRequestPreamble, &Regex, &[u8]) -> Result<HttpRequestType, net_error>
    {
        if preamble.verb == verb && regex.is_match(&preamble.path) {
            let payload = parser(preamble, regex, bytes)?;
            Ok(Some(payload))
        }
        else {
            Ok(None)
        }
    }

    pub fn parse(preamble: &HttpRequestPreamble, bytes: &[u8]) -> Result<HttpRequestType, net_error> {
        // TODO: make this static somehow
        let REQUEST_METHODS : [(&'static str, &'static Regex, &'static dyn Fn(&HttpRequestPreamble, &Regex, &[u8]) -> Result<HttpRequestType, net_error>); 4] = [
            ("GET", &PATH_GETNEIGHBORS, &HttpRequestType::parse_getneighbors),
            ("GET", &PATH_GETBLOCK, &HttpRequestType::parse_getblock),
            ("GET", &PATH_GETMICROBLOCKS, &HttpRequestType::parse_getmicroblocks),
            ("POST", &PATH_POSTTRANSACTION, &HttpRequestType::parse_posttransaction)
        ];

        for (verb, regex, parser) in REQUEST_METHODS.iter() {
            match HttpRequestType::try_parse(verb, regex, preamble, bytes, parser) {
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
    
    fn parse_getneighbors(preamble: &HttpRequestPreamble, _regex: &Regex, _bytes: &[u8]) -> Result<HttpRequestType, net_error> {
        if preamble.get_content_length() != 0 {
            return Err(net_error::DeserializeError("Invalid Http request: expected 0-length body for GetNeighbors".to_string()));
        }

        Ok(HttpRequestType::GetNeighbors(HttpRequestMetadata::from_preamble(preamble)))
    }

    fn parse_getblock(preamble: &HttpRequestPreamble, regex: &Regex, _bytes: &[u8]) -> Result<HttpRequestType, net_error> {
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

    fn parse_getmicroblocks(preamble: &HttpRequestPreamble, regex: &Regex, _bytes: &[u8]) -> Result<HttpRequestType, net_error> {
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

    fn parse_posttransaction(preamble: &HttpRequestPreamble, _regex: &Regex, bytes: &[u8]) -> Result<HttpRequestType, net_error> {
        if preamble.get_content_length() == 0 {
            return Err(net_error::DeserializeError("Invalid Http request: expected non-zero body length for PostTransaction".to_string()));
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

        if preamble.get_content_length() == 0 {
            return Err(net_error::DeserializeError("Missing or invalid Content-Length".to_string()));
        }

        if (bytes.len() as u32) < preamble.get_content_length() {
            return Err(net_error::UnderflowError(format!("Not enough bytes to read HTTP body (expected at least {}, but have {})", preamble.get_content_length(), bytes.len())));
        }

        let tx = StacksTransaction::consensus_deserialize(bytes, &mut 0, preamble.get_content_length())?;
        Ok(HttpRequestType::PostTransaction(HttpRequestMetadata::from_preamble(preamble), tx))
    }

    pub fn metadata(&self) -> HttpRequestMetadata {
        match *self {
            HttpRequestType::GetNeighbors(ref md) => md.clone(),
            HttpRequestType::GetBlock(ref md, _) => md.clone(),
            HttpRequestType::GetMicroblocks(ref md, _) => md.clone(),
            HttpRequestType::PostTransaction(ref md, _) => md.clone()
        }
    }
}

impl HttpResponseType {
    fn try_parse<F>(regex: &Regex, preamble: &HttpResponsePreamble, bytes: &[u8], parser: F) -> Result<Option<HttpResponseType>, net_error>
    where
        F: Fn(&HttpResponsePreamble, &[u8]) -> Result<HttpResponseType, net_error>
    {
        if regex.is_match(&preamble.request_path) {
            let payload = parser(preamble, bytes)?;
            Ok(Some(payload))
        }
        else {
            Ok(None)
        }
    }

    fn parse_error(preamble: &HttpResponsePreamble, bytes: &[u8]) -> Result<HttpResponseType, net_error> {
        if preamble.status_code < 400 || preamble.status_code > 599 {
            return Err(net_error::DeserializeError("Inavlid response: not an error".to_string()));
        }
        
        if preamble.content_type != HttpContentType::Text {
            return Err(net_error::DeserializeError("Invalid error response: expected text/plain".to_string()));
        }

        let error_text = 
            if bytes.len() > 0 {
                match String::from_utf8(bytes.to_vec()) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(net_error::DeserializeError("Invalid error response: invalid UTF-8 error message".to_string()));
                    }
                }
            }
            else {
                "".to_string()
            };

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


    pub fn parse(preamble: &HttpResponsePreamble, bytes: &[u8]) -> Result<HttpResponseType, net_error> {
        if preamble.status_code >= 400 {
            return HttpResponseType::parse_error(preamble, bytes);
        }

        // TODO: make this static somehow
        let RESPONSE_METHODS : [(&'static Regex, &'static dyn Fn(&HttpResponsePreamble, &[u8]) -> Result<HttpResponseType, net_error>); 4] = [
            (&PATH_GETNEIGHBORS, &HttpResponseType::parse_neighbors),
            (&PATH_GETBLOCK, &HttpResponseType::parse_block),
            (&PATH_GETMICROBLOCKS, &HttpResponseType::parse_microblocks),
            (&PATH_POSTTRANSACTION, &HttpResponseType::parse_txid)
        ];

        for (regex, parser) in RESPONSE_METHODS.iter() {
            match HttpResponseType::try_parse(regex, preamble, bytes, parser) {
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

    fn parse_neighbors(preamble: &HttpResponsePreamble, bytes: &[u8]) -> Result<HttpResponseType, net_error> {
        if !PATH_GETNEIGHBORS.is_match(&preamble.request_path) {
            return Err(net_error::DeserializeError("Invalid response: does not match requested path".to_string()))
        }

        let neighbors_data = serde_json::from_slice(bytes)
            .map_err(|e| {
                if e.is_eof() {
                    net_error::UnderflowError(format!("Not enough bytes to parse Neighbors JSON"))
                }
                else {
                    net_error::DeserializeError(format!("Failed to parse Neighbors JSON: {:?}", &e))
                }
            })?;
                
        Ok(HttpResponseType::Neighbors(HttpResponseMetadata::from_preamble(preamble), neighbors_data))
    }

    fn parse_block(preamble: &HttpResponsePreamble, bytes: &[u8]) -> Result<HttpResponseType, net_error> {
        if !PATH_GETBLOCK.is_match(&preamble.request_path) {
            return Err(net_error::DeserializeError("Invalid response: does not match requested path".to_string()))
        }

        let block : StacksBlock = read_next(bytes, &mut 0, bytes.len() as u32)?;
        Ok(HttpResponseType::Block(HttpResponseMetadata::from_preamble(preamble), block))
    }

    fn parse_microblocks(preamble: &HttpResponsePreamble, bytes: &[u8]) -> Result<HttpResponseType, net_error> {
        if !PATH_GETMICROBLOCKS.is_match(&preamble.request_path) {
            return Err(net_error::DeserializeError("Invalid response: does not match requested path".to_string()))
        }

        let microblocks : Vec<StacksMicroblock> = read_next(bytes, &mut 0, bytes.len() as u32)?;
        Ok(HttpResponseType::Microblocks(HttpResponseMetadata::from_preamble(preamble), microblocks))
    }

    fn parse_txid(preamble: &HttpResponsePreamble, bytes: &[u8]) -> Result<HttpResponseType, net_error> {
        if !PATH_POSTTRANSACTION.is_match(&preamble.request_path) {
            return Err(net_error::DeserializeError("Invalid response: does not match requested path".to_string()))
        }

        if bytes.len() < 64 {
            return Err(net_error::DeserializeError("Invalid txid: not enough bytes".to_string()));
        }

        let hex_str = str::from_utf8(bytes).map_err(|_e| net_error::DeserializeError("Failed to decode a txid".to_string()))?;
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

    fn error_response(&self, code: u16, message: &str) -> Vec<u8> {
        let md = self.metadata();
        let mut preamble = HttpResponsePreamble::new(code, HttpResponseType::error_reason(code).to_string(), message.len() as u32, HttpContentType::Text, md.request_id, md.request_path.clone());
        preamble.set_request_id(md.request_id);

        let mut bytes = preamble.consensus_serialize();
        bytes.extend_from_slice(message.as_bytes());
        bytes
    }
    
    pub fn metadata(&self) -> HttpResponseMetadata {
        match *self {
            HttpResponseType::Neighbors(ref md, _) => md.clone(),
            HttpResponseType::Block(ref md, _) => md.clone(),
            HttpResponseType::Microblocks(ref md, _) => md.clone(),
            HttpResponseType::TransactionID(ref md, _) => md.clone(),
            // errors
            HttpResponseType::BadRequest(ref md, _) => md.clone(),
            HttpResponseType::Unauthorized(ref md, _) => md.clone(),
            HttpResponseType::PaymentRequired(ref md, _) => md.clone(),
            HttpResponseType::Forbidden(ref md, _) => md.clone(),
            HttpResponseType::NotFound(ref md, _) => md.clone(),
            HttpResponseType::ServerError(ref md, _) => md.clone(),
            HttpResponseType::ServiceUnavailable(ref md, _) => md.clone(),
            HttpResponseType::Error(ref md, _, _) => md.clone()
        }
    }
}

lazy_static! {
    static ref PATH_GETNEIGHBORS: Regex = Regex::new(r#"^/v2/neighbors$"#).unwrap();
    static ref PATH_GETBLOCK : Regex = Regex::new(r#"^/v2/blocks/([0-9a-f]{64})$"#).unwrap();
    static ref PATH_GETMICROBLOCKS : Regex = Regex::new(r#"^/v2/microblocks/([0-9a-f]{64})$"#).unwrap();
    static ref PATH_POSTTRANSACTION : Regex = Regex::new(r#"^/v2/transactions$"#).unwrap();
}

impl StacksHttpMessage {
    /// StacksHttpMessage deals with HttpRequestPreambles and HttpResponsePreambles
    fn read_preamble(buf: &[u8], max_size: u32) -> Result<(NetworkPreamble, usize), net_error> {
        let mut index = 0;
        
        // the byte stream can decode to a http request or a http response, but not both.
        match HttpRequestPreamble::consensus_deserialize(buf, &mut index, max_size) {
            Ok(request) => Ok((NetworkPreamble::HttpRequest(request), index as usize)),
            Err(net_error::DeserializeError(_)) => {
                // maybe a http response?
                match HttpResponsePreamble::consensus_deserialize(buf, &mut index, max_size) {
                    Ok(response) => Ok((NetworkPreamble::HttpResponse(response), index as usize)),
                    Err(e) => Err(e)
                }
            },
            Err(e) => Err(e)
        }
    }

    /// StacksHttpMessage deals with HttpRequestType and HttpResponseType
    fn read_payload(preamble: &NetworkPreamble, buf: &[u8]) -> Result<StacksHttpMessage, net_error> {
        match preamble {
            NetworkPreamble::HttpRequest(ref http_request_preamble) => {
                match HttpRequestType::parse(http_request_preamble, buf) {
                    Ok(data_request) => Ok(StacksHttpMessage::Request(data_request)),
                    Err(e) => Err(e)
                }
            },
            NetworkPreamble::HttpResponse(ref http_response_preamble) => {
                match HttpResponseType::parse(http_response_preamble, buf) {
                    Ok(data_response) => Ok(StacksHttpMessage::Response(data_response)),
                    Err(e) => Err(e)
                }
            },
            _ => {
                Err(net_error::WrongProtocolFamily)
            }
        }
    }
}

impl StacksMessageCodec for HttpRequestType {
    fn consensus_serialize(&self) -> Vec<u8> {
        let bytes = match *self {
            HttpRequestType::GetNeighbors(ref md) => {
                let preamble = HttpRequestPreamble::new("GET".to_string(), "/v2/neighbors".to_string(), md.peer.hostname(), md.peer.port());
                preamble.consensus_serialize()
            },
            HttpRequestType::GetBlock(ref md, ref block_hash) => {
                let preamble = HttpRequestPreamble::new("GET".to_string(), format!("/v2/blocks/{}", block_hash.to_hex()), md.peer.hostname(), md.peer.port());
                preamble.consensus_serialize()
            },
            HttpRequestType::GetMicroblocks(ref md, ref block_hash) => {
                let preamble = HttpRequestPreamble::new("GET".to_string(), format!("/v2/microblocks/{}", block_hash.to_hex()), md.peer.hostname(), md.peer.port());
                preamble.consensus_serialize()
            }
            HttpRequestType::PostTransaction(ref md, ref tx) => {
                let mut tx_bytes = tx.consensus_serialize();
                let mut preamble = HttpRequestPreamble::new("POST".to_string(), "/v2/transactions".to_string(), md.peer.hostname(), md.peer.port());
                preamble.set_content_length(tx_bytes.len() as u32);
                preamble.set_content_type(HttpContentType::Bytes);

                let mut bytes = preamble.consensus_serialize();
                bytes.append(&mut tx_bytes);
                bytes
            }
        };
        bytes
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_len: u32) -> Result<HttpRequestType, net_error> {
        let mut index = *index_ptr;
        let http_preamble = HttpRequestPreamble::consensus_deserialize(buf, &mut index, max_len)?;

        let max_http_body_len = max_len.checked_sub(index).expect("FATAL: somehow read beyond end of buffer");
        if http_preamble.get_content_length() > max_http_body_len {
            return Err(net_error::OverflowError("Would read beyond end of buffer to read HTTP request body".to_string()));
        }
        if (http_preamble.get_content_length() as usize) > buf[(index as usize)..].len() {
            return Err(net_error::UnderflowError("Not enough bytes to read HTTP resposne body".to_string()));
        }

        let http_body = HttpRequestType::parse(&http_preamble, &buf[(index as usize)..])?;
        *index_ptr = index + http_preamble.get_content_length();
        Ok(http_body)
    }
}

impl StacksMessageCodec for HttpResponseType {
    fn consensus_serialize(&self) -> Vec<u8> {
        let bytes = match *self {
            HttpResponseType::Neighbors(ref md, ref neighbor_data) => {
                let mut neighbor_bytes = match serde_json::to_string(neighbor_data) {
                    Ok(neighbor_str) => neighbor_str.into_bytes(),
                    Err(_) => {
                        return self.error_response(500, "Failed to serialize neighbor data to JSON");
                    }
                };
                let mut preamble = HttpResponsePreamble::new(200, "OK".to_string(), neighbor_bytes.len() as u32, HttpContentType::JSON, md.request_id, md.request_path.clone());
                preamble.set_request_id(md.request_id);

                let mut bytes = preamble.consensus_serialize();
                bytes.append(&mut neighbor_bytes);
                bytes
            },
            HttpResponseType::Block(ref md, ref block) => {
                let mut block_bytes = block.consensus_serialize();
                let mut preamble = HttpResponsePreamble::new(200, "OK".to_string(), block_bytes.len() as u32, HttpContentType::Bytes, md.request_id, md.request_path.clone());
                preamble.set_request_id(md.request_id);

                let mut bytes = preamble.consensus_serialize();
                bytes.append(&mut block_bytes);
                bytes
            },
            HttpResponseType::Microblocks(ref md, ref microblocks) => {
                let mut microblock_bytes = microblocks.consensus_serialize();
                let mut preamble = HttpResponsePreamble::new(200, "OK".to_string(), microblock_bytes.len() as u32, HttpContentType::Bytes, md.request_id, md.request_path.clone());
                preamble.set_request_id(md.request_id);

                let mut bytes = preamble.consensus_serialize();
                bytes.append(&mut microblock_bytes);
                bytes
            },
            HttpResponseType::TransactionID(ref md, ref txid) => {
                let mut txid_bytes = txid.to_hex().into_bytes();
                let mut preamble = HttpResponsePreamble::new(200, "OK".to_string(), txid_bytes.len() as u32, HttpContentType::Text, md.request_id, md.request_path.clone());
                preamble.set_request_id(md.request_id);

                let mut bytes = preamble.consensus_serialize();
                bytes.append(&mut txid_bytes);
                bytes
            },
            HttpResponseType::BadRequest(ref md, ref msg) => self.error_response(400, msg),
            HttpResponseType::Unauthorized(ref md, ref msg) => self.error_response(401, msg),
            HttpResponseType::PaymentRequired(ref md, ref msg) => self.error_response(402, msg),
            HttpResponseType::Forbidden(ref md, ref msg) => self.error_response(403, msg),
            HttpResponseType::NotFound(ref md, ref msg) => self.error_response(404, msg),
            HttpResponseType::ServerError(ref md, ref msg) => self.error_response(500, msg),
            HttpResponseType::ServiceUnavailable(ref md, ref msg) => self.error_response(503, msg),
            HttpResponseType::Error(ref md, ref error_code, ref msg) => self.error_response(*error_code, msg)
        };
        bytes
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_len: u32) -> Result<HttpResponseType, net_error> {
        let mut index = *index_ptr;
        let http_preamble = HttpResponsePreamble::consensus_deserialize(buf, &mut index, max_len)?;
        
        let max_http_body_len = max_len.checked_sub(index).expect("FATAL: somehow read beyond end of buffer");
        if http_preamble.content_length > max_http_body_len {
            return Err(net_error::OverflowError("Would read beyond end of buffer to read HTTP response body".to_string()));
        }
        if (http_preamble.content_length as usize) > buf[(index as usize)..].len() {
            return Err(net_error::UnderflowError("Not enough bytes to read HTTP response body".to_string()));
        }

        let http_body = HttpResponseType::parse(&http_preamble, &buf[(index as usize)..])?;
        *index_ptr = index + http_preamble.content_length;
        Ok(http_body)
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

impl StacksMessageCodec for StacksHttpMessage {
    fn consensus_serialize(&self) -> Vec<u8> {
        match *self {
            StacksHttpMessage::Request(ref req) => req.consensus_serialize(),
            StacksHttpMessage::Response(ref res) => res.consensus_serialize()
        }
    }

    fn consensus_deserialize(buf: &[u8], index_ptr: &mut u32, max_size: u32) -> Result<StacksHttpMessage, net_error> {
        let index = *index_ptr;
        let (preamble, bytes_consumed) = StacksHttpMessage::read_preamble(&buf[(index as usize)..], max_size)?;

        if index > u32::max_value() - (preamble.payload_length() as u32) {
            return Err(net_error::OverflowError("Would overflow u32 to read payload".to_string()));
        }
        if index + (preamble.payload_length() as u32) > max_size {
            return Err(net_error::OverflowError("Would read beyond end of buffer to read payload".to_string()));
        }
        if (buf[(index as usize)..].len() as u32) < index + (preamble.payload_length() as u32) {
            return Err(net_error::UnderflowError("Not enough bytes remaining to read payload".to_string()));
        }

        let http_message = StacksHttpMessage::read_payload(&preamble, &buf[(index as usize)..])?;
        Ok(http_message)
    }
}

impl ProtocolFamily for StacksHttp {
    type Message = StacksHttpMessage;

    /// how big can a preamble get?
    fn preamble_size_hint() -> usize {
        HTTP_PREAMBLE_MAX_ENCODED_SIZE as usize
    }
    
    /// StacksHttp deals with HttpRequestPreambles and HttpResponsePreambles
    fn read_preamble(buf: &[u8]) -> Result<(NetworkPreamble, usize), net_error> {
        StacksHttpMessage::read_preamble(buf, buf.len() as u32)
    }

    /// StacksHttp deals with HttpRequestType and HttpResponseType
    fn read_payload(preamble: &NetworkPreamble, buf: &[u8]) -> Result<StacksHttpMessage, net_error> {
        StacksHttpMessage::read_payload(preamble, buf)
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

    #[test]
    fn test_parse_http_request_preamble_ok() {
        let tests = vec![
            ("GET /foo HTTP/1.1\r\nHost: localhost:6270\r\n\r\n",
             HttpRequestPreamble::from_headers("GET".to_string(), "/foo".to_string(), "localhost".to_string(), 6270, 0, vec!["host".to_string()], vec!["localhost:6270".to_string()])),
            ("POST asdf HTTP/1.0\r\nHost: core.blockstack.org\r\nFoo: Bar\r\n\r\n",
             HttpRequestPreamble::from_headers("POST".to_string(), "asdf".to_string(), "core.blockstack.org".to_string(), 80, 0, vec!["foo".to_string(), "host".to_string()], vec!["Bar".to_string(), "core.blockstack.org".to_string()])),
            ("POST asdf HTTP/1.0\r\nHost: core.blockstack.org\r\nFoo: Bar\r\nX-Request-Id: 123\r\n\r\n",
             HttpRequestPreamble::from_headers("POST".to_string(), "asdf".to_string(), "core.blockstack.org".to_string(), 80, 123, vec!["foo".to_string(), "host".to_string(), "x-request-id".to_string()], 
                                                                                                                                   vec!["Bar".to_string(), "core.blockstack.org".to_string(), "123".to_string()])),
        ];

        for (data, request) in tests.iter() {
            let mut index = 0;
            let req = HttpRequestPreamble::consensus_deserialize(&data.as_bytes().to_vec(), &mut index, data.len() as u32);
            assert!(req.is_ok(), format!("{:?}", &req));
            assert_eq!(req.unwrap(), *request);
            assert_eq!(index, data.len() as u32);
        }
    }

    #[test]
    fn test_parse_http_request_preamble_err() {
        let tests = vec![
            ("GET /foo HTTP/1.1\r\n",
            "Not enough bytes"),
            ("GET /foo HTTP/1.1\r\n\r\n",
             "Missing Host header"),
            ("GET /foo HTTP/1.1\r\nFoo: Bar\r\n\r\n",
             "Missing Host header"),
            ("GET /foo HTTP/\r\n\r\n",
             "Failed to parse HTTP request"),
            ("GET /foo HTTP/1.0\r\nHost:",
             "Not enough bytes"),
            ("GET /foo HTTP/1.1\r\nHost: foo:80\r\nHost: bar:80\r\n\r\n",
            "duplicate header"),
            ("GET /foo HTTP/1.1\r\nHost: foo:ffff\r\n\r\n",
            "Invalid Host header"),
            ("GET /foo HTTP/1.1\r\nHost: localhost:6270\r\nfoo: \u{2764}\r\n\r\n",
            "header value is not ASCII-US"),
            ("Get /foo HTTP/1.1\r\nHost: localhost:666666\r\n\r\n",
             "invalid port")
        ];

        for (data, errstr) in tests.iter() {
            let mut index = 0;
            let res = HttpRequestPreamble::consensus_deserialize(&data.as_bytes().to_vec(), &mut index, data.len() as u32);
            test_debug!("Expect '{}'", errstr);
            assert!(res.is_err(), format!("{:?}", &res));
            assert!(res.unwrap_err().description().find(errstr).is_some());
            assert_eq!(index, 0);
        }
    }

    #[test]
    fn test_http_request_preamble_headers() {
        let mut req = HttpRequestPreamble::new("GET".to_string(), "/foo".to_string(), "localhost".to_string(), 6270);
        req.set_request_id(123);
        req.add_header("foo".to_string(), "bar".to_string());

        let txt = String::from_utf8(req.consensus_serialize()).unwrap();
        assert!(txt.find("User-Agent: stacks/2.0\r\n").is_some(), "User-Agnet header is missing");
        assert!(txt.find("Host: localhost:6270\r\n").is_some(), "Host header is missing");
        assert!(txt.find("X-Request-Id: 123\r\n").is_some(), "X-Request-Id is missing");
        assert!(txt.find("foo: bar\r\n").is_some(), "foo header is missing");
    }

    #[test]
    fn test_parse_http_response_preamble_ok() {
        let tests = vec![
            ("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 123\r\nX-Request-ID: 0\r\nX-Request-Path: /foo\r\n\r\n",
             HttpResponsePreamble::from_headers(200, "OK".to_string(), 123, HttpContentType::Bytes, 0, "/foo".to_string(), 
                                                vec!["content-type".to_string(), "content-length".to_string(), "x-request-id".to_string(), "x-request-path".to_string()],
                                                vec!["application/octet-stream".to_string(), "123".to_string(), "0".to_string(), "/foo".to_string()])),
            ("HTTP/1.0 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 456\r\nFoo: Bar\r\nX-Request-ID: 0\r\nX-Request-Path: /foo\r\n\r\n",
             HttpResponsePreamble::from_headers(400, "Bad Request".to_string(), 456, HttpContentType::JSON, 0, "/foo".to_string(),
                                                vec!["content-type".to_string(), "content-length".to_string(), "foo".to_string(), "x-request-id".to_string(), "x-request-path".to_string()], 
                                                vec!["application/json".to_string(), "456".to_string(), "Bar".to_string(), "0".to_string(), "/foo".to_string(), ])),
            ("HTTP/1.0 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 456\r\nX-Request-Id: 123\r\nX-Request-path: /foo\r\nFoo: Bar\r\n\r\n",
             HttpResponsePreamble::from_headers(400, "Bad Request".to_string(), 456, HttpContentType::JSON, 123, "/foo".to_string(),
                                                vec!["content-type".to_string(), "content-length".to_string(), "x-request-id".to_string(), "foo".to_string(), "x-request-path".to_string()], 
                                                vec!["application/json".to_string(), "456".to_string(), "123".to_string(), "Bar".to_string(), "/foo".to_string()]))
        ];

        for (data, response) in tests.iter() {
            let mut index = 0;
            let res = HttpResponsePreamble::consensus_deserialize(&data.as_bytes().to_vec(), &mut index, data.len() as u32);
            assert!(res.is_ok(), format!("{:?}", &res));
            assert_eq!(res.unwrap(), *response);
            assert_eq!(index, data.len() as u32);
        }
    }

    #[test]
    fn test_http_response_preamble_headers() {
        let mut res = HttpResponsePreamble::new(200, "OK".to_string(), 456, HttpContentType::JSON, 456, "/foo".to_string());
        res.add_header("foo".to_string(), "bar".to_string());
        res.add_CORS_headers();

        let txt = String::from_utf8(res.consensus_serialize()).unwrap();
        assert!(txt.find("Server: stacks/2.0\r\n").is_some(), "Server header is missing");
        assert!(txt.find("Content-Length: 456\r\n").is_some(), "Content-Length is missing");
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
             "Not enough bytes"),
            ("HTTP/1.1 200 OK\r\nfoo: \u{2764}\r\n\r\n",
            "header value is not ASCII-US"),
            ("HTTP/1.1 200 OK\r\nfoo: bar\r\nfoo: bar\r\n\r\n",
             "duplicate header"),
            ("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n",
             "Unsupported Content-Type"),
            ("HTTP/1.1 200 OK\r\nContent-Length: foo\r\n\r\n",
             "Invalid Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 123\r\nX-Request-Id: 123\r\n\r\n",
             "missing Content-Type, Content-Length"),
            ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 123\r\nX-Request-Path: /foo\r\n\r\n",
             "missing Content-Type, Content-Length"),
        ];

        for (data, errstr) in tests.iter() {
            let mut index = 0;
            let res = HttpResponsePreamble::consensus_deserialize(&data.as_bytes().to_vec(), &mut index, data.len() as u32);
            test_debug!("Expect '{}', got: {:?}", errstr, &res);
            assert!(res.is_err(), format!("{:?}", &res));
            assert!(res.unwrap_err().description().find(errstr).is_some());
            assert_eq!(index, 0);
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
            "www.foo.com:1234567"
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

        let tx_body = make_test_transaction().consensus_serialize();
        let mut post_transaction_preamble = HttpRequestPreamble::new("POST".to_string(), "/v2/transactions".to_string(), http_request_metadata_dns.peer.hostname(), http_request_metadata_dns.peer.port());
        post_transaction_preamble.set_content_length(tx_body.len() as u32);
        post_transaction_preamble.set_content_type(HttpContentType::Bytes);

        // all of these should parse
        let expected_http_preambles = vec![
            HttpRequestPreamble::new("GET".to_string(), "/v2/neighbors".to_string(), http_request_metadata_ip.peer.hostname(), http_request_metadata_ip.peer.port()),
            HttpRequestPreamble::new("GET".to_string(), format!("/v2/blocks/{}", BlockHeaderHash([2u8; 32]).to_hex()), http_request_metadata_dns.peer.hostname(), http_request_metadata_dns.peer.port()),
            HttpRequestPreamble::new("GET".to_string(), format!("/v2/microblocks/{}", BlockHeaderHash([3u8; 32]).to_hex()), http_request_metadata_ip.peer.hostname(), http_request_metadata_ip.peer.port()),
            post_transaction_preamble
        ];

        let expected_http_bodies = vec![
            vec![],
            vec![],
            vec![],
            tx_body
        ];

        for (test, (expected_http_preamble, expected_http_body)) in tests.iter().zip(expected_http_preambles.iter().zip(expected_http_bodies.iter())) {
            let mut expected_bytes = expected_http_preamble.consensus_serialize();
            test_debug!("Expected preamble:\n{}", str::from_utf8(&expected_bytes).unwrap());

            if expected_http_preamble.content_type.is_none() || expected_http_preamble.content_type == Some(HttpContentType::Bytes) {
                test_debug!("Expected http body:\n{}", str::from_utf8(&expected_http_body).unwrap());
            }
            else {
                test_debug!("Expected http body (hex):\n{}", to_hex(&expected_http_body));
            }

            expected_bytes.append(&mut expected_http_body.clone());

            check_codec_and_corruption::<HttpRequestType>(test, &expected_bytes); 
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

        let tests = vec![
            HttpResponseType::Neighbors(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), test_neighbors_info.clone()),
            HttpResponseType::Block(HttpResponseMetadata::new(123, format!("/v2/blocks/{}", test_block_info.block_hash().to_hex())), test_block_info.clone()),
            HttpResponseType::Microblocks(HttpResponseMetadata::new(123, format!("/v2/microblocks/{}", test_microblock_info[0].block_hash().to_hex())), test_microblock_info.clone()),
            HttpResponseType::TransactionID(HttpResponseMetadata::new(123, "/v2/transactions".to_string()), Txid([0x1; 32])),

            // errors without error messages
            HttpResponseType::BadRequest(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "".to_string()),
            HttpResponseType::Unauthorized(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "".to_string()),
            HttpResponseType::PaymentRequired(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "".to_string()),
            HttpResponseType::Forbidden(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "".to_string()),
            HttpResponseType::NotFound(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "".to_string()),
            HttpResponseType::ServerError(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "".to_string()),
            HttpResponseType::ServiceUnavailable(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "".to_string()),
            HttpResponseType::Error(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), 502, "".to_string()),

            // errors with specific messages
            HttpResponseType::BadRequest(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "foo".to_string()),
            HttpResponseType::Unauthorized(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "foo".to_string()),
            HttpResponseType::PaymentRequired(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "foo".to_string()),
            HttpResponseType::Forbidden(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "foo".to_string()),
            HttpResponseType::NotFound(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "foo".to_string()),
            HttpResponseType::ServerError(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "foo".to_string()),
            HttpResponseType::ServiceUnavailable(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), "foo".to_string()),
            HttpResponseType::Error(HttpResponseMetadata::new(123, "/v2/neighbors".to_string()), 502, "foo".to_string()),
        ];

        let expected_http_preambles = vec![
            HttpResponsePreamble::new(200, "OK".to_string(), serde_json::to_string(&test_neighbors_info).unwrap().len() as u32, HttpContentType::JSON, 123, "/v2/neighbors".to_string()),
            HttpResponsePreamble::new(200, "OK".to_string(), test_block_info.consensus_serialize().len() as u32, HttpContentType::Bytes, 123, format!("/v2/blocks/{}", test_block_info.block_hash().to_hex())),
            HttpResponsePreamble::new(200, "OK".to_string(), test_microblock_info.consensus_serialize().len() as u32, HttpContentType::Bytes, 123, format!("/v2/microblocks/{}", test_microblock_info[0].block_hash().to_hex())),
            HttpResponsePreamble::new(200, "OK".to_string(), Txid([0x1; 32]).to_hex().len() as u32, HttpContentType::Text, 123, "/v2/transactions".to_string()),

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
            serde_json::to_string(&test_neighbors_info).unwrap().as_bytes().to_vec(),
            test_block_info.consensus_serialize(),
            test_microblock_info.consensus_serialize(),
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
            let mut expected_bytes = expected_http_preamble.consensus_serialize();
            test_debug!("Expected preamble:\n{}", str::from_utf8(&expected_bytes).unwrap());

            if expected_http_preamble.content_type != HttpContentType::Bytes {
                test_debug!("Expected http body:\n{}", str::from_utf8(&expected_http_body).unwrap());
            }
            else {
                test_debug!("Expected http body (hex):\n{}", to_hex(&expected_http_body));
            }

            expected_bytes.append(&mut expected_http_body.clone());

            check_codec_and_corruption::<HttpResponseType>(test, &expected_bytes);
        }
    }
}

