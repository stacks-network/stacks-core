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

use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use serde::de::{Deserialize, Error as de_Error};
use serde::ser::Serialize;

use crate::util::hash::to_bin;

#[derive(Debug)]
pub enum Error {
    DecodeError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::DecodeError(msg) => write!(f, "{}", &msg),
        }
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        match self {
            Error::DecodeError(_) => None,
        }
    }
}

/// A container for an IPv4 or IPv6 address.
/// Rules:
/// -- If this is an IPv6 address, the octets are in network byte order
/// -- If this is an IPv4 address, the octets must encode an IPv6-to-IPv4-mapped address
pub struct PeerAddress(pub [u8; 16]);
impl_array_newtype!(PeerAddress, u8, 16);
impl_array_hexstring_fmt!(PeerAddress);
impl_byte_array_newtype!(PeerAddress, u8, 16);
impl_byte_array_message_codec!(PeerAddress, 16);

impl Serialize for PeerAddress {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let inst = format!("{}", self.to_socketaddr(0).ip());
        s.serialize_str(inst.as_str())
    }
}

impl<'de> Deserialize<'de> for PeerAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PeerAddress, D::Error> {
        let inst = String::deserialize(d)?;
        let ip = inst.parse::<IpAddr>().map_err(de_Error::custom)?;

        Ok(PeerAddress::from_ip(&ip))
    }
}

impl PeerAddress {
    pub fn from_slice(bytes: &[u8]) -> Option<PeerAddress> {
        if bytes.len() != 16 {
            return None;
        }

        let mut bytes16 = [0u8; 16];
        bytes16.copy_from_slice(&bytes[0..16]);
        Some(PeerAddress(bytes16))
    }

    /// Is this an IPv4 address?
    pub fn is_ipv4(&self) -> bool {
        self.ipv4_octets().is_some()
    }

    /// Get the octet representation of this peer address as an IPv4 address.
    /// The last 4 bytes of the list contain the IPv4 address.
    /// This method returns None if the bytes don't encode a valid IPv4-mapped address (i.e. ::ffff:0:0/96)
    pub fn ipv4_octets(&self) -> Option<[u8; 4]> {
        if self.0[0..12]
            != [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
            ]
        {
            return None;
        }
        let mut ret = [0u8; 4];
        ret.copy_from_slice(&self.0[12..16]);
        Some(ret)
    }

    /// Return the bit representation of this peer address as an IPv4 address, in network byte
    /// order.  Return None if this is not an IPv4 address.
    pub fn ipv4_bits(&self) -> Option<u32> {
        let octets_opt = self.ipv4_octets();
        octets_opt?;

        let octets = octets_opt.unwrap();
        Some(
            ((octets[0] as u32) << 24)
                | ((octets[1] as u32) << 16)
                | ((octets[2] as u32) << 8)
                | (octets[3] as u32),
        )
    }

    /// Convert to SocketAddr
    pub fn to_socketaddr(&self, port: u16) -> SocketAddr {
        if self.is_ipv4() {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    self.0[12], self.0[13], self.0[14], self.0[15],
                )),
                port,
            )
        } else {
            let addr_words: [u16; 8] = [
                ((self.0[0] as u16) << 8) | (self.0[1] as u16),
                ((self.0[2] as u16) << 8) | (self.0[3] as u16),
                ((self.0[4] as u16) << 8) | (self.0[5] as u16),
                ((self.0[6] as u16) << 8) | (self.0[7] as u16),
                ((self.0[8] as u16) << 8) | (self.0[9] as u16),
                ((self.0[10] as u16) << 8) | (self.0[11] as u16),
                ((self.0[12] as u16) << 8) | (self.0[13] as u16),
                ((self.0[14] as u16) << 8) | (self.0[15] as u16),
            ];

            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(
                    addr_words[0],
                    addr_words[1],
                    addr_words[2],
                    addr_words[3],
                    addr_words[4],
                    addr_words[5],
                    addr_words[6],
                    addr_words[7],
                )),
                port,
            )
        }
    }

    /// Convert from socket address
    pub fn from_socketaddr(addr: &SocketAddr) -> PeerAddress {
        PeerAddress::from_ip(&addr.ip())
    }

    /// Convert from IP address
    pub fn from_ip(addr: &IpAddr) -> PeerAddress {
        match addr {
            IpAddr::V4(ref addr) => {
                let octets = addr.octets();
                PeerAddress([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                    octets[0], octets[1], octets[2], octets[3],
                ])
            }
            IpAddr::V6(ref addr) => {
                let words = addr.segments();
                PeerAddress([
                    (words[0] >> 8) as u8,
                    (words[0] & 0xff) as u8,
                    (words[1] >> 8) as u8,
                    (words[1] & 0xff) as u8,
                    (words[2] >> 8) as u8,
                    (words[2] & 0xff) as u8,
                    (words[3] >> 8) as u8,
                    (words[3] & 0xff) as u8,
                    (words[4] >> 8) as u8,
                    (words[4] & 0xff) as u8,
                    (words[5] >> 8) as u8,
                    (words[5] & 0xff) as u8,
                    (words[6] >> 8) as u8,
                    (words[6] & 0xff) as u8,
                    (words[7] >> 8) as u8,
                    (words[7] & 0xff) as u8,
                ])
            }
        }
    }

    /// Convert from ipv4 octets
    pub fn from_ipv4(o1: u8, o2: u8, o3: u8, o4: u8) -> PeerAddress {
        PeerAddress([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, o1, o2, o3, o4,
        ])
    }

    /// Is this the any-network address?  i.e. 0.0.0.0 (v4) or :: (v6)?
    pub fn is_anynet(&self) -> bool {
        self.0 == [0x00; 16] || self == &PeerAddress::from_ipv4(0, 0, 0, 0)
    }

    /// Is this a private IP address?
    pub fn is_in_private_range(&self) -> bool {
        if self.is_ipv4() {
            // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or 127.0.0.0/8
            self.0[12] == 10
                || (self.0[12] == 172 && self.0[13] >= 16 && self.0[13] <= 31)
                || (self.0[12] == 192 && self.0[13] == 168)
                || self.0[12] == 127
        } else {
            // private address (fc00::/7) or localhost (::1)
            self.0[0] >= 0xfc || (self.0[0..15] == [0u8; 15] && self.0[15] == 1)
        }
    }

    /// Is this a local loopback address?
    pub fn is_loopback(&self) -> bool {
        self.to_socketaddr(0).ip().is_loopback()
    }

    pub fn to_bin(&self) -> String {
        to_bin(&self.0)
    }
}

/// Peer address variants for the Host: header
#[derive(Clone, PartialEq)]
pub enum PeerHost {
    DNS(String, u16),
    IP(PeerAddress, u16),
}

impl fmt::Display for PeerHost {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PeerHost::DNS(ref s, ref p) => write!(f, "{}:{}", s, p),
            PeerHost::IP(ref a, ref p) => write!(f, "{}", a.to_socketaddr(*p)),
        }
    }
}

impl fmt::Debug for PeerHost {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PeerHost::DNS(ref s, ref p) => write!(f, "PeerHost::DNS({},{})", s, p),
            PeerHost::IP(ref a, ref p) => write!(f, "PeerHost::IP({:?},{})", a, p),
        }
    }
}

impl Hash for PeerHost {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match *self {
            PeerHost::DNS(ref name, ref port) => {
                "DNS".hash(state);
                name.hash(state);
                port.hash(state);
            }
            PeerHost::IP(ref addrbytes, ref port) => {
                "IP".hash(state);
                addrbytes.hash(state);
                port.hash(state);
            }
        }
    }
}

impl FromStr for PeerHost {
    type Err = Error;

    fn from_str(header: &str) -> Result<PeerHost, Error> {
        // we're looser than the RFC allows for DNS names -- anything that doesn't parse to an IP
        // address will be parsed to a DNS name.
        // try as IP:port
        match header.parse::<SocketAddr>() {
            Ok(socketaddr) => Ok(PeerHost::IP(
                PeerAddress::from_socketaddr(&socketaddr),
                socketaddr.port(),
            )),
            Err(_) => {
                // maybe missing :port
                let hostport = format!("{}:80", header);
                match hostport.parse::<SocketAddr>() {
                    Ok(socketaddr) => Ok(PeerHost::IP(
                        PeerAddress::from_socketaddr(&socketaddr),
                        socketaddr.port(),
                    )),
                    Err(_) => {
                        // try as DNS-name:port
                        let host;
                        let port;
                        let parts: Vec<&str> = header.split(':').collect();
                        if parts.is_empty() {
                            return Err(Error::DecodeError(
                                "Failed to parse PeerHost: no parts".to_string(),
                            ));
                        } else if parts.len() == 1 {
                            // no port
                            host = Some(parts[0].to_string());
                            port = Some(80);
                        } else {
                            let np = parts.len();
                            if parts[np - 1].chars().all(char::is_numeric) {
                                // ends in :port
                                let host_str = parts[0..np - 1].join(":");
                                if host_str.is_empty() {
                                    return Err(Error::DecodeError("Empty host".to_string()));
                                }
                                host = Some(host_str);

                                let port_res = parts[np - 1].parse::<u16>();
                                port = match port_res {
                                    Ok(p) => Some(p),
                                    Err(_) => {
                                        return Err(Error::DecodeError(
                                            "Failed to parse PeerHost: invalid port".to_string(),
                                        ));
                                    }
                                };
                            } else {
                                // only host
                                host = Some(header.to_string());
                                port = Some(80);
                            }
                        }

                        match (host, port) {
                            (Some(h), Some(p)) => Ok(PeerHost::DNS(h, p)),
                            (_, _) => Err(Error::DecodeError(
                                "Failed to parse PeerHost: failed to extract host and/or port"
                                    .to_string(),
                            )), // I don't think this is reachable
                        }
                    }
                }
            }
        }
    }
}

impl PeerHost {
    pub fn hostname(&self) -> String {
        match *self {
            PeerHost::DNS(ref s, _) => s.clone(),
            PeerHost::IP(ref a, ref p) => format!("{}", a.to_socketaddr(*p).ip()),
        }
    }

    pub fn port(&self) -> u16 {
        match *self {
            PeerHost::DNS(_, ref p) => *p,
            PeerHost::IP(_, ref p) => *p,
        }
    }

    pub fn from_host_port(host: String, port: u16) -> PeerHost {
        // try as IP, and fall back to DNS
        match host.parse::<IpAddr>() {
            Ok(addr) => PeerHost::IP(PeerAddress::from_ip(&addr), port),
            Err(_) => PeerHost::DNS(host, port),
        }
    }

    pub fn from_socketaddr(socketaddr: &SocketAddr) -> PeerHost {
        PeerHost::IP(PeerAddress::from_socketaddr(socketaddr), socketaddr.port())
    }

    pub fn to_host_port(&self) -> (String, u16) {
        match *self {
            PeerHost::DNS(ref s, ref p) => (s.clone(), *p),
            PeerHost::IP(ref i, ref p) => (format!("{}", i.to_socketaddr(0).ip()), *p),
        }
    }
}

impl From<SocketAddr> for PeerHost {
    fn from(addr: SocketAddr) -> PeerHost {
        PeerHost::from_socketaddr(&addr)
    }
}
