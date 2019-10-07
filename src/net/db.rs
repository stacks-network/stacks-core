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

use std::fmt;

use rusqlite::{Connection, OpenFlags, NO_PARAMS};
use rusqlite::types::ToSql;
use rusqlite::Row;
use rusqlite::Transaction;

use std::fs;
use std::convert::From;

use util::db::{FromRow, RowOrder, query_rows, query_count};
use util::db::Error as db_error;
use util::db::DBConn;

use util;
use util::log;
use util::hash::{to_hex, hex_bytes, Hash160, Sha512Trunc256Sum};
use util::secp256k1::Secp256k1PrivateKey;
use util::secp256k1::Secp256k1PublicKey;
use util::macros::is_big_endian;

use rand::RngCore;
use rand::Rng;
use rand::thread_rng;
use rand::seq::SliceRandom;

use net::asn::ASEntry4;
use net::PeerAddress;
use net::Neighbor;
use net::NeighborKey;
use net::ServiceFlags;

use burnchains::PublicKey;
use burnchains::PrivateKey;

use core::NETWORK_P2P_PORT;

pub const PEERDB_VERSION : &'static str = "21.0.0.0";

const NUM_SLOTS : usize = 8;

impl FromRow<PeerAddress> for PeerAddress {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<PeerAddress, db_error> {
        let addrbytes_hex : String = row.get(index);
        let addrbytes = hex_bytes(&addrbytes_hex)
            .map_err(|_e| {
                error!("Unparseable peer address {}", addrbytes_hex);
                db_error::ParseError
            })?;

        if addrbytes.len() != 16 {
            error!("Peer address has {} bytes; expected 16", addrbytes.len());
            return Err(db_error::ParseError);
        }

        let mut addrbytes_buf = [0u8; 16];
        addrbytes_buf.copy_from_slice(&addrbytes[0..16]);

        Ok(PeerAddress(addrbytes_buf))
    }
}

#[derive(PartialEq, Clone)]
pub struct LocalPeer {
    pub network_id: u32,
    nonce: [u8; 32],
    pub private_key: Secp256k1PrivateKey,
    pub private_key_expire: u64,

    pub addrbytes: PeerAddress,
    pub port: u16,
    pub services: u16
}

impl fmt::Display for LocalPeer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "local.{:x}://{:?}:{}", self.network_id, &self.addrbytes, self.port)
    }
}

impl fmt::Debug for LocalPeer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "local.{:x}://{:?}:{}", self.network_id, &self.addrbytes, self.port)
    }
}

impl LocalPeer {
    pub fn new(network_id: u32, key_expire: u64) -> LocalPeer {
        let mut rng = thread_rng();
        let my_private_key = Secp256k1PrivateKey::new();
        let mut my_nonce = [0u8; 32];

        rng.fill_bytes(&mut my_nonce);

        let addr = PeerAddress::from_ipv4(127, 0, 0, 1);
        let port = NETWORK_P2P_PORT;
        let services = ServiceFlags::RELAY;

        LocalPeer {
            network_id: network_id,
            nonce: my_nonce,
            private_key: my_private_key,
            private_key_expire: key_expire,
            addrbytes: addr,
            port: port,
            services: services as u16
        }
    }
}

impl RowOrder for LocalPeer {
    fn row_order() -> Vec<&'static str> {
        vec!["network_id", "nonce", "private_key", "private_key_expire", "addrbytes", "port", "services"]
    }
}

impl FromRow<LocalPeer> for LocalPeer {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<LocalPeer, db_error> {
        let network_id : u32 = row.get(index);
        let nonce_hex : String = row.get(index + 1);
        let privkey = Secp256k1PrivateKey::from_row(row, index + 2)?;
        let privkey_expire_i64 : i64 = row.get(index + 3);
        let addrbytes : PeerAddress = PeerAddress::from_row(row, index + 4)?;
        let port : u16 = row.get(index + 5);
        let services : u16 = row.get(index + 6);

        let nonce_bytes = hex_bytes(&nonce_hex)
            .map_err(|_e| {
                error!("Unparseable local peer nonce {}", &nonce_hex);
                db_error::ParseError
            })?;

        if nonce_bytes.len() != 32 {
            error!("Peer nonce has {} bytes: {}", nonce_bytes.len(), nonce_hex);
            return Err(db_error::ParseError);
        }

        let mut nonce_buf = [0u8; 32];
        nonce_buf.copy_from_slice(&nonce_bytes[0..32]);

        if privkey_expire_i64 < 0 {
            return Err(db_error::ParseError);
        }

        Ok(LocalPeer {
            network_id: network_id,
            private_key: privkey,
            nonce: nonce_buf,
            private_key_expire: privkey_expire_i64 as u64,
            addrbytes: addrbytes,
            port: port,
            services: services
        })
    }
}

impl RowOrder for ASEntry4 {
    fn row_order() -> Vec<&'static str> {
        vec!["prefix", "mask", "asn", "org"]
    }
}

impl FromRow<ASEntry4> for ASEntry4 {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<ASEntry4, db_error> {
        let prefix : u32 = row.get(index);
        let mask : u8 = row.get(index+1);
        let asn : u32 = row.get(index+2);
        let org : u32 = row.get(index+3);

        Ok(ASEntry4 {
            prefix,
            mask,
            asn,
            org
        })
    }
}

impl RowOrder for Neighbor {
    fn row_order() -> Vec<&'static str> {
        vec!["peer_version", "network_id", "addrbytes", "port", "public_key", "expire_block_height", "last_contact_time", "asn", "org", "whitelisted", "blacklisted", "in_degree", "out_degree"]
    }
}

impl FromRow<Neighbor> for Neighbor {
    fn from_row<'a>(row: &'a Row, index: usize) -> Result<Neighbor, db_error> {
        let peer_version : u32 = row.get(index);
        let network_id : u32 = row.get(index+1);
        let addrbytes : PeerAddress = PeerAddress::from_row(row, index+2)?;
        let port : u16 = row.get(index+3);
        let public_key : Secp256k1PublicKey = Secp256k1PublicKey::from_row(row, index+4)?;
        let expire_block_height_i64 : i64 = row.get(index+5);
        let last_contact_time_i64 : i64 = row.get(index+6);
        let asn : u32 = row.get(index+7);
        let org : u32 = row.get(index+8);
        let whitelisted : i64 = row.get(index+9);
        let blacklisted : i64 = row.get(index+10);
        let in_degree_i64 : i64 = row.get(index+11);
        let out_degree_i64 : i64 = row.get(index+12);

        if expire_block_height_i64 < 0 {
            error!("Invalid expore block height {}", expire_block_height_i64);
            return Err(db_error::ParseError);
        }

        if last_contact_time_i64 < 0 {
            error!("Invalid last contact time {}", last_contact_time_i64);
            return Err(db_error::ParseError);
        }

        if in_degree_i64 < 0 {
            error!("Invalid in_degree {}", in_degree_i64);
            return Err(db_error::ParseError);
        }

        if out_degree_i64 < 0 {
            error!("Invalid out_degree {}", out_degree_i64);
            return Err(db_error::ParseError);
        }

        let expire_block_height = expire_block_height_i64 as u64;
        let last_contact_time = last_contact_time_i64 as u64;

        Ok(Neighbor {
            addr: NeighborKey {
                peer_version: peer_version,
                network_id: network_id,
                addrbytes: addrbytes,
                port: port,
            },
            public_key: public_key,
            expire_block: expire_block_height,
            last_contact_time: last_contact_time,
            asn: asn,
            org: org,
            whitelisted: whitelisted,
            blacklisted: blacklisted,
            in_degree: in_degree_i64 as u32,
            out_degree: out_degree_i64 as u32,
        })
    }
}

// In what is likely an abuse of Sqlite, the peer database is structured such that the `frontier`
// table stores peers keyed by a deterministically-chosen random "slot," instead of their IP/port.
// (i.e. the slot is determined by a cryptographic the hash of the IP/port).  The reason for this
// is to facilitate randomized peer eviction when the frontier table gets too big -- if a peer's
// possible slots are taken, then the _existing_ peer is pinged to see if it is still online.  If
// it is still online, the new peer will _not_ be inserted.  If it is offline, then it will be.
// This is done to ensure that the frontier represents live, long-lived peers to the greatest
// extent possible.
const PEERDB_SETUP : &'static [&'static str]= &[
    r#"
    CREATE TABLE frontier(
        peer_version INTEGER NOT NULL,
        network_id INTEGER NOT NULL,
        addrbytes TEXT NOT NULL,
        port INTEGER NOT NULL,
        public_key TEXT NOT NULL,
        expire_block_height INTEGER NOT NULL,
        last_contact_time INTEGER NOT NULL,
        asn INTEGER NOT NULL,
        org INTEGER NOT NULL,
        whitelisted INTEGER NOT NULL,
        blacklisted INTEGER NOT NULL,
        in_degree INTEGER NOT NULL,
        out_degree INTEGER NOT NULL,

        -- used to deterministically insert and evict
        slot INTEGER UNIQUE NOT NULL,

        PRIMARY KEY(slot)
    );"#,
    r#"
    CREATE TABLE asn4(
        prefix INTEGER NOT NULL,
        mask INTEGER NOT NULL,

        asn INTEGER NOT NULL,
        org INTEGER,

        PRIMARY KEY(prefix,mask)
    );"#,
    r#"
    CREATE TABLE db_version(version TEXT NOT NULL);
    "#,
    r#"
    CREATE TABLE local_peer(
        network_id INT NOT NULL,
        nonce TEXT NOT NULL,
        private_key TEXT NOT NULL,
        private_key_expire INTEGER NOT NULL,
        addrbytes TEXT NOT NULL,
        port INTEGER NOT NULL,
        services INTEGER NOT NULL
    );"#
];

pub struct PeerDB {
    pub conn: Connection,
    pub readwrite: bool,
}

impl PeerDB {
    fn instantiate(&mut self, network_id: u32, key_expires: u64, asn4_entries: &Vec<ASEntry4>, initial_neighbors: &Vec<Neighbor>) -> Result<(), db_error> {
        let localpeer = LocalPeer::new(network_id, key_expires);

        let mut tx = self.tx_begin()?;

        for row_text in PEERDB_SETUP {
            tx.execute(row_text, NO_PARAMS)
                .map_err(db_error::SqliteError)?;
        }

        tx.execute("INSERT INTO db_version (version) VALUES (?1)", &[&PEERDB_VERSION])
            .map_err(db_error::SqliteError)?;

        tx.execute("INSERT INTO local_peer (network_id, nonce, private_key, private_key_expire, addrbytes, port, services) VALUES (?1,?2,?3,?4,?5,?6,?7)", 
                   &[&network_id as &ToSql, &to_hex(&localpeer.nonce.to_vec()) as &ToSql, &to_hex(&localpeer.private_key.to_bytes()) as &ToSql, &(key_expires as i64) as &ToSql,
                     &to_hex(&localpeer.addrbytes.as_bytes().to_vec()), &localpeer.port as &ToSql, &(localpeer.services as u16) as &ToSql])
            .map_err(db_error::SqliteError)?;

        for neighbor in initial_neighbors {
            // do we have this neighbor already?
            let res = PeerDB::try_insert_peer(&mut tx, &neighbor)?;
            if !res {
                warn!("Failed to insert neighbor {:?}", &neighbor);
            }
        }

        for asn4 in asn4_entries {
            PeerDB::asn4_insert(&mut tx, &asn4)?;
        }

        tx.commit()
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Open the burn database at the given path.  Open read-only or read/write.
    /// If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(path: &String, readwrite: bool, network_id: u32, key_expires: u64, asn4_path: &Option<String>, initial_neighbors: Option<&Vec<Neighbor>>) -> Result<PeerDB, db_error> {
        let mut create_flag = false;
        let open_flags =
            if fs::metadata(path).is_err() {
                // need to create 
                if readwrite {
                    create_flag = true;
                    OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                }
                else {
                    return Err(db_error::NoDBError);
                }
            }
            else {
                // can just open 
                if readwrite {
                    OpenFlags::SQLITE_OPEN_READ_WRITE
                }
                else {
                    OpenFlags::SQLITE_OPEN_READ_ONLY
                }
            };

        let mut asn4_recs = vec![];
        match asn4_path {
            Some(path) => {
                asn4_recs = ASEntry4::from_file(&path)
                    .map_err(|_e| db_error::ParseError)?;
            },
            None => {}
        }

        let conn = Connection::open_with_flags(path, open_flags)
            .map_err(|e| db_error::SqliteError(e))?;

        let mut db = PeerDB {
            conn: conn,
            readwrite: readwrite,
        };

        if create_flag {
            // instantiate!
            match initial_neighbors {
                Some(ref neighbors) => {
                    db.instantiate(network_id, key_expires, &asn4_recs, neighbors)?;
                },
                None => {
                    db.instantiate(network_id, key_expires, &asn4_recs, &vec![])?;
                }
            }
        }
        Ok(db)
    }

    /// Open a burn database in memory (used for testing)
    pub fn connect_memory(network_id: u32, key_expires: u64, asn4_entries: &Vec<ASEntry4>, initial_neighbors: &Vec<Neighbor>) -> Result<PeerDB, db_error> {
        let conn = Connection::open_in_memory()
            .map_err(|e| db_error::SqliteError(e))?;

        let mut db = PeerDB {
            conn: conn,
            readwrite: true,
        };

        db.instantiate(network_id, key_expires, asn4_entries, initial_neighbors)?;
        Ok(db)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }
    
    pub fn tx_begin<'a>(&'a mut self) -> Result<Transaction<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = self.conn.transaction()
            .map_err(|e| db_error::SqliteError(e))?;
        Ok(tx)
    }

    /// Read the local peer record 
    pub fn get_local_peer(conn: &DBConn) -> Result<LocalPeer, db_error> {
        let row_order = LocalPeer::row_order().join(",");
        let qry = format!("SELECT {} FROM local_peer LIMIT 1", row_order);
        let rows = query_rows::<LocalPeer, _>(conn, &qry.to_string(), NO_PARAMS)?;

        match rows.len() {
            1 => Ok(rows[0].clone()),
            _ => {
                // only one item here 
                panic!("Got multiple LocalPeer rows, or 0");
            }
        }
    }

    /// Set the local IP address and port 
    pub fn set_local_ipaddr<'a>(tx: &mut Transaction<'a>, addrbytes: &PeerAddress, port: u16) -> Result<(), db_error> {
        tx.execute("UPDATE local_peer SET addrbytes = ?1, port = ?2", &[&to_hex(&addrbytes.as_bytes().to_vec()), &port as &ToSql])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Set local service availability 
    pub fn set_local_services<'a>(tx: &mut Transaction<'a>, services: u16) -> Result<(), db_error> {
        tx.execute("UPDATE local_peer SET services = ?1", &[&services as &ToSql])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Set local private key and expiry 
    pub fn set_local_private_key<'a>(tx: &mut Transaction<'a>, privkey: &Secp256k1PrivateKey, expire_block: u64) -> Result<(), db_error> {
        if expire_block > ((1 as u64) << 63) - 1 {
            return Err(db_error::Overflow);
        }

        tx.execute("UPDATE local_peer SET private_key = ?1, private_key_expire = ?2",
                   &[&to_hex(&privkey.to_bytes()), &(expire_block as i64) as &ToSql])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Re-key and return the new local peer 
    pub fn rekey(&mut self, new_expire_block: u64) -> Result<LocalPeer, db_error> {
        if new_expire_block > ((1 as u64) << 63) - 1 {
            return Err(db_error::Overflow);
        }

        let new_key = Secp256k1PrivateKey::new();
        {
            let mut tx = self.tx_begin()?;

            PeerDB::set_local_private_key(&mut tx, &new_key, new_expire_block)?;
            tx.commit()
                .map_err(db_error::SqliteError)?;
        }

        PeerDB::get_local_peer(self.conn())
    }

    /// Calculate the "slots" in the peer database where this peer can be inserted.
    /// Slots are distributed uniformly at random between 0 and 2**24.
    /// NUM_SLOTS will be returned.
    pub fn peer_slots(conn: &DBConn, network_id: u32, peer_addr: &PeerAddress, peer_port: u16) -> Result<Vec<u32>, db_error> {
        let local_peer = PeerDB::get_local_peer(conn)?;
        let mut ret = vec![];
        for i in 0..NUM_SLOTS {
            // pack peer address, port, and index.
            // Randomize with local nonce 
            let mut bytes = vec![];
            bytes.append(&mut local_peer.nonce.to_vec().clone());
            bytes.push(i as u8);

            for i in 0..16 {
                bytes.push(peer_addr.as_bytes()[i]);
            }

            bytes.push((peer_port & 0xff) as u8);
            bytes.push((peer_port >> 8) as u8);

            bytes.push(((network_id & 0xff000000) >> 24) as u8);
            bytes.push(((network_id & 0x00ff0000) >> 16) as u8);
            bytes.push(((network_id & 0x0000ff00) >>  8) as u8);
            bytes.push(((network_id & 0x000000ff)      ) as u8);

            let h = Sha512Trunc256Sum::from_data(&bytes[..]);
            let slot : u32 =
                (h.as_bytes()[0] as u32) |
                ((h.as_bytes()[1] as u32) << 8) |
                ((h.as_bytes()[2] as u32) << 16);

            ret.push(slot);
        }
        Ok(ret)
    }

    /// Do we have this neighbor already?  If so, look it up.
    /// Panics if the peer was inserted twice -- this shouldn't happen.
    pub fn get_peer(conn: &DBConn, network_id: u32, peer_addr: &PeerAddress, peer_port: u16) -> Result<Option<Neighbor>, db_error> {
        let row_order = Neighbor::row_order().join(",");
        let qry = format!("SELECT {} FROM frontier WHERE network_id = ?1 AND addrbytes = ?2 AND port = ?3", row_order);
        let args = [&network_id as &ToSql, &peer_addr.to_hex() as &ToSql, &peer_port as &ToSql];
        let rows = query_rows::<Neighbor, _>(conn, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // if this happens, it's a bug 
                panic!("FATAL: multiple entries for peer {}:{:?}:{}", network_id, &peer_addr, peer_port);
            }
        }
    }

    /// Get a peer record at a particular slot
    pub fn get_peer_at(conn: &DBConn, network_id: u32, slot: u32) -> Result<Option<Neighbor>, db_error> {
        let row_order = Neighbor::row_order().join(",");
        let qry = format!("SELECT {} FROM frontier WHERE network_id = ?1 AND slot = ?2", row_order);
        let args = [&network_id as &ToSql, &slot as &ToSql];
        let rows = query_rows::<Neighbor, _>(conn, &qry.to_string(), &args)?;

        match rows.len() {
            0 => Ok(None),
            1 => Ok(Some(rows[0].clone())),
            _ => {
                // if this happens, it's a bug
                panic!("FATAL: multiple peers with the same slot {}", slot);
            }
        }
    }

    /// Insert or replace a neighbor into a given slot 
    pub fn insert_or_replace_peer<'a>(tx: &mut Transaction<'a>, neighbor: &Neighbor, slot: u32) -> Result<(), db_error> {
        if neighbor.last_contact_time > ((1 as u64) << 63) - 1 {
            return Err(db_error::Overflow);
        }

        if neighbor.expire_block > ((1 as u64) << 63) - 1 {
            return Err(db_error::Overflow);
        }

        tx.execute("INSERT OR REPLACE INTO frontier (peer_version, network_id, addrbytes, port, public_key, expire_block_height, last_contact_time, asn, org, whitelisted, blacklisted, in_degree, out_degree, slot) \
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                   &[&neighbor.addr.peer_version as &ToSql, &neighbor.addr.network_id as &ToSql, &to_hex(&neighbor.addr.addrbytes.as_bytes().to_vec()) as &ToSql, &neighbor.addr.port,
                     &to_hex(&neighbor.public_key.to_bytes_compressed()), &(neighbor.expire_block as i64) as &ToSql, &(neighbor.last_contact_time as i64) as &ToSql,
                     &neighbor.asn, &neighbor.org, &neighbor.whitelisted, &neighbor.blacklisted, &(neighbor.in_degree as i64) as &ToSql, &(neighbor.out_degree as i64) as &ToSql, &slot])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Remove a peer from the peer database 
    pub fn drop_peer<'a>(tx: &mut Transaction<'a>, network_id: u32, peer_addr: &PeerAddress, peer_port: u16) -> Result<(), db_error> {
        tx.execute("DELETE FROM frontier WHERE network_id = ?1 AND addrbytes = ?2 AND port = ?3",
                   &[&network_id as &ToSql, &peer_addr.to_hex() as &ToSql, &peer_port as &ToSql])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Set/unset whitelist flag for a peer
    /// Pass -1 for "always"
    pub fn set_whitelist_peer<'a>(tx: &mut Transaction<'a>, network_id: u32, peer_addr: &PeerAddress, peer_port: u16, whitelist_deadline: i64) -> Result<(), db_error> {
        tx.execute("UPDATE frontier SET whitelisted = ?1 WHERE network_id = ?2 AND addrbytes = ?3 AND port = ?4",
                   &[&whitelist_deadline as &ToSql, &network_id, &peer_addr.to_hex(), &peer_port])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Set/unset blacklist flag for a peer
    /// negative values aren't allowed
    pub fn set_blacklist_peer<'a>(tx: &mut Transaction<'a>, network_id: u32, peer_addr: &PeerAddress, peer_port: u16, blacklist_deadline: u64) -> Result<(), db_error> {
        if blacklist_deadline > ((1 as u64) << 63) - 1 {
            return Err(db_error::Overflow);
        }

        tx.execute("UPDATE frontier SET blacklisted = ?1 WHERE network_id = ?2 AND addrbytes = ?3 AND port = ?4",
                   &[&(blacklist_deadline as i64) as &ToSql, &network_id, &peer_addr.to_hex(), &peer_port])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Update an existing peer's entries.  Does nothing if the peer is not present.
    pub fn update_peer<'a>(tx: &mut Transaction<'a>, neighbor: &Neighbor) -> Result<(), db_error> {
        if neighbor.last_contact_time > ((1 as u64) << 63) - 1 {
            return Err(db_error::Overflow);
        }

        if neighbor.expire_block > ((1 as u64) << 63) - 1 {
            return Err(db_error::Overflow);
        }

        tx.execute("UPDATE frontier SET peer_version = ?1, public_key = ?2, expire_block_height = ?3, last_contact_time = ?4, asn = ?5, org = ?6, whitelisted = ?7, blacklisted = ?8, in_degree = ?9, out_degree = ?10 \
                    WHERE network_id = ?11 AND addrbytes = ?12 AND port = ?13",
                   &[&neighbor.addr.peer_version as &ToSql, &to_hex(&neighbor.public_key.to_bytes_compressed()), &(neighbor.expire_block as i64) as &ToSql, &(neighbor.last_contact_time as i64) as &ToSql,
                     &neighbor.asn, &neighbor.org, &neighbor.whitelisted, &neighbor.blacklisted, &(neighbor.in_degree as i64) as &ToSql, &(neighbor.out_degree as i64) as &ToSql,
                   &neighbor.addr.network_id as &ToSql, &to_hex(&neighbor.addr.addrbytes.as_bytes().to_vec()) as &ToSql, &neighbor.addr.port])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Try to insert a peer at one of its slots.
    /// Does not insert the peer if it is already present, but will instead try to update it with
    /// this peer's information.
    /// If at least one slot was empty, or if the peer is already present and can be updated, then insert/update the peer and return true.
    /// If all slots are occupied, return false.
    pub fn try_insert_peer<'a>(tx: &mut Transaction<'a>, neighbor: &Neighbor) -> Result<bool, db_error> {
        let present = PeerDB::get_peer(tx, neighbor.addr.network_id, &neighbor.addr.addrbytes, neighbor.addr.port)?;
        if present.is_some() {
            // already here 
            PeerDB::update_peer(tx, neighbor)?;
            return Ok(false);
        }

        let slots = PeerDB::peer_slots(tx, neighbor.addr.network_id, &neighbor.addr.addrbytes, neighbor.addr.port)?;
        for slot in &slots {
            let peer_opt = PeerDB::get_peer_at(tx, neighbor.addr.network_id, *slot)?;
            if peer_opt.is_none() {
                // have a spare slot!
                PeerDB::insert_or_replace_peer(tx, neighbor, *slot)?;
                return Ok(true);
            }
        }

        // no slots free 
        return Ok(false);
    }

    /// Get random neighbors, optionally always including whitelisted neighbors
    pub fn get_random_neighbors(conn: &DBConn, network_id: u32, count: u32, block_height: u64, always_include_whitelisted: bool) -> Result<Vec<Neighbor>, db_error> {
        if block_height > ((1 as u64) << 63) - 1 {
            return Err(db_error::Overflow);
        }

        let mut ret = vec![];

        // UTC time 
        let now_secs = util::get_epoch_time_secs();
        if now_secs > ((1 as u64) << 63) - 1 {
            return Err(db_error::Overflow);
        }

        let neighbor_row_order = Neighbor::row_order().join(",");

        if always_include_whitelisted {
            // always include whitelisted neighbors, freshness be damned
            let whitelist_qry = format!("SELECT {} FROM frontier WHERE network_id = ?1 AND blacklisted < ?2 AND (whitelisted < 0 OR ?3 < whitelisted)", neighbor_row_order);
            let whitelist_args = [&network_id as &ToSql, &(now_secs as i64) as &ToSql, &(now_secs as i64) as &ToSql];
            let mut whitelist_rows = query_rows::<Neighbor, _>(conn, &whitelist_qry.to_string(), &whitelist_args)?;

            if whitelist_rows.len() >= (count as usize) {
                // return a random subset 
                let whitelist_slice = whitelist_rows.as_mut_slice();
                whitelist_slice.shuffle(&mut thread_rng());
                return Ok(whitelist_slice[0..(count as usize)].to_vec());
            }

            ret.append(&mut whitelist_rows);
        }

        // fill in with non-whitelisted, randomly-chosen, fresh peers 
        let random_peers_qry = 
            if always_include_whitelisted {
                format!("SELECT {} FROM frontier WHERE network_id = ?1 AND last_contact_time >= 0 AND ?2 < expire_block_height AND blacklisted < ?3 AND \
                        (whitelisted >= 0 AND whitelisted <= $4) ORDER BY RANDOM() LIMIT ?5", neighbor_row_order)
            }
            else {
                format!("SELECT {} FROM frontier WHERE network_id = ?1 AND last_contact_time >= 0 AND ?2 < expire_block_height AND blacklisted < ?3 AND \
                        (whitelisted < 0 OR (whitelisted >= 0 AND whitelisted <= $4)) ORDER BY RANDOM() LIMIT ?5", neighbor_row_order)
            };

        let random_peers_args = [&network_id as &ToSql, &(block_height as i64) as &ToSql, &(now_secs as i64) as &ToSql, &(now_secs as i64) as &ToSql, &(count - (ret.len() as u32)) as &ToSql];
        let mut random_peers = query_rows::<Neighbor, _>(conn, &random_peers_qry.to_string(), &random_peers_args)?;

        ret.append(&mut random_peers);
        Ok(ret)
    }

    /// Get an randomized initial set of peers.
    /// -- always include all whitelisted neighbors
    /// -- never include blacklisted neighbors
    /// -- for neighbors that are neither whitelisted nor blacklisted, sample them randomly as long as they're fresh.
    pub fn get_initial_neighbors(conn: &DBConn, network_id: u32, count: u32, block_height: u64) -> Result<Vec<Neighbor>, db_error> {
        PeerDB::get_random_neighbors(conn, network_id, count, block_height, true)
    }

    /// Get a randomized set of peers for walking the peer graph.
    /// -- selects peers at random even if not whitelisted 
    pub fn get_random_walk_neighbors(conn: &DBConn, network_id: u32, count: u32, block_height: u64) -> Result<Vec<Neighbor>, db_error> {
        PeerDB::get_random_neighbors(conn, network_id, count, block_height, false)
    }
    
    /// Add an IPv4 <--> ASN mapping 
    /// Used during db instantiation
    fn asn4_insert<'a>(tx: &mut Transaction<'a>, asn4: &ASEntry4) -> Result<(), db_error> {
        tx.execute("INSERT OR REPLACE INTO asn4 (prefix, mask, asn, org) VALUES (?1, ?2, ?3, ?4)",
                  &[&asn4.prefix as &ToSql, &asn4.mask as &ToSql, &asn4.asn as &ToSql, &asn4.org as &ToSql])
            .map_err(db_error::SqliteError)?;

        Ok(())
    }

    /// Classify an IPv4 address to its AS number.
    /// This method doesn't have to be particularly efficient since it's off the critical path.
    pub fn asn4_lookup(conn: &DBConn, addrbits: &PeerAddress) -> Result<Option<u32>, db_error> {
        // must be an IPv4 address 
        if !addrbits.is_ipv4() {
            return Err(db_error::TypeError);
        }
       
        // NOTE: sqlite3 will use the machine's endianness here
        let addr_u32 = addrbits.ipv4_bits().unwrap();
        
        let qry = "SELECT * FROM asn4 WHERE prefix = (?1 & ~((1 << (32 - mask)) - 1)) ORDER BY prefix DESC LIMIT 1".to_string();
        let args = [&addr_u32 as &ToSql];
        let rows = query_rows::<ASEntry4, _>(conn, &qry.to_string(), &args)?;
        match rows.len() {
            0 => Ok(None),
            _ => Ok(Some(rows[0].asn))
        }
    }

    /// Classify an IP address to its AS number
    pub fn asn_lookup(conn: &DBConn, addrbits: &PeerAddress) -> Result<Option<u32>, db_error> {
        if addrbits.is_ipv4() {
            PeerDB::asn4_lookup(conn, addrbits)
        }
        else {
            // TODO
            Ok(None)
        }
    }

    /// Count the number of nodes in a given AS
    pub fn asn_count(conn: &DBConn, asn: u32) -> Result<u64, db_error> {
        let qry = "SELECT COUNT(*) FROM frontier WHERE asn = ?1";
        let args = [&asn as &ToSql];
        let count = query_count(conn, &qry.to_string(), &args)?;
        Ok(count as u64)
    }
    
    pub fn get_frontier_size(conn: &DBConn) -> Result<u64, db_error> {
        let qry = "SELECT COUNT(*) FROM frontier";
        let count = query_count(conn, &qry.to_string(), NO_PARAMS)?;
        Ok(count as u64)
    }

    /// used only in testing 
    #[cfg(test)]
    pub fn get_all_peers(conn: &DBConn) -> Result<Vec<Neighbor>, db_error> {
        let row_order = Neighbor::row_order().join(",");
        let qry = format!("SELECT {} FROM frontier ORDER BY addrbytes ASC, port ASC", row_order);
        let rows = query_rows::<Neighbor, _>(conn, &qry.to_string(), NO_PARAMS)?;
        Ok(rows)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use net::Neighbor;
    use net::NeighborKey;
    use net::PeerAddress;

    #[test]
    fn test_peer_insert_and_retrieval() {
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
            in_degree: 1,
            out_degree: 1
        };
        
        let mut db = PeerDB::connect_memory(0x9abcdef0, 12345, &vec![], &vec![]).unwrap();
        
        let neighbor_before_opt = PeerDB::get_peer(db.conn(), 0x9abcdef0, &PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]), 12345).unwrap();
        assert_eq!(neighbor_before_opt, None);

        {
            let mut tx = db.tx_begin().unwrap();
            PeerDB::insert_or_replace_peer(&mut tx, &neighbor, 0).unwrap();
            tx.commit().unwrap();
        }

        let neighbor_opt = PeerDB::get_peer(db.conn(), 0x9abcdef0, &PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]), 12345).unwrap();
        assert_eq!(neighbor_opt, Some(neighbor.clone()));

        let neighbor_at_opt = PeerDB::get_peer_at(db.conn(), 0x9abcdef0, 0).unwrap();
        assert_eq!(neighbor_at_opt, Some(neighbor.clone()));

        let neighbor_not_at_opt = PeerDB::get_peer_at(db.conn(), 0x9abcdef0, 1).unwrap();
        assert_eq!(neighbor_not_at_opt, None);
        
        let neighbor_not_at_opt_network = PeerDB::get_peer_at(db.conn(), 0x9abcdef1, 0).unwrap();
        assert_eq!(neighbor_not_at_opt_network, None);

        {
            let mut tx = db.tx_begin().unwrap();
            PeerDB::insert_or_replace_peer(&mut tx, &neighbor, 0).unwrap();
            tx.commit().unwrap();
        }
    }

    #[test]
    fn test_try_insert_peer() {
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
            in_degree: 1,
            out_degree: 1
        };

        let mut db = PeerDB::connect_memory(0x9abcdef0, 12345, &vec![], &vec![]).unwrap();
        
        {
            let mut tx = db.tx_begin().unwrap();
            let res = PeerDB::try_insert_peer(&mut tx, &neighbor).unwrap();
            tx.commit().unwrap();

            assert_eq!(res, true);
        }
        
        let neighbor_opt = PeerDB::get_peer(db.conn(), 0x9abcdef0, &PeerAddress([0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]), 12345).unwrap();
        assert_eq!(neighbor_opt, Some(neighbor.clone()));

        {
            let mut tx = db.tx_begin().unwrap();
            let res = PeerDB::try_insert_peer(&mut tx, &neighbor).unwrap();
            tx.commit().unwrap();

            assert_eq!(res, false);
        }
    }

    #[test]
    fn test_initial_neighbors() {
        let mut initial_neighbors = vec![];
        let now_secs = util::get_epoch_time_secs();
        for i in 0..10 {
            initial_neighbors.push(Neighbor {
                addr: NeighborKey {
                    peer_version: 0x12345678,
                    network_id: 0x9abcdef0,
                    addrbytes: PeerAddress([i as u8; 16]),
                    port: i,
                },
                public_key: Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::new()),
                expire_block: (i + 23456) as u64,
                last_contact_time: (1552509642 + (i as u64)) as u64,
                whitelisted: (now_secs + 600) as i64,
                blacklisted: -1,
                asn: (34567 + i) as u32,
                org: (45678 + i) as u32,
                in_degree: 1,
                out_degree: 1
            });
        }

        for i in 10..20 {
            initial_neighbors.push(Neighbor {
                addr: NeighborKey {
                    peer_version: 0x12345678,
                    network_id: 0x9abcdef0,
                    addrbytes: PeerAddress([i as u8; 16]),
                    port: i,
                },
                public_key: Secp256k1PublicKey::from_private(&Secp256k1PrivateKey::new()),
                expire_block: (i + 23456) as u64,
                last_contact_time: (1552509642 + (i as u64)) as u64,
                whitelisted: 0,
                blacklisted: -1,
                asn: (34567 + i) as u32,
                org: (45678 + i) as u32,
                in_degree: 1,
                out_degree: 1
            });
        }

        fn are_present(ne: &Vec<Neighbor>, nei: &Vec<Neighbor>) -> bool {
            for n in ne {
                let mut found = false;
                for ni in nei {
                    if *n == *ni {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return false;
                }
            }
            return true;
        }
        
        let db = PeerDB::connect_memory(0x9abcdef0, 12345, &vec![], &initial_neighbors).unwrap();

        let n5 = PeerDB::get_initial_neighbors(db.conn(), 0x9abcdef0, 5, 23455).unwrap();
        assert!(are_present(&n5, &initial_neighbors));

        let n10 = PeerDB::get_initial_neighbors(db.conn(), 0x9abcdef0, 10, 23455).unwrap();
        assert!(are_present(&n10, &initial_neighbors));

        let n20 = PeerDB::get_initial_neighbors(db.conn(), 0x9abcdef0, 20, 23455).unwrap();
        assert!(are_present(&initial_neighbors, &n20));

        let n15_fresh = PeerDB::get_initial_neighbors(db.conn(), 0x9abcdef0, 15, 23456 + 14).unwrap();
        assert!(are_present(&n15_fresh[10..15].to_vec(), &initial_neighbors[10..20].to_vec()));
        for n in &n15_fresh[10..15] {
            assert!(n.expire_block > 23456 + 14);
            assert!(n.whitelisted == 0);
        }
    }

    #[test]
    fn asn4_insert_lookup() {
        let asn4_table = vec![
            ASEntry4 {
                prefix: 0x01020200,
                mask: 24,
                asn: 1,
                org: 0,
            },
            ASEntry4 {
                prefix: 0x01020200,
                mask: 23,
                asn: 2,
                org: 0,
            },
            ASEntry4 {
                prefix: 0x01020000,
                mask: 16,
                asn: 3,
                org: 0
            },
            ASEntry4 {
                prefix: 0x02030000,
                mask: 16,
                asn: 4,
                org: 0
            },
        ];

        let db = PeerDB::connect_memory(0x9abcdef0, 12345, &asn4_table, &vec![]).unwrap();
    
        let asn1_addr = PeerAddress([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x01,0x02,0x02,0x04]);
        let asn2_addr = PeerAddress([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x01,0x02,0x03,0x10]);
        let asn3_addr = PeerAddress([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x01,0x02,0x13,0x10]);
        let asn4_addr = PeerAddress([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x02,0x03,0x13,0x10]);

        // classify addresses 
        let asn1_opt = PeerDB::asn4_lookup(db.conn(), &asn1_addr).unwrap();
        assert_eq!(asn1_opt, Some(1));

        let asn2_opt = PeerDB::asn4_lookup(db.conn(), &asn2_addr).unwrap();
        assert_eq!(asn2_opt, Some(2));

        let asn3_opt = PeerDB::asn4_lookup(db.conn(), &asn3_addr).unwrap();
        assert_eq!(asn3_opt, Some(3));

        let asn4_opt = PeerDB::asn4_lookup(db.conn(), &asn4_addr).unwrap();
        assert_eq!(asn4_opt, Some(4));

        // invalid -- not an ipv4 address
        let asn4_invalid_addr = PeerAddress([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0xff,0xff,0x02,0x03,0x13,0x10]);
        let asn_invalid_opt = PeerDB::asn4_lookup(db.conn(), &asn4_invalid_addr);
        match asn_invalid_opt {
            Ok(_) => assert!(false),
            Err(db_error::TypeError) => assert!(true),
            Err(_) => assert!(false)
        }

        // not present
        let asn4_missing_addr = PeerAddress([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x02,0x04,0x13,0x10]);
        let asn_missing_opt = PeerDB::asn4_lookup(db.conn(), &asn4_missing_addr).unwrap();
        assert_eq!(asn_missing_opt, None);
    }
}
