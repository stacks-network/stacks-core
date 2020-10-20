use rusqlite::types::ToSql;
use rusqlite::Row;
use rusqlite::Transaction;
use rusqlite::{Connection, OpenFlags, NO_PARAMS};

use std::convert::From;
use std::convert::TryFrom;
use std::fs;

use util::db::tx_begin_immediate;
use util::db::DBConn;
use util::db::Error as db_error;
use util::db::{query_count, query_row, query_rows, u64_to_sql, FromColumn, FromRow};

use util;
use util::hash::{bin_bytes, hex_bytes, to_bin, to_hex, Hash160};
use util::log;
use util::macros::is_big_endian;
use util::secp256k1::Secp256k1PrivateKey;
use util::secp256k1::Secp256k1PublicKey;

use super::inv::ZonefileHash;
use super::Attachment;

pub const ATLASDB_VERSION: &'static str = "23.0.0.0";

const ATLASDB_SETUP: &'static [&'static str] = &[
    r#"
    CREATE TABLE attachments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        content TEXT NOT NULL,
        txid STRING UNIQUE NOT NULL,
        stacks_block_id INTEGER NOT NULL,
        inv_index INTEGER NOT NULL,
        present INTEGER NOT NULL,
        tried_storage TEXT NOT NULL,
        block_height INTEGER NOT NULL
    );"#,
    r#"
    CREATE TABLE unprocessed_attachments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        content TEXT NOT NULL
    );"#, // todo(ludo): should content be a BLOB instead? 
    r#"
    CREATE TABLE records(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at INTEGER NOT NULL,
        zonefile_id INTEGER NOT NULL,
        name STRING NOT NULL
    );"#,
    r#"
    CREATE TABLE db_version(version TEXT NOT NULL);
    "#
];

#[derive(Debug)]
pub struct AtlasDB {
    pub conn: Connection,
    pub readwrite: bool,
}

impl AtlasDB {
    fn instantiate(&mut self) -> Result<(), db_error> {
        let tx = self.tx_begin()?;

        for row_text in ATLASDB_SETUP {
            tx.execute(row_text, NO_PARAMS)
                .map_err(db_error::SqliteError)?;
        }

        tx.execute(
            "INSERT INTO db_version (version) VALUES (?1)",
            &[&ATLASDB_VERSION],
        )
        .map_err(db_error::SqliteError)?;

        tx.commit().map_err(db_error::SqliteError)?;

        Ok(())
    }

    // todo(ludo): parse error: Invalid numeric literal at line 1, column 7

    // Open the burn database at the given path.  Open read-only or read/write.
    // If opened for read/write and it doesn't exist, instantiate it.
    pub fn connect(
        path: &String,
        readwrite: bool,
    ) -> Result<AtlasDB, db_error> {
        let mut create_flag = false;
        let open_flags = if fs::metadata(path).is_err() {
            // need to create
            if readwrite {
                create_flag = true;
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                return Err(db_error::NoDBError);
            }
        } else {
            // can just open
            if readwrite {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            }
        };
        let conn =
            Connection::open_with_flags(path, open_flags).map_err(|e| db_error::SqliteError(e))?;

        let mut db = AtlasDB {
            conn: conn,
            readwrite: readwrite,
        };
        if create_flag {
            db.instantiate()?;
        }
        Ok(db)
    }

    // Open a burn database in memory (used for testing)
    #[cfg(test)]
    pub fn connect_memory() -> Result<AtlasDB, db_error> {
        let conn = Connection::open_in_memory().map_err(|e| db_error::SqliteError(e))?;

        let mut db = AtlasDB {
            conn: conn,
            readwrite: true,
        };

        db.instantiate()?;
        Ok(db)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn tx_begin<'a>(&'a mut self) -> Result<Transaction<'a>, db_error> {
        if !self.readwrite {
            return Err(db_error::ReadOnly);
        }

        let tx = tx_begin_immediate(&mut self.conn)?;
        Ok(tx)
    }

    // Read the local peer record
    fn get_zonefiles_hashes_in_range_desc(&self, min: u32, max: u32) -> Result<Vec<ZonefileHash>, db_error> { // todo(ludo): can't fork, won't work
        let qry = "SELECT inv_index, content_hash FROM attachments WHERE inv_index >= ?1 AND inv_index < ?2 ORDER BY inv_index DESC".to_string();
        let args = [&min as &dyn ToSql, &max as &dyn ToSql];
        let rows = query_rows::<ZonefileHash, _>(&self.conn, &qry, &args)?;
        Ok(rows)
    }

    pub fn get_processed_zonefiles_hashes_at_page(&self, min: u32, max: u32) -> (Vec<Option<ZonefileHash>>, Vec<u32>) {
        let mut missing_indexes = vec![];
        let mut downloaded_zonefiles = match self.get_zonefiles_hashes_in_range_desc(min, max) {
            Ok(zonefiles) => zonefiles,
            Err(e) => {
                println!("{:?}", e);
                panic!() // todo(ludo)
            }
        };

        let mut zonefiles_hashes = vec![];        
        for cursor in min..max {
            let entry = match downloaded_zonefiles.len() {
                0 => None,
                len => match downloaded_zonefiles[len - 1].zonefile_id {
                    index if index == cursor => downloaded_zonefiles.pop(),
                    _ => None,
                }
            };
            if entry.is_none() {
                missing_indexes.push(cursor);
            }

            zonefiles_hashes.push(entry);
        }

        (zonefiles_hashes, missing_indexes)
    }

    pub fn insert_unprocessed_attachment(&mut self, attachment: Attachment) -> Result<(), db_error> {

        // Check hash + content

        // Do we already have an entry (proceessed or unprocessed) for this attachment? - todo(ludo) think more about this
        let qry = "SELECT count(*) FROM unprocessed_attachments WHERE content_hash = ?1".to_string();
        let args = [&attachment.content_hash as &dyn ToSql];
        let count = query_count(&self.conn, &qry, &args)?;
        if count != 0 {
            // todo(ludo): early return
            return Ok(())
        }

        let tx = self.tx_begin()?;

        let now = util::get_epoch_time_secs() as i64;

        let res = tx.execute(
            "INSERT INTO unprocessed_attachments (content_hash, content, created_at) VALUES (?1, ?2, ?3)",
            &[
                &attachment.content_hash as &dyn ToSql, 
                &attachment.content as &dyn ToSql,
                &now as &dyn ToSql
            ]
        );

        res.map_err(db_error::SqliteError)?;

        tx.commit().map_err(db_error::SqliteError)?;

        Ok(())
    }


    // Set the local IP address and port
    // pub fn set_local_ipaddr<'a>(
    //     tx: &mut Transaction<'a>,
    //     addrbytes: &PeerAddress,
    //     port: u16,
    // ) -> Result<(), db_error> {
    //     tx.execute(
    //         "UPDATE local_peer SET addrbytes = ?1, port = ?2",
    //         &[&to_bin(&addrbytes.as_bytes().to_vec()), &port as &dyn ToSql],
    //     )
    //     .map_err(db_error::SqliteError)?;

    //     Ok(())
    // }

    // Get peer by port (used in tests where the IP address doesn't really matter)
    // #[cfg(test)]
    // pub fn get_peer_by_port(
    //     conn: &DBConn,
    //     network_id: u32,
    //     peer_port: u16,
    // ) -> Result<Option<Neighbor>, db_error> {
    //     let qry = "SELECT * FROM frontier WHERE network_id = ?1 AND port = ?2".to_string();
    //     let args = [&network_id as &dyn ToSql, &peer_port as &dyn ToSql];
    //     query_row::<Neighbor, _>(conn, &qry, &args)
    // }

    // Get a peer record at a particular slot
    // pub fn get_peer_at(
    //     conn: &DBConn,
    //     network_id: u32,
    //     slot: u32,
    // ) -> Result<Option<Neighbor>, db_error> {
    //     let qry = "SELECT * FROM frontier WHERE network_id = ?1 AND slot = ?2".to_string();
    //     let args = [&network_id as &dyn ToSql, &slot as &dyn ToSql];
    //     query_row::<Neighbor, _>(conn, &qry, &args)
    // }

    // Insert or replace a neighbor into a given slot
    // pub fn insert_or_replace_peer<'a>(
    //     tx: &mut Transaction<'a>,
    //     neighbor: &Neighbor,
    //     slot: u32,
    // ) -> Result<(), db_error> {
    //     let neighbor_args: &[&dyn ToSql] = &[
    //         &neighbor.addr.peer_version,
    //         &neighbor.addr.network_id,
    //         &to_bin(neighbor.addr.addrbytes.as_bytes()),
    //         &neighbor.addr.port,
    //         &to_hex(&neighbor.public_key.to_bytes_compressed()),
    //         &u64_to_sql(neighbor.expire_block)?,
    //         &u64_to_sql(neighbor.last_contact_time)?,
    //         &neighbor.asn,
    //         &neighbor.org,
    //         &neighbor.allowed,
    //         &neighbor.denied,
    //         &neighbor.in_degree,
    //         &neighbor.out_degree,
    //         &0i64,
    //         &slot,
    //     ];

    //     tx.execute("INSERT OR REPLACE INTO frontier (peer_version, network_id, addrbytes, port, public_key, expire_block_height, last_contact_time, asn, org, allowed, denied, in_degree, out_degree, initial, slot) \
    //                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)", neighbor_args)
    //         .map_err(db_error::SqliteError)?;

    //     Ok(())
    // }

    // Remove a peer from the peer database
    // pub fn drop_peer<'a>(
    //     tx: &mut Transaction<'a>,
    //     network_id: u32,
    //     peer_addr: &PeerAddress,
    //     peer_port: u16,
    // ) -> Result<(), db_error> {
    //     tx.execute(
    //         "DELETE FROM frontier WHERE network_id = ?1 AND addrbytes = ?2 AND port = ?3",
    //         &[
    //             &network_id as &dyn ToSql,
    //             &peer_addr.to_bin() as &dyn ToSql,
    //             &peer_port as &dyn ToSql,
    //         ],
    //     )
    //     .map_err(db_error::SqliteError)?;

    //     Ok(())
    // }

    // // Is a peer one of this node's initial neighbors?
    // pub fn is_initial_peer(
    //     conn: &DBConn,
    //     network_id: u32,
    //     peer_addr: &PeerAddress,
    //     peer_port: u16,
    // ) -> Result<bool, db_error> {
    //     let res: Option<i64> = query_row(
    //         conn,
    //         "SELECT initial FROM frontier WHERE network_id = ?1 AND addrbytes = ?2 AND port = ?3",
    //         &[&network_id as &dyn ToSql, &peer_addr.to_bin(), &peer_port],
    //     )?;

    //     match res {
    //         Some(x) => Ok(x != 0),
    //         None => Ok(false),
    //     }
    // }

    // // Set a peer as an initial peer
    // fn set_initial_peer<'a>(
    //     tx: &mut Transaction<'a>,
    //     network_id: u32,
    //     peer_addr: &PeerAddress,
    //     peer_port: u16,
    // ) -> Result<(), db_error> {
    //     tx.execute("UPDATE frontier SET initial = 1 WHERE network_id = ?1 AND addrbytes = ?2 AND port = ?3", 
    //                 &[&network_id as &dyn ToSql, &peer_addr.to_bin(), &peer_port])
    //         .map_err(db_error::SqliteError)?;

    //     Ok(())
    // }

    // // clear all initial peers
    // fn clear_initial_peers<'a>(tx: &mut Transaction<'a>) -> Result<(), db_error> {
    //     tx.execute("UPDATE frontier SET initial = 0", NO_PARAMS)
    //         .map_err(db_error::SqliteError)?;

    //     Ok(())
    // }

    // // Set/unset allow flag for a peer
    // // Pass -1 for "always"
    // pub fn set_allow_peer<'a>(
    //     tx: &mut Transaction<'a>,
    //     network_id: u32,
    //     peer_addr: &PeerAddress,
    //     peer_port: u16,
    //     allow_deadline: i64,
    // ) -> Result<(), db_error> {
    //     let num_updated = tx.execute("UPDATE frontier SET allowed = ?1 WHERE network_id = ?2 AND addrbytes = ?3 AND port = ?4",
    //                &[&allow_deadline as &dyn ToSql, &network_id, &peer_addr.to_bin(), &peer_port])
    //         .map_err(db_error::SqliteError)?;

    //     if num_updated == 0 {
    //         // we're preemptively allowing
    //         let nk = NeighborKey {
    //             peer_version: 0,
    //             network_id: network_id,
    //             addrbytes: peer_addr.clone(),
    //             port: peer_port,
    //         };
    //         let empty_key = StacksPublicKey::from_private(&StacksPrivateKey::new());
    //         let mut empty_neighbor = Neighbor::empty(&nk, &empty_key, 0);

    //         empty_neighbor.allowed = allow_deadline as i64;

    //         debug!("Preemptively allow peer {:?}", &nk);
    //         if !PeerDB::try_insert_peer(tx, &empty_neighbor)? {
    //             let mut slots = PeerDB::peer_slots(tx, network_id, peer_addr, peer_port)?;
    //             let slot = slots.pop().expect("BUG: no slots");
    //             warn!(
    //                 "Forcing replacement of peer at slot {} for allowed peer {:?}",
    //                 slot, &empty_neighbor.addr
    //             );
    //             PeerDB::insert_or_replace_peer(tx, &empty_neighbor, slot)?;
    //         }
    //     }

    //     Ok(())
    // }

    // Set/unset deny flag for a peer
    // negative values aren't allowed
    // pub fn set_deny_peer<'a>(
    //     tx: &mut Transaction<'a>,
    //     network_id: u32,
    //     peer_addr: &PeerAddress,
    //     peer_port: u16,
    //     deny_deadline: u64,
    // ) -> Result<(), db_error> {
    //     let args: &[&dyn ToSql] = &[
    //         &u64_to_sql(deny_deadline)?,
    //         &network_id,
    //         &peer_addr.to_bin(),
    //         &peer_port,
    //     ];
    //     let num_updated = tx.execute("UPDATE frontier SET denied = ?1 WHERE network_id = ?2 AND addrbytes = ?3 AND port = ?4", args)
    //         .map_err(db_error::SqliteError)?;

    //     if num_updated == 0 {
    //         // we're preemptively denying
    //         let nk = NeighborKey {
    //             peer_version: 0,
    //             network_id: network_id,
    //             addrbytes: peer_addr.clone(),
    //             port: peer_port,
    //         };
    //         let empty_key = StacksPublicKey::from_private(&StacksPrivateKey::new());
    //         let mut empty_neighbor = Neighbor::empty(&nk, &empty_key, 0);

    //         empty_neighbor.denied = deny_deadline as i64;

    //         debug!("Preemptively deny peer {:?}", &nk);
    //         if !PeerDB::try_insert_peer(tx, &empty_neighbor)? {
    //             let mut slots = PeerDB::peer_slots(tx, network_id, peer_addr, peer_port)?;
    //             let slot = slots.pop().expect("BUG: no slots");
    //             warn!(
    //                 "Forcing replacement of peer at slot {} for denied peer {:?}",
    //                 slot, &empty_neighbor.addr
    //             );
    //             PeerDB::insert_or_replace_peer(tx, &empty_neighbor, slot)?;
    //         }
    //     }

    //     Ok(())
    // }

    // Update an existing peer's entries.  Does nothing if the peer is not present.
    // pub fn update_peer<'a>(tx: &mut Transaction<'a>, neighbor: &Neighbor) -> Result<(), db_error> {
    //     let args: &[&dyn ToSql] = &[
    //         &neighbor.addr.peer_version,
    //         &to_hex(&neighbor.public_key.to_bytes_compressed()),
    //         &u64_to_sql(neighbor.expire_block)?,
    //         &u64_to_sql(neighbor.last_contact_time)?,
    //         &neighbor.asn,
    //         &neighbor.org,
    //         &neighbor.allowed,
    //         &neighbor.denied,
    //         &neighbor.in_degree,
    //         &neighbor.out_degree,
    //         &neighbor.addr.network_id,
    //         &to_bin(neighbor.addr.addrbytes.as_bytes()),
    //         &neighbor.addr.port,
    //     ];

    //     tx.execute("UPDATE frontier SET peer_version = ?1, public_key = ?2, expire_block_height = ?3, last_contact_time = ?4, asn = ?5, org = ?6, allowed = ?7, denied = ?8, in_degree = ?9, out_degree = ?10 \
    //                 WHERE network_id = ?11 AND addrbytes = ?12 AND port = ?13", args)
    //         .map_err(db_error::SqliteError)?;

    //     Ok(())
    // }

    // Try to insert a peer at one of its slots.
    // Does not insert the peer if it is already present, but will instead try to update it with
    // this peer's information.
    // If at least one slot was empty, or if the peer is already present and can be updated, then insert/update the peer and return true.
    // If all slots are occupied, return false.
    // pub fn try_insert_peer<'a>(
    //     tx: &mut Transaction<'a>,
    //     neighbor: &Neighbor,
    // ) -> Result<bool, db_error> {
    //     let present = PeerDB::get_peer(
    //         tx,
    //         neighbor.addr.network_id,
    //         &neighbor.addr.addrbytes,
    //         neighbor.addr.port,
    //     )?;
    //     if present.is_some() {
    //         // already here
    //         PeerDB::update_peer(tx, neighbor)?;
    //         return Ok(false);
    //     }

    //     let slots = PeerDB::peer_slots(
    //         tx,
    //         neighbor.addr.network_id,
    //         &neighbor.addr.addrbytes,
    //         neighbor.addr.port,
    //     )?;
    //     for slot in &slots {
    //         let peer_opt = PeerDB::get_peer_at(tx, neighbor.addr.network_id, *slot)?;
    //         if peer_opt.is_none() {
    //             // have a spare slot!
    //             PeerDB::insert_or_replace_peer(tx, neighbor, *slot)?;
    //             return Ok(true);
    //         }
    //     }

    //     // no slots free
    //     return Ok(false);
    // }

}
