// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
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

use std::{fs, path::PathBuf};

use rusqlite::{OpenFlags, OptionalExtension};

use crate::{
    burnchains::Txid,
    core::MemPoolDB,
    net::{Error as net_error, HttpRequestType},
    util::{
        db::{tx_busy_handler, DBConn},
        get_epoch_time_secs,
    },
};
use util::db::Error as DatabaseError;

#[cfg(feature = "monitoring_prom")]
mod prometheus;

pub fn increment_rpc_calls_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::RPC_CALL_COUNTER.inc();
}

pub fn instrument_http_request_handler<F, R>(
    req: HttpRequestType,
    handler: F,
) -> Result<R, net_error>
where
    F: FnOnce(HttpRequestType) -> Result<R, net_error>,
{
    #[cfg(feature = "monitoring_prom")]
    increment_rpc_calls_counter();

    #[cfg(feature = "monitoring_prom")]
    let timer = prometheus::new_rpc_call_timer(req.get_path());

    let res = handler(req);

    #[cfg(feature = "monitoring_prom")]
    timer.stop_and_record();

    res
}

pub fn increment_stx_blocks_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_RECEIVED_COUNTER.inc();
}

pub fn increment_stx_micro_blocks_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_MICRO_BLOCKS_RECEIVED_COUNTER.inc();
}

pub fn increment_stx_blocks_served_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_SERVED_COUNTER.inc();
}

pub fn increment_stx_micro_blocks_served_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_MICRO_BLOCKS_SERVED_COUNTER.inc();
}

pub fn increment_stx_confirmed_micro_blocks_served_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_CONFIRMED_MICRO_BLOCKS_SERVED_COUNTER.inc();
}

pub fn increment_txs_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::TXS_RECEIVED_COUNTER.inc();
}

pub fn increment_btc_blocks_received_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BTC_BLOCKS_RECEIVED_COUNTER.inc();
}

pub fn increment_btc_ops_sent_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BTC_OPS_SENT_COUNTER.inc();
}

pub fn increment_stx_blocks_processed_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_PROCESSED_COUNTER.inc();
}

pub fn increment_stx_blocks_mined_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_BLOCKS_MINED_COUNTER.inc();
}

pub fn increment_warning_emitted_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::WARNING_EMITTED_COUNTER.inc();
}

pub fn increment_errors_emitted_counter() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::ERRORS_EMITTED_COUNTER.inc();
}

fn txid_tracking_db(chainstate_root_path: &str) -> Result<DBConn, DatabaseError> {
    let mut path = PathBuf::from(chainstate_root_path);

    path.push("tx_tracking.sqlite");
    let db_path = path.to_str().ok_or_else(|| DatabaseError::ParseError)?;

    let mut create_flag = false;
    let open_flags = if fs::metadata(&db_path).is_err() {
        // need to create
        create_flag = true;
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        // can just open
        OpenFlags::SQLITE_OPEN_READ_WRITE
    };

    let conn = DBConn::open_with_flags(&db_path, open_flags)?;

    conn.busy_handler(Some(tx_busy_handler))?;

    if create_flag {
        conn.execute(
            "CREATE TABLE processed_txids (txid TEXT NOT NULL PRIMARY KEY)",
            rusqlite::NO_PARAMS,
        )?;
    }

    Ok(conn)
}

fn txid_tracking_db_contains(conn: &DBConn, txid: &Txid) -> Result<bool, DatabaseError> {
    let contains = conn
        .query_row(
            "SELECT 1 FROM processed_txids WHERE txid = ?",
            &[txid],
            |_row| Ok(true),
        )
        .optional()?
        .is_some();
    Ok(contains)
}

#[allow(unused_variables)]
pub fn mempool_accepted(txid: &Txid, chainstate_root_path: &str) -> Result<(), DatabaseError> {
    #[cfg(feature = "monitoring_prom")]
    {
        let tracking_db = txid_tracking_db(chainstate_root_path)?;

        if txid_tracking_db_contains(&tracking_db, txid)? {
            // processed by a previous block, do not track again
            return Ok(());
        }

        prometheus::MEMPOOL_OUTSTANDING_TXS.inc();
    }

    Ok(())
}

#[allow(unused_variables)]
pub fn log_transaction_processed(
    txid: &Txid,
    chainstate_root_path: &str,
) -> Result<(), DatabaseError> {
    #[cfg(feature = "monitoring_prom")]
    {
        let mempool_db_path = MemPoolDB::db_path(chainstate_root_path)?;
        let mempool_conn =
            DBConn::open_with_flags(&mempool_db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let tracking_db = txid_tracking_db(chainstate_root_path)?;

        let tx = match MemPoolDB::get_tx(&mempool_conn, txid)? {
            Some(tx) => tx,
            None => {
                debug!("Could not log transaction receive to process time, txid not found in mempool"; "txid" => %txid);
                return Ok(());
            }
        };

        if txid_tracking_db_contains(&tracking_db, txid)? {
            // processed by a previous block, do not track again
            return Ok(());
        }

        let mempool_accept_time = tx.metadata.accept_time;
        let time_now = get_epoch_time_secs();

        let time_to_process = time_now - mempool_accept_time;

        prometheus::MEMPOOL_OUTSTANDING_TXS.dec();
        prometheus::MEMPOOL_TX_CONFIRM_TIME.observe(time_to_process as f64);
    }
    Ok(())
}

#[allow(unused_variables)]
pub fn update_active_miners_count_gauge(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::ACTIVE_MINERS_COUNT_GAUGE.set(value);
}

#[allow(unused_variables)]
pub fn update_stacks_tip_height(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STACKS_TIP_HEIGHT_GAUGE.set(value);
}

#[allow(unused_variables)]
pub fn update_burnchain_height(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::BURNCHAIN_HEIGHT_GAUGE.set(value);
}

#[allow(unused_variables)]
pub fn update_inbound_neighbors(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_NEIGHBORS_GAUGE.set(value);
}

#[allow(unused_variables)]
pub fn update_outbound_neighbors(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OUTBOUND_NEIGHBORS_GAUGE.set(value);
}

#[allow(unused_variables)]
pub fn update_inbound_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_BANDWIDTH_GAUGE.add(value);
}

#[allow(unused_variables)]
pub fn update_outbound_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OUTBOUND_BANDWIDTH_GAUGE.add(value);
}

#[allow(unused_variables)]
pub fn update_inbound_rpc_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::INBOUND_RPC_BANDWIDTH_GAUGE.add(value);
}

#[allow(unused_variables)]
pub fn update_outbound_rpc_bandwidth(value: i64) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::OUTBOUND_RPC_BANDWIDTH_GAUGE.add(value);
}

#[allow(unused_variables)]
pub fn increment_msg_counter(name: String) {
    #[cfg(feature = "monitoring_prom")]
    prometheus::MSG_COUNTER_VEC
        .with_label_values(&[&name])
        .inc();
}

pub fn increment_stx_mempool_gc() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::STX_MEMPOOL_GC.inc();
}

pub fn increment_contract_calls_processed() {
    #[cfg(feature = "monitoring_prom")]
    prometheus::CONTRACT_CALLS_PROCESSED_COUNT.inc();
}
