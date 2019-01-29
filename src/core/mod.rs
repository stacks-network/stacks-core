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

// This module contains the "main loop" that drives everything
use std::path::PathBuf;
use std::sync::mpsc::sync_channel;
use std::thread;

use chainstate::burn::db::burndb::BurnDB;

use burnchains::bitcoin::indexer::BitcoinIndexer;

use burnchains::bitcoin::Error as btc_error;
use burnchains::bitcoin::address::BitcoinAddress;
use burnchains::bitcoin::keys::BitcoinPublicKey;

use burnchains::indexer::BurnchainIndexer;
use burnchains::Address;
use burnchains::PublicKey;
use burnchains::BurnchainHeaderHash;
use burnchains::BurnchainBlock;
use burnchains::BlockChannel;
use burnchains::indexer::BurnchainBlockDownloader;
use burnchains::indexer::BurnchainBlockParser;
use burnchains::indexer::{BurnHeaderIPC, BurnBlockIPC};

use burnchains::Error as burnchain_error;

use util::Error as util_error;
use util::pipeline::PipelineStage;
use util::pipeline::PipelineProcessor;

/// Check the burn chain for reorgs and identify where we need to start synchronizing from.
/// Returns the block height on success, as well as any new headers' hashes that need to be
/// downloaded.
fn sync_burnchain_reorg<T, H, B, D, P, A, K>(indexer: &mut T, burndb: &mut BurnDB<A, K>) -> Result<(u64, u64), burnchain_error>
where
    A: Address + Send + Sync,
    K: PublicKey + Send + Sync,
    H: Send + Sync,
    B: Send + Sync,
    D: BurnchainBlockDownloader<H, B>,
    P: BurnchainBlockParser<H, B, A, K>,
    T: BurnchainIndexer<H, B, D, P, A, K>,
{
    let headers_path = indexer.get_headers_path();
    let sync_height;
    
    // how far are we in sync'ing the db to?
    let db_height = BurnDB::<A, K>::get_block_height(burndb.conn())
        .map_err(|e| {
            error!("Failed to query block height from burn DB");
            burnchain_error::DBError(e)
        })?;

    // sanity check -- how many headers do we have? 
    let headers_height = indexer.get_headers_height(&headers_path)
        .map_err(|e| {
            error!("Failed to read headers height");
            e
        })?;

    if headers_height < db_height {
        error!("Missing headers -- possibly corrupt database or headers file");
        return Err(burnchain_error::MissingHeaders);
    }

    // how big is the blockchain now?
    let block_height = indexer.get_blockchain_height()
        .map_err(|e| {
            error!("Failed to query blockchain height");
            e
        })?;

    // did we encounter a reorg since last sync?
    let new_height = indexer.find_chain_reorg(&headers_path, db_height)
        .map_err(|e| {
            error!("Failed to check for reorgs between {} and {}", db_height, block_height);
            e
        })?;
    
    if new_height < db_height {
        warn!("Detected burnchain reorg at height {}.  Invalidating affected burn DB transactions and re-sync'ing...", new_height);

        let mut tx = burndb.tx_begin()
            .map_err(|e| {
                error!("Failed to begin burn DB transaction");
                burnchain_error::DBError(e)
            })?;

        BurnDB::<A, K>::burnchain_history_reorg(&mut tx, new_height)
            .map_err(|e| {
                error!("Failed to process burn chain reorg between {} and {}", new_height, db_height);
                burnchain_error::DBError(e)
            })?;

        tx.commit();

        // drop associated headers as well 
        indexer.drop_headers(&headers_path, new_height)?;
        sync_height = new_height;
    }
    else {
        sync_height = db_height;
    }
    Ok((sync_height, block_height))
}

/// synchronize the burn database up to the given block height
fn sync_burnchain<H, B, D, P, A, K, I>(network_name: &String, working_dir: &String, first_block: u64, first_block_hash: &BurnchainHeaderHash) -> Result<u64, burnchain_error>
where
    H: Send + Sync + Clone + 'static,
    B: Send + Sync + Clone + 'static,
    A: Address + Send + Sync + 'static,
    K: PublicKey + Send + Sync + 'static,
    D: BurnchainBlockDownloader<H, B> + Send + Sync + 'static,
    P: BurnchainBlockParser<H, B, A, K> + Send + Sync + 'static,
    I: BurnchainIndexer<H, B, D, P, A, K> + Send + Sync + 'static
{

    let mut db_pathbuf = PathBuf::from(working_dir);
    db_pathbuf.push("burn.db");
    
    let db_path = db_pathbuf.to_str().unwrap().to_string();

    let mut indexer : I = BurnchainIndexer::init(network_name, working_dir)?;
    let mut burndb = BurnDB::<A, K>::connect(&db_path, first_block, first_block_hash, true)
        .map_err(burnchain_error::DBError)?;

    let headers_path = indexer.get_headers_path();
    let db_height = BurnDB::<A, K>::get_block_height(burndb.conn())
        .map_err(|e| {
            error!("Failed to query block height from burn DB");
            burnchain_error::DBError(e)
        })?;

    // handle reorgs
    let (sync_height, end_block) = sync_burnchain_reorg(&mut indexer, &mut burndb)?;

    if db_height >= end_block {
        // all caught up
        return Ok(db_height);
    }

    // get latest headers 
    // TODO: do this atomically -- write to headers_path.new, do the sync, and then merge the files
    // atomically.
    indexer.sync_headers(&headers_path, sync_height, end_block)?;

    // initial inputs 
    let input_headers = indexer.read_headers(&headers_path, sync_height, end_block)?;

    // synchronize 
    let (downloader_send, downloader_recv) = sync_channel(1);
    let (parser_send, parser_recv) = sync_channel(1);
    let (db_send, db_recv) = sync_channel(1);

    let mut downloader = indexer.downloader();
    let mut parser = indexer.parser();

    let download_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
        while true {
            let header : BurnHeaderIPC<H> = downloader_recv.recv()
                .map_err(|_e| burnchain_error::ThreadChannelError)?;

            let block : BurnBlockIPC<H, B> = downloader.download(&header)?;

            parser_send.send(block)
                .map_err(|_e| burnchain_error::ThreadChannelError)?;
        }
        Ok(())
    });

    let parse_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
        while true {
            let block : BurnBlockIPC<H, B> = parser_recv.recv()
                .map_err(|_e| burnchain_error::ThreadChannelError)?;

            let burnchain_block : BurnchainBlock<A, K> = parser.parse(&block)?;

            db_send.send(burnchain_block)
                .map_err(|_e| burnchain_error::ThreadChannelError)?;
        }
        Ok(())
    });

    let db_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
        while true {
            let burnchain_block : BurnchainBlock<A, K> = db_recv.recv()
                .map_err(|_e| burnchain_error::ThreadChannelError)?;

            burndb.process_block(&burnchain_block)
                .map_err(|e| burnchain_error::DBError(e));
        }
        Ok(())
    });

    // feed the pipeline!
    for i in 0..input_headers.len() {
        downloader_send.send(input_headers[i].clone())
            .map_err(|e| burnchain_error::ThreadChannelError)?;
    }

    // join up 
    download_thread.join();
    parse_thread.join();
    db_thread.join();

    Ok(end_block)
}

/// Synchronize burn transactions from the Bitcoin blockchain 
pub fn sync_burnchain_bitcoin(network_name: &String, working_dir: &String) -> Result<u64, burnchain_error> {
    use bitcoin::blockdata::block::LoneBlockHeader;
    use burnchains::bitcoin::PeerMessage;
    use burnchains::bitcoin::indexer::FIRST_BLOCK_MAINNET;
    use burnchains::bitcoin::indexer::FIRST_BLOCK_MAINNET_HASH;
    use burnchains::bitcoin::blocks::{BitcoinBlockDownloader, BitcoinBlockParser};
    use burnchains::bitcoin::indexer::BitcoinIndexer;

    sync_burnchain::<LoneBlockHeader, PeerMessage, BitcoinBlockDownloader, BitcoinBlockParser, BitcoinAddress, BitcoinPublicKey, BitcoinIndexer>(network_name, working_dir, FIRST_BLOCK_MAINNET, &FIRST_BLOCK_MAINNET_HASH)
}
