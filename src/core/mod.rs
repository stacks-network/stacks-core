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
use std::fs;

use chainstate::burn::db::burndb::BurnDB;

use burnchains::indexer::BurnchainIndexer;
use burnchains::Address;
use burnchains::PublicKey;
use burnchains::BurnchainHeaderHash;
use burnchains::BurnchainBlock;
use burnchains::indexer::BurnchainBlockDownloader;
use burnchains::indexer::BurnchainBlockParser;
use burnchains::indexer::{BurnHeaderIPC, BurnBlockIPC};

use burnchains::Error as burnchain_error;

use util::log;

/// Check the burn chain for reorgs and identify where we need to start synchronizing from.
/// Returns the block height on success, as well as any new headers' hashes that need to be
/// downloaded.
fn sync_burnchain_reorg<I>(indexer: &mut I, burndb: &mut BurnDB<<<I as BurnchainIndexer>::P as BurnchainBlockParser>::A, <<I as BurnchainIndexer>::P as BurnchainBlockParser>::K>) -> Result<(u64, u64), burnchain_error>
where
    I: BurnchainIndexer
{
    let headers_path = indexer.get_headers_path();
    let sync_height;
    
    // how far are we in sync'ing the db to?
    let db_height = BurnDB::<<<I as BurnchainIndexer>::P as BurnchainBlockParser>::A, <<I as BurnchainIndexer>::P as BurnchainBlockParser>::K>::get_block_height(burndb.conn())
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

        BurnDB::<<<I as BurnchainIndexer>::P as BurnchainBlockParser>::A, <<I as BurnchainIndexer>::P as BurnchainBlockParser>::K>::burnchain_history_reorg(&mut tx, new_height)
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
fn sync_burnchain<I>(network_name: &String, working_dir: &String, first_block: u64, first_block_hash: &BurnchainHeaderHash) -> Result<u64, burnchain_error>
where
    I: BurnchainIndexer + 'static
{
    let mut db_pathbuf = PathBuf::from(working_dir);
    db_pathbuf.push("burn.db");
    
    let db_path = db_pathbuf.to_str().unwrap().to_string();

    let mut indexer : I = BurnchainIndexer::init(network_name, working_dir)?;

    // careful -- need to use the address and public key types that the indexer uses
    let mut burndb = BurnDB::<<<I as BurnchainIndexer>::P as BurnchainBlockParser>::A, <<I as BurnchainIndexer>::P as BurnchainBlockParser>::K>::connect(&db_path, first_block, first_block_hash, true)
        .map_err(burnchain_error::DBError)?;

    let headers_path = indexer.get_headers_path();
    let db_height = BurnDB::<<<I as BurnchainIndexer>::P as BurnchainBlockParser>::A, <<I as BurnchainIndexer>::P as BurnchainBlockParser>::K>::get_block_height(burndb.conn())
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
    let header_height = indexer.get_headers_height(&headers_path)?;
    
    // TODO: do this atomically -- write to headers_path.new, do the sync, and then merge the files
    // and rename the merged file over the headers file (atomic)
    debug!("Sync headers from {} - {}", header_height, end_block);
    indexer.sync_headers(&headers_path, header_height, end_block)?;

    // initial inputs
    // TODO: stream this -- don't need to load them all into RAM
    let input_headers = indexer.read_headers(&headers_path, sync_height, end_block)?;

    // synchronize 
    let (downloader_send, downloader_recv) = sync_channel(1);
    let (parser_send, parser_recv) = sync_channel(1);
    let (db_send, db_recv) = sync_channel(1);

    let mut downloader = indexer.downloader();
    let mut parser = indexer.parser();

    let download_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
        loop {
            debug!("Try recv next header");
            let header : <<<I as BurnchainIndexer>::P as BurnchainBlockParser>::D as BurnchainBlockDownloader>::H = downloader_recv.recv()
                .map_err(|_e| burnchain_error::ThreadChannelError)?;

            let block : <<<I as BurnchainIndexer>::P as BurnchainBlockParser>::D as BurnchainBlockDownloader>::B = downloader.download(&header)?;

            parser_send.send(block)
                .map_err(|_e| burnchain_error::ThreadChannelError)?;
        }
        Ok(())
    });

    let parse_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
        loop {
            debug!("Try recv next block");
            let block : <<<I as BurnchainIndexer>::P as BurnchainBlockParser>::D as BurnchainBlockDownloader>::B = parser_recv.recv()
                .map_err(|_e| burnchain_error::ThreadChannelError)?;

            let burnchain_block : BurnchainBlock<<<I as BurnchainIndexer>::P as BurnchainBlockParser>::A, <<I as BurnchainIndexer>::P as BurnchainBlockParser>::K> = parser.parse(&block)?;

            db_send.send(burnchain_block)
                .map_err(|_e| burnchain_error::ThreadChannelError)?;
        }
        Ok(())
    });

    let db_thread : thread::JoinHandle<Result<(), burnchain_error>> = thread::spawn(move || {
        loop {
            debug!("Try recv next parsed block");
            let burnchain_block : BurnchainBlock<<<I as BurnchainIndexer>::P as BurnchainBlockParser>::A, <<I as BurnchainIndexer>::P as BurnchainBlockParser>::K> = db_recv.recv()
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
    let download_res = download_thread.join();
    let parser_res = parse_thread.join();
    let db_res = db_thread.join();

    debug!("Download res: {:?}", download_res);
    debug!("Parser res: {:?}", parser_res);
    debug!("DB res: {:?}", db_res);

    Ok(end_block)
}

/// Instantiate Bitcoin-specific state 
fn setup_burnchain_bitcoin(network_name: &String, working_dir: &String) -> Result<(), burnchain_error> {
    use burnchains::bitcoin::indexer::BitcoinIndexerConfig;
    use burnchains::bitcoin::indexer::BitcoinIndexer;
    
    // working dir
    let working_dir_path = PathBuf::from(working_dir);
    if !working_dir_path.exists() {
       fs::create_dir_all(&working_dir_path)
           .map_err(burnchain_error::FSError)?;
    }

    // bitcoin.ini
    let mut bitcoin_conf_path = working_dir_path.clone();
    bitcoin_conf_path.push("bitcoin.ini");

    if !bitcoin_conf_path.exists() {
        let bitcoin_conf_path_str = bitcoin_conf_path.to_str().unwrap().to_string();
        let default_config = BitcoinIndexerConfig::default(working_dir);
        default_config.to_file(&bitcoin_conf_path_str)
            .map_err(burnchain_error::bitcoin)?;
    }

    let bitcoin_conf_path_str = bitcoin_conf_path.to_str().unwrap();
    let mut bitcoin_indexer = BitcoinIndexer::init(network_name, working_dir)?;
    let spv_headers_pathbuf = PathBuf::from(bitcoin_indexer.config.spv_headers_path.clone());
    
    // initial spv headers 
    if !spv_headers_pathbuf.exists() {
        // sync headers 
        let bitcoin_blockchain_height = bitcoin_indexer.get_blockchain_height()?;
        bitcoin_indexer.sync_all_headers(bitcoin_blockchain_height)
            .map_err(burnchain_error::bitcoin)?;
    }
    
    Ok(())
}

/// Synchronize burn transactions from the Bitcoin blockchain 
pub fn sync_burnchain_bitcoin(network_name: &String, working_dir: &String) -> Result<u64, burnchain_error> {
    use burnchains::bitcoin::indexer::BitcoinIndexer;
    use bitcoin::network::serialize::BitcoinHash;

    setup_burnchain_bitcoin(network_name, working_dir)?;

    let bitcoin_indexer = BitcoinIndexer::init(network_name, working_dir)?;
    let first_block_height = bitcoin_indexer.get_first_block_height();
    let headers_path = bitcoin_indexer.get_headers_path();
    let initial_headers_list = bitcoin_indexer.read_headers(&headers_path, first_block_height, first_block_height+1)?;
    
    if initial_headers_list.len() == 0 {
        return Err(burnchain_error::MissingHeaders);
    }

    let first_block_header_hash = &BurnchainHeaderHash::from_bitcoin_hash(&initial_headers_list[0].block_header.header.bitcoin_hash());

    sync_burnchain::<BitcoinIndexer>(network_name, working_dir, first_block_height, first_block_header_hash)
}
