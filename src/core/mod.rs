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

use chainstate::burn::db::burndb::BurnDB;

use burnchains::bitcoin::indexer::BitcoinIndexer;

use burnchains::bitcoin::Error as btc_error;

use burnchains::indexer::BurnchainIndexer;
use burnchains::Address;
use burnchains::PublicKey;
use burnchains::BurnchainHeaderHash;

use burnchains::Error as burnchain_error;

/// Check the burn chain for reorgs and identify where we need to start synchronizing from.
/// Returns the block height on success, as well as any new headers' hashes that need to be
/// downloaded.
pub fn sync_burnchain_reorg<T, A, K>(indexer: &mut T, burndb: &mut BurnDB) -> Result<(u64, Vec<BurnchainHeaderHash>), burnchain_error>
where
    A: Address,
    K: PublicKey,
    T: BurnchainIndexer<A, K>
{
    let headers_path = indexer.get_headers_path();
    let sync_height;
    
    // how far are we in sync'ing the db to?
    let db_height = burndb.get_block_height()
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
    let (new_height, new_headers) = indexer.find_chain_reorg(&headers_path, db_height)
        .map_err(|e| {
            error!("Failed to check for reorgs between {} and {}", db_height, block_height);
            e
        })?;
    
    if new_height < db_height {
        warn!("Detected burnchain reorg at height {}.  Invalidating affected burn DB transactions and re-sync'ing...", new_height);

        burndb.tx_begin()
            .map_err(|e| {
                error!("Failed to begin burn DB transaction");
                burnchain_error::DBError(e)
            })?;

        burndb.burnchain_history_reorg(new_height)
            .map_err(|e| {
                error!("Failed to process burn chain reorg between {} and {}", new_height, db_height);
                burnchain_error::DBError(e)
            })?;

        burndb.tx_commit();

        // drop associated headers as well 
        indexer.drop_headers(&headers_path, new_height)?;
        sync_height = new_height;
    }
    else {
        sync_height = db_height;
    }

    Ok((new_height, new_headers))
}

/// Go and get all the blocks between to block heights, and feed them into the burn chain DB in
/// order.
pub fn sync_burnchain_blocks<T, A, K>(indexer: &mut T, burndb: &mut BurnDB, start_block: u64, end_block: u64) -> Result<u64, burnchain_error>
where
    A: Address,
    K: PublicKey,
    T: BurnchainIndexer<A, K>
{
    // assemble a thread pipeline to go and download blocks 
    Err(burnchain_error::bitcoin(btc_error::NotImplemented))
}    

/// synchronize the burn database up to the given block height
pub fn sync_burnchain<T, A, K>(indexer: &mut T, burndb: &mut BurnDB, end_block: u64) -> Result<u64, burnchain_error>
where
    A: Address,
    K: PublicKey,
    T: BurnchainIndexer<A, K>
{

    let headers_path = indexer.get_headers_path();
    let db_height = burndb.get_block_height()
        .map_err(|e| {
            error!("Failed to query block height from burn DB");
            burnchain_error::DBError(e)
        })?;

    if db_height >= end_block {
        // all caught up
        return Ok(db_height);
    }

    // handle reorgs
    let (sync_height, new_header_hashes) = sync_burnchain_reorg(indexer, burndb)?;

    // get headers 
    indexer.sync_headers(&headers_path, sync_height, end_block)?;

    Err(burnchain_error::bitcoin(btc_error::NotImplemented))
}
