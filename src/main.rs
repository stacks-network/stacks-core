/*
 copyright: (c) 2013-2018 by Blockstack PBC, a public benefit corporation.

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

extern crate rand;
extern crate bitcoin;
extern crate ini;
extern crate jsonrpc;
extern crate serde;
#[macro_use] extern crate serde_derive;
#[macro_use] extern crate log;

mod burnchains;
mod util;

use burnchains::indexer::BurnchainIndexer;
use burnchains::bitcoin::indexer::sync_block_headers;
use burnchains::bitcoin::Error as btc_error;
use util::log as logger;

fn main() {
    logger::init().unwrap();

    let mut bitcoin_indexer = burnchains::bitcoin::indexer::BitcoinIndexer::new();
    bitcoin_indexer.setup("/tmp/test-blockstack-ng").unwrap();

    match sync_block_headers(&mut bitcoin_indexer, Some(540000)) {
        Ok(num_fetched) => {
            debug!("Fetched {} headers!", num_fetched);
        }
        Err(e) => {
            error!("Failed to sync headers: {:?}", e);
        }
    }
}
