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

use burnchains::*;
use burnchains::Error as burnchain_error;
use burnchains::bitcoin::BlockSender;

use burnchains::BurnchainHeaderHash;
use burnchains::BurnchainBlock;

use chainstate::burn::db::burndb::BurnDB;

use std::sync::Arc;
use std::sync::mpsc::SyncSender;

pub type BlockChannel<A, K> = SyncSender<Arc<BurnchainBlock<A, K>>>;

pub trait BurnchainIndexer<A: Address, K: PublicKey> {
    fn init(network_name: &String, working_directory: &String) -> Result<Self, burnchain_error>
        where Self : Sized;
    fn connect(&mut self) -> Result<(), burnchain_error>;
    fn get_blockchain_height(&self) -> Result<u64, burnchain_error>;
    fn get_headers_path(&self) -> String;
    fn get_headers_height(&self, headers_path: &String) -> Result<u64, burnchain_error>;
    fn find_chain_reorg(&mut self, headers_path: &String, start_height: u64) -> Result<(u64, Vec<BurnchainHeaderHash>), burnchain_error>;
    fn sync_headers(&mut self, headers_path: &String, start_height: u64, end_height: u64) -> Result<(), burnchain_error>;
    fn drop_headers(&mut self, headers_path: &String, new_height: u64) -> Result<(), burnchain_error>;
    fn sync_blocks(&mut self, headers_path: &String, start_height: u64, end_height: u64, block_channel: &BlockChannel<A, K>) -> Result<(), burnchain_error>;
}
