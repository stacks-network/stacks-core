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
use burnchains::BlockChannel;

use chainstate::burn::db::burndb::BurnDB;

// IPC messages between threads
#[derive(Debug, Clone, PartialEq)]
pub struct BurnHeaderIPC<H> {
    pub height: u64,
    pub header: H
}

#[derive(Debug, Clone, PartialEq)]
pub struct BurnBlockIPC<H, B> {
    pub height: u64,
    pub header: H,
    pub block: B
}

pub trait BurnchainBlockDownloader<H, B>
where
    H: Sync + Send,
    B: Sync + Send,
{
    fn download(&mut self, header: &BurnHeaderIPC<H>) -> Result<BurnBlockIPC<H, B>, burnchain_error>;
}

pub trait BurnchainBlockParser<H, B, A, K>
where
    A: Address + Sync + Send,
    K: PublicKey + Sync + Send
{
    fn parse(&mut self, block: &BurnBlockIPC<H, B>) -> Result<BurnchainBlock<A, K>, burnchain_error>;
}

pub trait BurnchainIndexer<H, B, D, P, A, K>
where
    // Rust doesn't have higher-kinded types yet :(
    H: Send + Sync,
    B: Send + Sync,
    D: BurnchainBlockDownloader<H, B>,
    P: BurnchainBlockParser<H, B, A, K>,
    A: Address + Sync + Send,
    K: PublicKey + Sync + Send,
{
    
    fn init(network_name: &String, working_directory: &String) -> Result<Self, burnchain_error>
        where Self : Sized;
    fn connect(&mut self) -> Result<(), burnchain_error>;
    fn get_blockchain_height(&self) -> Result<u64, burnchain_error>;
    fn get_headers_path(&self) -> String;
    fn get_headers_height(&self, headers_path: &String) -> Result<u64, burnchain_error>;
    fn find_chain_reorg(&mut self, headers_path: &String, start_height: u64) -> Result<u64, burnchain_error>;
    fn sync_headers(&mut self, headers_path: &String, start_height: u64, end_height: u64) -> Result<(), burnchain_error>;
    fn drop_headers(&mut self, headers_path: &String, new_height: u64) -> Result<(), burnchain_error>;

    fn read_headers(&self, headers_path: &String, start_block: u64, end_block: u64) -> Result<Vec<BurnHeaderIPC<H>>, burnchain_error>;

    fn downloader(&self) -> D;
    fn parser(&self) -> P;
}

