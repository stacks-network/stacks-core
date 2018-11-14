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

pub struct BurnchainTxOutput {
    script: String,
    units: u64
}

pub struct BurnchainTxInput {
    sender: BurnchainTxOutput,
    keys: Vec<String>
}

pub struct BurnchainTransaction {
    block_height: u64,
    txid: String,
    vtxindex: u64,
    op: u8,
    data: String,
    inputs: Vec<BurnchainTxInput>,
    outputs: Vec<BurnchainTxOutput>
}

pub trait BurnchainIndexer {
    fn setup(&mut self, working_directory: &str) -> Result<(), &'static str>;
    fn connect(&mut self, &str) -> Result<(), &'static str>;
    fn get_block_hash(&mut self, block_height: u64) -> Result<String, &'static str>;
    fn get_block_txs(&mut self, block_hash: &str) -> Result<Box<Vec<BurnchainTransaction>>, &'static str>;
}
