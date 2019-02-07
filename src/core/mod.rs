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
use burnchains::Burnchain;
use burnchains::Error as burnchain_error;
use util::log;

// fork set identifier -- to be mixed with the consensus hash (encodes the version)
pub const SYSTEM_FORK_SET_VERSION : [u8; 4] = [21u8, 0u8, 0u8, 0u8];

/// Synchronize burn transactions from the Bitcoin blockchain 
pub fn sync_burnchain_bitcoin(working_dir: &String, network_name: &String) -> Result<u64, burnchain_error> {
    use burnchains::bitcoin::indexer::BitcoinIndexer;
    use burnchains::bitcoin::indexer::BitcoinIndexerAddress;
    use burnchains::bitcoin::indexer::BitcoinIndexerPublicKey;

    let mut burnchain = Burnchain::new(working_dir, &"bitcoin".to_string(), network_name);
    let new_height_res = burnchain.sync::<BitcoinIndexer, BitcoinIndexerAddress, BitcoinIndexerPublicKey>();
    let new_height = new_height_res
        .map_err(|e| {
            error!("Failed to synchronize Bitcoin chain state for {} in {}", network_name, working_dir);
            e
        })?;

    Ok(new_height)
}
