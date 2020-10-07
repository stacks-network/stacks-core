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

use burnchains::bitcoin::indexer::BitcoinIndexer;
use burnchains::bitcoin::Error as btc_error;
use burnchains::bitcoin::PeerMessage;

pub trait BitcoinMessageHandler {
    fn begin_session(&mut self, indexer: &mut BitcoinIndexer) -> Result<bool, btc_error>;
    fn handle_message(
        &mut self,
        indexer: &mut BitcoinIndexer,
        msg: PeerMessage,
    ) -> Result<bool, btc_error>;
}
