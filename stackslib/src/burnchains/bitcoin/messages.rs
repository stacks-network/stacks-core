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

use crate::burnchains::bitcoin::indexer::BitcoinIndexer;
use crate::burnchains::bitcoin::{Error as btc_error, PeerMessage};

pub trait BitcoinMessageHandler {
    fn begin_session(&mut self, indexer: &mut BitcoinIndexer) -> Result<bool, btc_error>;
    fn handle_message(
        &mut self,
        indexer: &mut BitcoinIndexer,
        msg: PeerMessage,
    ) -> Result<bool, btc_error>;
}
