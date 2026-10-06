// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

pub mod epoch2x;
pub mod nakamoto;

pub use epoch2x::{BlockDownloader, BLOCK_DOWNLOAD_INTERVAL};

use crate::net::p2p::PeerNetwork;

impl PeerNetwork {
    /// Forget what the epoch 2.x and Nakamoto block downloaders already fetched, so that anything
    /// not yet stored (epoch 2.x) or processed (Nakamoto) is fetched again. Needed when downloaded
    /// blocks may have been dropped before the relayer stored them.
    pub fn forget_completed_downloads(&mut self) {
        let scan_start = self
            .inv_state
            .as_ref()
            .map(|inv_state| inv_state.block_sortition_start)
            .unwrap_or(0);
        let mut cleared_requests = 0;
        if let Some(downloader) = self.block_downloader.as_mut() {
            cleared_requests = downloader.clear_requested_blocks();
            // The scan may already be past the dropped blocks, so restart it from where it would
            // wrap around to.
            downloader.restart_scan(scan_start);
        }

        let mut cleared_tenures = 0;
        if let Some(downloader) = self.block_downloader_nakamoto.as_mut() {
            cleared_tenures = downloader.clear_completed_tenures();
        }

        // These count bookkeeping entries kept since the downloaders started, not dropped blocks.
        info!("Cleared block download bookkeeping";
              "epoch2_request_entries" => cleared_requests,
              "nakamoto_completed_tenures" => cleared_tenures,
              "epoch2_scan_start" => scan_start);
    }
}
