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

//! This file contains the Nakamoto block downloader implementation.
//!
//! # Overview
//!
//! The downloader is implemented as a network state machine, which is called from the main event
//! loop of the p2p network.  On each pass, the downloader state machine inspects the Stacks chain
//! state and peer block inventories to see if there are any tenures to download, and if so, it
//! queues up HTTP requests for the blocks and reacts to their responses.  It yields the downloaded
//! blocks, which the p2p main loop yields in its `NetworkResult` for the relayer to consume.
//!
//! # Design
//!
//! The state machine has three layers: a top-level state machine for managing all of
//! the requisite state for identifying tenures to download, a pair of low-level state machines for
//! fetching individual tenures, and a middle layer for using the tenure data to drive the low-level
//! state machines to fetch the requisite tenures.
//!
//! The three-layer design is meant to provide a degree of encapsulation of each downloader
//! concern.  Because downloading tenures is a multi-step process, we encapsulate the steps to
//! download a single tenure into a low-level state machine which can be driven by separate
//! flow-control.  Because we can drive multiple tenure downloads in parallel (i.e. one per peer),
//! we have a middle layer for scheduling tenures to peers for download.  This middle layer manages
//! the lifecycles of the lower layer state machines.  The top layer is needed to interface the
//! middle layer to the chainstate and the rest of the p2p network, and as such, handles the
//! bookkeeping so that the lower layers can operate without needing access to this
//! otherwise-unrelated concern.
//!
//! ## NakamotoDownloadStateMachine
//!
//! The top-level download state machine (`NakamotoDownloadStateMachine`) has two states:
//! Obtaining confirmed tenures, and obtaining unconfirmed tenures.  A _confirmed_ tenure is a
//! tenure for which we can obtain the start and end block hashes using peer inventories and the
//! sortition DB.  The hashes are embedded within sortition winners, and the inventories tell us
//! which sortitions correspond to tenure-starts and tenure-ends (each tenure-end is the
//! tenure-start of the next tenure).  An _unconfirmed_ tenure is a tenure that is not confirmed --
//! we do not have one or both of its start/end block hashes available from the sortition history
//! since they have not been recorded yet.
//!
//! The `NakamotoDownloadStateMachine` operates by attempting to download each reward cycle's
//! tenures, including the current reward cycle.  Once it has obtained them all for the current
//! reward cycle, it proceeds to fetch the next reward cycle's tenures.  It does this because the
//! sortition DB itself cannot inform us of the tenure start/end block hashes in a given reward
//! cycle until the PoX anchor block mined in the previous reward cycle has been downloaded and
//! processed.
//!
//! To achieve this, the `NakamotoDwonloadStateMachine` performs a lot of bookkeeping.  Namely, it
//! keeps track of:
//!
//! * The ongoing and prior reward cycle's sortitions' tenure IDs and winning block hashes
//! (implemented as lists of `WantedTenure`s)
//! * Which sortitions correspond to tenure start and end blocks (implemented as a table of
//! `TenureStartEnd`s)
//! * Which neighbors can serve which full tenures
//! * What order to request tenures in
//!
//! This information is consumed by the lower levels of the state machine.
//!
//! ## `NakamotoTenureDownloadSet`
//!
//! Naturally, the `NakamotoDownloadStateMachine` contains two code paths -- one for each mode.
//! To facilitate confirmed tenure downloads, it has a second-layer state machine called
//! the `NakamotoTenureDownloadSet`.  This is responsible for identifying and issuing requests to
//! peers which can serve complete tenures, and keeping track of whether or not the current reward
//! cycle has any remaining tenures to download.  To facilitate unconfirmed tenure downloads (which
//! is a much simpler task), it simply provides an internal method for issuing requests and
//! processing responses for its neighbors' unconfirmed tenure data.
//!
//! This middle layer consumes the data mantained by the `,akamotoDownloaderStateMachine` in order
//! to instantiate, drive, and clean up one or more per-tenure download state machines.
//!
//! ## `NakamotoTenureDownloader` and `NakamotoUnconfirmedTenureDownloader`
//!
//! Per SIP-021, obtaining a confirmed tenure is a multi-step process.  To carry this out, this
//! module contains two third-level state machines: `NakamotoTenureDownloader`, which downloads a
//! single tenure's blocks if the start and end block hash are known, and
//! `NakamotoUnconfirmedTenureDownloader`, which downloads the ongoing tenure.  The
//! `NakamotoTenureDownloadSet` uses a set of `NakamotoTenureDownloader` instances (one per
//! neighbor) to fetch confirmed tenures, and the `NakamotoDownloadStateMachine`'s unconfirmed
//! tenure download state provides a method for driving a set of
//! `NakamotoUnconfirmedTenureDownloader` machines to poll neighbors for their latest tenure
//! blocks.
//!
//! # Implementation
//!
//! The implementation here plugs directly into the p2p state machine, and is called once per pass.
//! Unlike in Stacks 2.x, the downloader is consistently running, and can act on newly-discovered
//! tenures once a peer's inventory reports their availability.  This is because Nakamoto is more
//! latency-sensitive than Stacks 2.x, and nodes need to obtain blocks as quickly as possible.
//!
//! Concerning latency, a lot of attention is paid to reducing the amount of gratuitous I/O
//! required for the state machine to run.  The bookkeeping steps in the
//! `NakamotoDownloadStateMachine` may seem tedious, but they are specifically designed to only
//! load new sortition and chainstate data when it is necessary to do so.  Most of the time, the
//! downloader never touches disk; it only needs to do so when it is considering new sortitions and
//! new chain tips.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use rand::{thread_rng, RngCore};
use stacks_common::types::chainstate::{
    BlockHeaderHash, ConsensusHash, PoxId, SortitionId, StacksBlockId,
};
use stacks_common::types::net::{PeerAddress, PeerHost};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs, log};
use wsts::curve::point::Point;

use crate::burnchains::{Burnchain, BurnchainView, PoxConstants};
use crate::chainstate::burn::db::sortdb::{
    BlockHeaderCache, SortitionDB, SortitionDBConn, SortitionHandleConn,
};
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::{
    NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, NakamotoStagingBlocksConnRef,
};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::{
    Error as chainstate_error, StacksBlockHeader, TenureChangePayload,
};
use crate::core::{
    EMPTY_MICROBLOCK_PARENT_HASH, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH,
};
use crate::net::api::gettenureinfo::RPCGetTenureInfo;
use crate::net::chat::ConversationP2P;
use crate::net::db::{LocalPeer, PeerDB};
use crate::net::http::HttpRequestContents;
use crate::net::httpcore::{StacksHttpRequest, StacksHttpResponse};
use crate::net::inv::epoch2x::InvState;
use crate::net::inv::nakamoto::{NakamotoInvStateMachine, NakamotoTenureInv};
use crate::net::neighbors::rpc::NeighborRPC;
use crate::net::neighbors::NeighborComms;
use crate::net::p2p::PeerNetwork;
use crate::net::server::HttpPeer;
use crate::net::{Error as NetError, Neighbor, NeighborAddress, NeighborKey};
use crate::util_lib::db::{DBConn, Error as DBError};

mod download_state_machine;
mod tenure;
mod tenure_downloader;
mod tenure_downloader_set;
mod tenure_downloader_unconfirmed;

pub use crate::net::download::nakamoto::download_state_machine::{
    NakamotoDownloadState, NakamotoDownloadStateMachine,
};
pub use crate::net::download::nakamoto::tenure::{AvailableTenures, TenureStartEnd, WantedTenure};
pub use crate::net::download::nakamoto::tenure_downloader::{
    NakamotoTenureDownloadState, NakamotoTenureDownloader,
};
pub use crate::net::download::nakamoto::tenure_downloader_set::NakamotoTenureDownloaderSet;
pub use crate::net::download::nakamoto::tenure_downloader_unconfirmed::{
    NakamotoUnconfirmedDownloadState, NakamotoUnconfirmedTenureDownloader,
};

impl PeerNetwork {
    /// Set up the Nakamoto block downloader
    pub fn init_nakamoto_block_downloader(&mut self) {
        if self.block_downloader_nakamoto.is_some() {
            return;
        }
        let epoch = self.get_epoch_by_epoch_id(StacksEpochId::Epoch30);
        let downloader = NakamotoDownloadStateMachine::new(epoch.start_height);
        self.block_downloader_nakamoto = Some(downloader);
    }

    /// Drive the block download state machine
    pub fn sync_blocks_nakamoto(
        &mut self,
        burnchain_height: u64,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        ibd: bool,
    ) -> Result<HashMap<ConsensusHash, Vec<NakamotoBlock>>, NetError> {
        if self.block_downloader_nakamoto.is_none() {
            self.init_nakamoto_block_downloader();
        }
        let Some(mut block_downloader) = self.block_downloader_nakamoto.take() else {
            return Ok(HashMap::new());
        };

        let new_blocks_res = block_downloader.run(burnchain_height, self, sortdb, chainstate, ibd);
        self.block_downloader_nakamoto = Some(block_downloader);

        new_blocks_res
    }

    /// Perform block sync.
    /// Drive the state machine, and clear out any dead and banned neighbors
    pub fn do_network_block_sync_nakamoto(
        &mut self,
        burnchain_height: u64,
        sortdb: &SortitionDB,
        chainstate: &StacksChainState,
        ibd: bool,
    ) -> Result<HashMap<ConsensusHash, Vec<NakamotoBlock>>, NetError> {
        let res = self.sync_blocks_nakamoto(burnchain_height, sortdb, chainstate, ibd)?;

        let Some(mut block_downloader) = self.block_downloader_nakamoto.take() else {
            return Ok(res);
        };

        for broken in block_downloader.neighbor_rpc.take_broken() {
            self.deregister_and_ban_neighbor(&broken);
        }

        for dead in block_downloader.neighbor_rpc.take_dead() {
            self.deregister_neighbor(&dead);
        }

        self.block_downloader_nakamoto = Some(block_downloader);
        Ok(res)
    }
}
