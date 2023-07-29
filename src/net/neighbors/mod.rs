// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

use crate::net::db::PeerDB;
use crate::net::Error as net_error;
use crate::net::Neighbor;
use crate::net::NeighborKey;
use crate::net::PeerAddress;

use crate::net::codec::*;
use crate::net::*;

use crate::net::connection::ConnectionOptions;
use crate::net::connection::ReplyHandleP2P;

use crate::net::db::LocalPeer;

use crate::net::p2p::PeerNetwork;

use crate::util_lib::db::DBConn;
use crate::util_lib::db::DBTx;
use crate::util_lib::db::Error as db_error;

use stacks_common::util::secp256k1::Secp256k1PublicKey;

use std::cmp;
use std::mem;
use std::net::SocketAddr;

use std::collections::HashMap;
use std::collections::HashSet;

use crate::burnchains::Address;
use crate::burnchains::Burnchain;
use crate::burnchains::BurnchainView;
use crate::burnchains::PublicKey;

use rand::prelude::*;
use rand::thread_rng;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::log;

pub mod comms;
pub mod neighbor;
pub mod walk;

pub use comms::{NeighborSet, NeighborSetMessageIterator, NeighborSetRequest, ToNeighborKey};

pub use walk::{NeighborPingback, NeighborWalk, NeighborWalkResult};

/// How often we can contact other neighbors, at a minimim
#[cfg(test)]
pub const NEIGHBOR_MINIMUM_CONTACT_INTERVAL: u64 = 0;
#[cfg(not(test))]
pub const NEIGHBOR_MINIMUM_CONTACT_INTERVAL: u64 = 600;

/// Default number of seconds to wait for a reply from a neighbor
pub const NEIGHBOR_REQUEST_TIMEOUT: u64 = 30;

/// Maximum age of a neighbor until we stop reporting it via the p2p network.
/// Default is 3 days.
pub const MAX_NEIGHBOR_AGE: u64 = 60 * 60 * 24 * 3;

/// Default number of initial walks the state-machine should execute before self-throttling.  When
/// the node starts up, it will run this many walks without delay in order to quickly populate the
/// frontier DB. After this many walks complete, it will settle into walking every so often.
/// This value counts the number of *successful* walks; failed or partially-successful walks do not
/// count towards this total.
pub const NUM_INITIAL_WALKS: u64 = 10;
/// Default number of initial walk retries.  The node will re-attempt an unthrottled walk this many
/// times when it starts up, should the initial walk fail for some reason.
pub const WALK_RETRY_COUNT: u64 = 10;
/// Every so often, the neighbor walk's current neighbor will be reset to a random node (selected
/// from the DB or the current set of connected peers).  This is the minimum number of walk steps
/// to be taken before this reset happens.
pub const WALK_MIN_DURATION: u64 = 20;
/// Maximum number of times a neighbor walk can take steps before being forcibly reset to a random
/// node.
pub const WALK_MAX_DURATION: u64 = 40;
/// The probability that a walk will be reset when the number of steps is in-between the min and
/// max durations.
pub const WALK_RESET_PROB: f64 = 0.05;
/// Maximum number of seconds the walk can remain in a single state before it will be reset.  This
/// prevents walks from stalling out indefinitely.
pub const WALK_STATE_TIMEOUT: u64 = 60;

/// Total number of seconds for which a particular walk can exist.  It will be reset if it exceeds
/// this age.
#[cfg(test)]
pub const WALK_RESET_INTERVAL: u64 = 60;
#[cfg(not(test))]
pub const WALK_RESET_INTERVAL: u64 = 600;

/// How often the node will consider pruning neighbors from its neighbor set.  The node will prune
/// neighbors from over-represented hosts and IP ranges in order to maintain connections to a
/// diverse set of neighbors.
#[cfg(test)]
pub const PRUNE_FREQUENCY: u64 = 0;
#[cfg(not(test))]
pub const PRUNE_FREQUENCY: u64 = 43200;

/// Not all neighbors discovered will have an up-to-date chain tip.  This value is the highest
/// discrepancy between the local burnchain block height and the remote node's burnchain block
/// height for which the neighbor will be considered as a worthwhile peer to remember.
#[cfg(test)]
pub const MAX_NEIGHBOR_BLOCK_DELAY: u64 = 25;
#[cfg(not(test))]
pub const MAX_NEIGHBOR_BLOCK_DELAY: u64 = 288;

/// How often to kick off neighbor walks.
#[cfg(test)]
pub const NEIGHBOR_WALK_INTERVAL: u64 = 0;
#[cfg(not(test))]
pub const NEIGHBOR_WALK_INTERVAL: u64 = 120; // seconds

impl PeerNetwork {
    /// Instantiate a neighbor walk, and update internal bookkeeping about how many times and how
    /// often we've done this (so we can intelligently alter walk strategies).
    ///
    /// Returns the new neighbor walk on success.
    /// Returns None if we could not instantiate a walk for some reason.
    fn new_neighbor_walk(&mut self, ibd: bool) -> Option<NeighborWalk> {
        // alternate between starting walks from inbound and outbound neighbors.
        // fall back to pingbacks-only walks if no options exist.
        debug!(
            "{:?}: Begin walk attempt {}",
            &self.local_peer, self.walk_attempts
        );

        // always ensure we're connected to always-allowed outbound peers
        let walk_res = if ibd {
            // always connect to bootstrap peers if in IBD
            NeighborWalk::instantiate_walk_to_always_allowed(self, ibd)
        } else {
            // if not in IBD, then we're not required to use the always-allowed neighbors
            // all the time (since they may be offline, and we have all the blocks anyway).
            // Alternate between picking random neighbors, and picking always-allowed
            // neighbors.
            if self.walk_attempts % (self.connection_opts.walk_inbound_ratio + 1) == 0 {
                NeighborWalk::instantiate_walk(self)
            } else {
                NeighborWalk::instantiate_walk_to_always_allowed(self, ibd)
            }
        };

        // recover if we error out in creating a walk by trying a different strategy
        let walk_res = match walk_res {
            Ok(x) => Ok(x),
            Err(net_error::NotFoundError) => {
                // failed to create a walk, so either connect to any known neighbor or connect
                // to an inbound peer.
                if self.walk_attempts % (self.connection_opts.walk_inbound_ratio + 1) == 0 {
                    NeighborWalk::instantiate_walk(self)
                } else {
                    if self.connection_opts.disable_inbound_walks {
                        debug!(
                            "{:?}: disabled inbound neighbor walks for testing",
                            &self.local_peer
                        );
                        NeighborWalk::instantiate_walk(self)
                    } else {
                        NeighborWalk::instantiate_walk_from_inbound(self)
                    }
                }
            }
            Err(e) => Err(e),
        };

        self.walk_attempts += 1;

        // if we somehow failed to create a walk, then at least try to create a walk to a pingback
        // peer in the event that our error was due to there being no known/available neighbors.
        let walk = match walk_res {
            Ok(x) => x,
            Err(Error::NoSuchNeighbor) => {
                match NeighborWalk::instantiate_walk_from_pingback(self) {
                    Ok(x) => x,
                    Err(e) => {
                        debug!(
                            "{:?}: Failed to begin neighbor walk from pingback: {:?}",
                            &self.local_peer, &e
                        );
                        self.walk_retries += 1;
                        self.walk_deadline =
                            self.connection_opts.walk_interval + get_epoch_time_secs();
                        return None;
                    }
                }
            }
            Err(e) => {
                debug!(
                    "{:?}: Failed to begin neighbor walk from peer database: {:?}",
                    &self.local_peer, &e
                );
                self.walk_retries += 1;
                self.walk_deadline = self.connection_opts.walk_interval + get_epoch_time_secs();
                return None;
            }
        };

        Some(walk)
    }

    /// Reset the state of the walk
    fn reset_walk(&mut self) {
        test_debug!("{:?}: Reset walk", &self.local_peer);
        self.walk = None;
        self.walk_resets += 1;
    }

    /// Set up the walk state-machine if need be.
    /// Returns true if we instantiated the walk.
    /// Returns false if not.
    fn setup_walk(&mut self, ibd: bool) -> bool {
        // we unconditionally need to begin walking if we're not connected to any always-allowed
        // peer
        let mut need_new_peers = false;
        let (num_always_connected, total_always_connected) = self
            .count_connected_always_allowed_peers()
            .unwrap_or((0, 0));
        if num_always_connected == 0 && total_always_connected > 0 {
            // force a reset
            debug!("{:?}: not connected to any always-allowed peers; forcing a walk reset to try and fix this", &self.local_peer);
            self.reset_walk();

            need_new_peers = true;
        }

        if self.walk.is_none() {
            // time to do a walk yet?
            if !need_new_peers
                && (self.walk_count > self.connection_opts.num_initial_walks
                    || self.walk_retries > self.connection_opts.walk_retry_count)
                && self.walk_deadline > get_epoch_time_secs()
            {
                // we've done enough walks for an initial mixing, or we can't connect to anyone,
                // so throttle ourselves down until the walk deadline passes.
                test_debug!(
                    "{:?}: Throttle walk until {} to walk again (walk count: {}, walk retries: {})",
                    &self.local_peer,
                    self.walk_deadline,
                    self.walk_count,
                    self.walk_retries
                );
                return false;
            }

            // time to walk!
            let new_walk = if let Some(w) = self.new_neighbor_walk(ibd) {
                w
            } else {
                // unable to create a walk a this time.
                return false;
            };
            self.walk = Some(new_walk);
        }

        return true;
    }

    #[cfg(test)]
    fn print_walk_diagnostics(&mut self) {
        let (mut inbound, mut outbound) = self.dump_peer_table();

        inbound.sort();
        outbound.sort();

        debug!("{:?}: Walk finished ===================", &self.local_peer,);
        debug!(
            "{:?}: Peers outbound ({}): {}",
            &self.local_peer,
            outbound.len(),
            outbound.join(", ")
        );
        debug!(
            "{:?}: Peers inbound ({}):  {}",
            &self.local_peer,
            inbound.len(),
            inbound.join(", ")
        );

        match PeerDB::get_frontier_size(self.peerdb.conn()) {
            Ok(count) => {
                debug!("{:?}: Frontier table size: {}", &self.local_peer, count);
            }
            Err(_) => {}
        };
        debug!("{:?}: Walk finished ===================", &self.local_peer);
    }

    #[cfg(not(test))]
    fn print_walk_diagnostics(&self) {}

    /// Update the state of our peer graph walk.
    /// If we complete a walk, give back a walk result.
    /// Mask errors by restarting the graph walk.
    /// Returns the walk result, and a true/false flag to indicate whether or not the work for the
    /// walk was finished (i.e. we either completed the walk, or we reset the walk)
    pub fn walk_peer_graph(&mut self, ibd: bool) -> (bool, Option<NeighborWalkResult>) {
        if !self.setup_walk(ibd) {
            // nothing to do
            return (true, None);
        }

        let mut walk = if let Some(walk) = self.walk.take() {
            walk
        } else {
            // nothing to do
            return (true, None);
        };

        let walk_result_opt = match walk.run(self) {
            Ok(Some(ws)) => {
                // walk ran to completion
                self.walk_count += 1;
                self.walk_deadline = self.connection_opts.walk_interval + get_epoch_time_secs();

                debug!(
                    "{:?}: walk has completed in {} steps ({} walks total)",
                    &self.local_peer, walk.walk_step_count, self.walk_count
                );

                self.print_walk_diagnostics();
                Some(ws)
            }
            Ok(None) => {
                // walk is not done yet, but we did make some progress
                self.walk_total_step_count += 1;
                self.walk_retries = 0;
                self.walk = Some(walk);
                return (false, None);
            }
            Err(net_error::StepTimeout) => {
                // walk step took to long. Needs a reset
                debug!(
                    "{:?}: walk has timed out: stayed in state {:?} for more than {} seconds",
                    &self.local_peer, &walk.state, walk.walk_state_timeout
                );
                self.reset_walk();
                return (true, None);
            }
            Err(_e) => {
                // walk step failed for some reason
                debug!(
                    "{:?}: Restarting neighbor walk with new random neighbors: {:?} => {:?}",
                    &self.local_peer, walk.state, &_e
                );
                self.reset_walk();
                return (true, None);
            }
        };

        // did a walk take too long?
        // - too many steps?
        // - too much time?
        let walk_timed_out = walk.walk_step_count >= walk.walk_max_duration
            || walk.walk_instantiation_time + walk.walk_reset_interval < get_epoch_time_secs();

        // unless we're seeding the frontier table, we should occasionally restart the walk.
        if (self.walk_count > self.connection_opts.num_initial_walks
            && walk.walk_step_count >= walk.walk_min_duration)
            || walk_timed_out
        {
            // consider re-setting the walk state, now that we completed a walk.
            let mut rng = thread_rng();
            let sample: f64 = rng.gen();
            if walk_timed_out || sample < walk.walk_reset_prob {
                debug!(
                    "{:?}: Resetting walk due to either a walk timeout ({}) or random restart",
                    &self.local_peer, walk_timed_out
                );
                self.reset_walk();
                return (true, None);
            }
        }

        self.walk = Some(walk);
        (false, walk_result_opt)
    }
}
