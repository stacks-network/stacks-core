// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

use stacks_common::consts::{CHAIN_ID_MAINNET, CHAIN_ID_TESTNET};
use stacks_common::types::StacksEpochId;

#[cfg(test)]
use super::ClarityVersion;
pub use super::test_util::*;
use crate::vm::contexts::OwnedEnvironment;
pub use crate::vm::database::BurnStateDB;
use crate::vm::database::MemoryBackingStore;

#[cfg(all(test, feature = "developer-mode"))]
mod analysis;
mod assets;
mod contracts;
#[cfg(test)]
mod conversions;
#[cfg(test)]
mod crypto;
#[cfg(test)]
mod datamaps;
mod defines;
#[cfg(test)]
mod post_conditions;
mod principals;
#[cfg(test)]
pub mod proptest_utils;
#[cfg(test)]
mod representations;
#[cfg(test)]
mod sequences;
#[cfg(test)]
mod simple_apply_eval;
mod traits;
mod variables;

#[cfg(any(test, feature = "testing"))]
impl OwnedEnvironment<'_, '_> {
    pub fn set_tenure_height(&mut self, tenure_height: u32) {
        self.context.database.begin();
        self.context
            .database
            .set_tenure_height(tenure_height)
            .unwrap();
        self.context.database.commit().unwrap();
    }

    pub fn setup_block_metadata(&mut self, block_time: u64) {
        self.context.database.begin();
        self.context
            .database
            .setup_block_metadata(Some(block_time))
            .unwrap();
        self.context.database.commit().unwrap();
    }
}

macro_rules! epochs_template {
    ($($epoch:ident,)*) => {
        #[template]
        #[export]
        #[rstest]
        $(
            #[case::$epoch(StacksEpochId::$epoch)]
        )*
        pub fn test_epochs(#[case] epoch: StacksEpochId) {}

        #[test]
        fn epochs_covered() {
            let epoch = StacksEpochId::latest();
            match epoch {
                // don't test Epoch-1.0
                StacksEpochId::Epoch10 => (),
                // this will lead to a compile time failure if an epoch is left out
                //  of the epochs_template! macro list
                $(StacksEpochId::$epoch)|* => (),
            }
        }
    }
}

macro_rules! clarity_template {
    ($($case_name:ident: ($epoch:ident, $clarity:ident),)*) => {
        #[template]
        #[export]
        #[rstest]
        $(
            #[case::$case_name(ClarityVersion::$clarity, StacksEpochId::$epoch)]
        )*
        pub fn test_clarity_versions(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {}

        #[test]
        fn epoch_clarity_pairs_covered() {
            let epoch = StacksEpochId::latest();
            let clarity = ClarityVersion::latest();
            match (epoch, clarity) {
                // don't test Epoch-1.0
                (StacksEpochId::Epoch10, _) => (),
                // don't test these pairs, because they aren't supported:
                (StacksEpochId::Epoch20, ClarityVersion::Clarity2) => (),
                (StacksEpochId::Epoch2_05, ClarityVersion::Clarity2) => (),
                (StacksEpochId::Epoch20, ClarityVersion::Clarity3) => (),
                (StacksEpochId::Epoch2_05, ClarityVersion::Clarity3) => (),
                (StacksEpochId::Epoch21, ClarityVersion::Clarity3) => (),
                (StacksEpochId::Epoch22, ClarityVersion::Clarity3) => (),
                (StacksEpochId::Epoch23, ClarityVersion::Clarity3) => (),
                (StacksEpochId::Epoch24, ClarityVersion::Clarity3) => (),
                (StacksEpochId::Epoch25, ClarityVersion::Clarity3) => (),
                (StacksEpochId::Epoch20, ClarityVersion::Clarity4) => (),
                (StacksEpochId::Epoch2_05, ClarityVersion::Clarity4) => (),
                (StacksEpochId::Epoch21, ClarityVersion::Clarity4) => (),
                (StacksEpochId::Epoch22, ClarityVersion::Clarity4) => (),
                (StacksEpochId::Epoch23, ClarityVersion::Clarity4) => (),
                (StacksEpochId::Epoch24, ClarityVersion::Clarity4) => (),
                (StacksEpochId::Epoch25, ClarityVersion::Clarity4) => (),
                (StacksEpochId::Epoch30, ClarityVersion::Clarity4) => (),
                (StacksEpochId::Epoch31, ClarityVersion::Clarity4) => (),
                (StacksEpochId::Epoch32, ClarityVersion::Clarity4) => (),
                // this will lead to a compile time failure if a pair is left out
                //  of the clarity_template! macro list
                $((StacksEpochId::$epoch, ClarityVersion::$clarity))|* => (),
            }
        }
    }
}

// Define two rstest templates for Clarity tests: `test_epochs` and `test_clarity_versions`
//  these templates test all epochs (except 1.0) and all valid epoch/clarity-version pairs.
//
// The macro definitions ensure that we get compile time errors in testing if there is a
//  non-covered case in the rstest template. This *could* have been written as a derive macro,
//  but then it would need to be defined in the `stacks-common` library (where it would have to
//  get a `testing` feature flag). This seems less obtuse.
epochs_template! {
    Epoch20,
    Epoch2_05,
    Epoch21,
    Epoch22,
    Epoch23,
    Epoch24,
    Epoch25,
    Epoch30,
    Epoch31,
    Epoch32,
    Epoch33,
}
#[cfg(any(test, feature = "testing"))]
clarity_template! {
    Epoch20_Clarity1: (Epoch20, Clarity1),
    Epoch2_05_Clarity1: (Epoch2_05, Clarity1),
    Epoch21_Clarity1: (Epoch21, Clarity1),
    Epoch21_Clarity2: (Epoch21, Clarity2),
    Epoch22_Clarity1: (Epoch22, Clarity1),
    Epoch22_Clarity2: (Epoch22, Clarity2),
    Epoch23_Clarity1: (Epoch23, Clarity1),
    Epoch23_Clarity2: (Epoch23, Clarity2),
    Epoch24_Clarity1: (Epoch24, Clarity1),
    Epoch24_Clarity2: (Epoch24, Clarity2),
    Epoch25_Clarity1: (Epoch25, Clarity1),
    Epoch25_Clarity2: (Epoch25, Clarity2),
    Epoch30_Clarity1: (Epoch30, Clarity1),
    Epoch30_Clarity2: (Epoch30, Clarity2),
    Epoch30_Clarity3: (Epoch30, Clarity3),
    Epoch31_Clarity1: (Epoch31, Clarity1),
    Epoch31_Clarity2: (Epoch31, Clarity2),
    Epoch31_Clarity3: (Epoch31, Clarity3),
    Epoch32_Clarity1: (Epoch32, Clarity1),
    Epoch32_Clarity2: (Epoch32, Clarity2),
    Epoch32_Clarity3: (Epoch32, Clarity3),
    Epoch33_Clarity1: (Epoch33, Clarity1),
    Epoch33_Clarity2: (Epoch33, Clarity2),
    Epoch33_Clarity3: (Epoch33, Clarity3),
    Epoch33_Clarity4: (Epoch33, Clarity4),
}

#[fixture]
pub fn env_factory() -> MemoryEnvironmentGenerator {
    MemoryEnvironmentGenerator(MemoryBackingStore::new())
}

#[fixture]
pub fn tl_env_factory() -> TopLevelMemoryEnvironmentGenerator {
    TopLevelMemoryEnvironmentGenerator(MemoryBackingStore::new())
}

pub struct MemoryEnvironmentGenerator(MemoryBackingStore);
impl MemoryEnvironmentGenerator {
    fn get_env(&mut self, epoch: StacksEpochId) -> OwnedEnvironment<'_, '_> {
        let mut db = self.0.as_clarity_db();
        db.begin();
        db.set_clarity_epoch_version(epoch).unwrap();
        db.commit().unwrap();
        if epoch.clarity_uses_tip_burn_block() {
            db.begin();
            db.set_tenure_height(1).unwrap();
            db.commit().unwrap();
        }
        if epoch.uses_marfed_block_time() {
            db.begin();
            db.setup_block_metadata(Some(1)).unwrap();
            db.commit().unwrap();
        }
        let mut owned_env = OwnedEnvironment::new(db, epoch);
        // start an initial transaction.
        owned_env.begin();
        owned_env
    }
}

pub struct TopLevelMemoryEnvironmentGenerator(MemoryBackingStore);
impl TopLevelMemoryEnvironmentGenerator {
    pub fn get_env(&mut self, epoch: StacksEpochId) -> OwnedEnvironment<'_, '_> {
        let mut db = self.0.as_clarity_db();
        db.begin();
        db.set_clarity_epoch_version(epoch).unwrap();
        db.commit().unwrap();
        if epoch.clarity_uses_tip_burn_block() {
            db.begin();
            db.set_tenure_height(1).unwrap();
            db.commit().unwrap();
        }
        if epoch.uses_marfed_block_time() {
            db.begin();
            db.setup_block_metadata(Some(1)).unwrap();
            db.commit().unwrap();
        }
        OwnedEnvironment::new(db, epoch)
    }
}

/// Determine whether or not to use the testnet or mainnet chain ID, given whether or not the
/// caller expects to use mainnet or testnet.
///
/// WARNING TO THE READER:  This is *test-only* code.  The existence of this method does *not*
/// imply that there is a canonical, supported way to convert a `bool` into a chain ID.  The fact
/// that Stacks has a separate chain ID for its testnet (0x80000000) is an accident.  In general, a
/// Stacks blockchain instance only needs _one_ chain ID, and can use the mainnet/testnet field in
/// its transactions to determine whether or not a transaction should be mined in a given chain.
/// Going forward, you should *never* use a different chain ID for your testnet.
///
/// So, do *not* refactor this code to use this conversion in production.
pub fn test_only_mainnet_to_chain_id(mainnet: bool) -> u32 {
    // seriously -- don't even think about it.
    if mainnet {
        CHAIN_ID_MAINNET
    } else {
        CHAIN_ID_TESTNET
    }
}
