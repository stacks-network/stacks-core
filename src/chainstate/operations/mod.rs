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

pub mod leader_key_register;
pub mod leader_block_commit;
pub mod user_burn_support;

use std::fmt;
use std::error;

use self::leader_key_register::LeaderKeyRegisterOp;
use self::leader_block_commit::LeaderBlockCommitOp;
use self::user_burn_support::UserBurnSupportOp;

use burnchains::{BurnchainTransaction, PublicKey, Txid, Hash160};
use chainstate::db::burndb;

use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::address::{BitcoinAddressType, BitcoinAddress};

use util::hash::to_hex;

#[derive(Debug)]
pub enum Error {
    /// Not implemented 
    NotImplemented,
    /// Failed to parse the operation from the burnchain transaction
    ParseError,
    /// Did not recognize the opcode 
    UnrecognizedOpcode,
    /// Invalid input data
    InvalidInput
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotImplemented => f.write_str(error::Error::description(self)),
            Error::ParseError => f.write_str(error::Error::description(self)),
            Error::UnrecognizedOpcode => f.write_str(error::Error::description(self)),
            Error::InvalidInput => f.write_str(error::Error::description(self)),
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::NotImplemented => None,
            Error::ParseError => None,
            Error::UnrecognizedOpcode => None,
            Error::InvalidInput => None,
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::NotImplemented => "Not implemented",
            Error::ParseError => "Failed to parse transaction into Blockstack operation",
            Error::UnrecognizedOpcode => "Unrecognized opcode",
            Error::InvalidInput => "Invalid input",
        }
    }
}

#[derive(Debug)]
pub enum BlockstackOperationType {
    LeaderKeyRegister(LeaderKeyRegisterOp<BitcoinAddress>),
    LeaderBlockCommit(LeaderBlockCommitOp<BitcoinPublicKey>),
    UserBurnSupport(UserBurnSupportOp)
}

impl fmt::Display for BlockstackOperationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BlockstackOperationType::LeaderKeyRegister(ref leader_key_register) => fmt::Display::fmt(&format!("{:?}", leader_key_register), f),
            BlockstackOperationType::LeaderBlockCommit(ref leader_block_commit) => fmt::Display::fmt(&format!("{:?}", leader_block_commit), f),
            BlockstackOperationType::UserBurnSupport(ref user_burn_support) => fmt::Display::fmt(&format!("{:?}", user_burn_support), f)
        }
    }
}

pub trait BlockstackOperation {
    fn check(&self, db: &burndb::BurnDB, block_height: u64, checked_block_ops: &Vec<BlockstackOperationType>) -> bool;
    fn consensus_serialize(&self) -> Vec<u8>;
}
