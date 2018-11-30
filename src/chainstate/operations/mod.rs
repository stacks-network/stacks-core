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

pub mod announce;
pub mod nameimport;
pub mod namepreorder;
pub mod nameregistration;
pub mod namerenewal;
pub mod namerevoke;
pub mod namespacepreorder;
pub mod namespaceready;
pub mod namespacereveal;
pub mod nametransfer;
pub mod nameupdate;
pub mod tokentransfer;

use std::fmt;
use std::error;

use burnchains::{BurnchainTransaction, PublicKey, Txid, Hash160, ConsensusHash};
use chainstate::db::namedb;

use burnchains::bitcoin::keys::BitcoinPublicKey;
use burnchains::bitcoin::address::{BitcoinAddressType, BitcoinAddress};

use util::hash::to_hex;

use self::announce::AnnounceOp;
use self::nameimport::NameImportOp;
use self::namepreorder::NamePreorderOp;
use self::nameregistration::NameRegistrationOp;
use self::namerenewal::NameRenewalOp;
use self::namerevoke::NameRevokeOp;
use self::namespacepreorder::NamespacePreorderOp;
use self::namespaceready::NamespaceReadyOp;
use self::namespacereveal::NamespaceRevealOp;
use self::nametransfer::NameTransferOp;
use self::nameupdate::NameUpdateOp;
use self::tokentransfer::TokenTransferOp;

#[derive(Debug)]
pub enum Error {
    /// Not implemented 
    NotImplemented,
    /// Failed to parse the operation from the burnchain transaction
    ParseError,
    /// Did not recognize the opcode 
    UnrecognizedOpcode
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::NotImplemented => f.write_str(error::Error::description(self)),
            Error::ParseError => f.write_str(error::Error::description(self)),
            Error::UnrecognizedOpcode => f.write_str(error::Error::description(self))
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::NotImplemented => None,
            Error::ParseError => None,
            Error::UnrecognizedOpcode => None
        }
    }

    fn description(&self) -> &str {
        match *self {
            Error::NotImplemented => "Not implemented",
            Error::ParseError => "Failed to parse transaction into Blockstack operation",
            Error::UnrecognizedOpcode => "Unrecognized opcode"
        }
    }
}

#[derive(Debug)]
pub enum BlockstackOperationType {
    Announce(AnnounceOp),
    NameImport(NameImportOp),
    NamePreorder(NamePreorderOp),
    NameRegistration(NameRegistrationOp),
    NameRenewal(NameRenewalOp),
    NameRevoke(NameRevokeOp),
    NamespacePreorder(NamespacePreorderOp),
    NamespaceReveal(NamespaceRevealOp),
    NamespaceReady(NamespaceReadyOp),
    NameTransfer(NameTransferOp),
    NameUpdate(NameUpdateOp),
    TokenTransfer(TokenTransferOp),
}

#[derive(Debug)]
pub struct Opcode(u8);

impl fmt::Display for BlockstackOperationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BlockstackOperationType::Announce(ref announce) => fmt::Display::fmt(&format!("{:?}", announce), f),
            BlockstackOperationType::NameImport(ref name_import) => fmt::Display::fmt(&format!("{:?}", name_import), f),
            BlockstackOperationType::NamePreorder(ref name_preorder) => fmt::Display::fmt(&format!("{:?}", name_preorder), f),
            BlockstackOperationType::NameRegistration(ref name_registration) => fmt::Display::fmt(&format!("{:?}", name_registration), f),
            BlockstackOperationType::NameRenewal(ref name_renewal) => fmt::Display::fmt(&format!("{:?}", name_renewal), f),
            BlockstackOperationType::NameRevoke(ref name_revoke) => fmt::Display::fmt(&format!("{:?}", name_revoke), f),
            BlockstackOperationType::NamespacePreorder(ref namespace_preorder) => fmt::Display::fmt(&format!("{:?}", namespace_preorder), f),
            BlockstackOperationType::NamespaceReveal(ref namespace_reveal) => fmt::Display::fmt(&format!("{:?}", namespace_reveal), f),
            BlockstackOperationType::NamespaceReady(ref namespace_ready) => fmt::Display::fmt(&format!("{:?}", namespace_ready), f),
            BlockstackOperationType::NameTransfer(ref name_transfer) => fmt::Display::fmt(&format!("{:?}", name_transfer), f),
            BlockstackOperationType::NameUpdate(ref name_update) => fmt::Display::fmt(&format!("{:?}", name_update), f),
            BlockstackOperationType::TokenTransfer(ref token_transfer) => fmt::Display::fmt(&format!("{:?}", token_transfer), f),
        }
    }
}

pub trait BlockstackOperation {
    fn check(&self, db: &namedb::NameDB, block_height: u64, checked_block_ops: &Vec<BlockstackOperationType>) -> bool;
    fn consensus_serialize(&self) -> Vec<u8>;
}

// consensus serializations for the types that make up a BlockstackOperation 
pub trait ConsensusField {
    fn consensus_serialize(&self) -> Vec<u8>;
}

impl ConsensusField for u8 {
    fn consensus_serialize(&self) -> Vec<u8> {
        let fmtstr = format!("{}", self);
        return format!("{}:{}", fmtstr.len(), fmtstr).into_bytes();
    }
}

impl ConsensusField for u64 {
    fn consensus_serialize(&self) -> Vec<u8> {
        let fmtstr = format!("{}", self);
        return format!("{}:{}", fmtstr.len(), fmtstr).into_bytes();
    }
}

impl ConsensusField for Opcode {
    fn consensus_serialize(&self) -> Vec<u8> {
        let fmtstr = format!("{}", self.0 as char);
        return fmtstr.into_bytes();
    }
}

impl ConsensusField for Txid {
    fn consensus_serialize(&self) -> Vec<u8> {
        let hexstr = to_hex(self.as_bytes());
        let fmtstr = format!("{}:{}", hexstr.len(), hexstr);
        return fmtstr.into_bytes();
    }
}

impl ConsensusField for ConsensusHash {
    fn consensus_serialize(&self) -> Vec<u8> {
        let hexstr = to_hex(self.as_bytes());
        let fmtstr = format!("{}:{}", hexstr.len(), hexstr);
        return fmtstr.into_bytes();
    }
}

impl ConsensusField for BitcoinAddress {
    fn consensus_serialize(&self) -> Vec<u8> {
        let b58addr = self.to_b58();
        let fmtstr = format!("{}:{}", b58addr.len(), b58addr);
        return fmtstr.into_bytes();
    }
}
