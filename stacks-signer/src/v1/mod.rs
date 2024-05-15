// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
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

use libsigner::v1::messages::SignerMessage;

use crate::v1::signer::Signer;

/// The coordinator selector for the signer
pub mod coordinator;
/// The signer module for processing events
pub mod signer;
/// The stackerdb module for sending messages between signers and miners
pub mod stackerdb_manager;

/// A v1 spawned signer
pub type SpawnedSigner = crate::SpawnedSigner<Signer, SignerMessage>;
