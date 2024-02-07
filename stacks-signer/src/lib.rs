#![forbid(missing_docs)]
/*!
# stacks-signer: a libary for creating a Stacks compliant signer. A default implementation binary is also provided.
Usage documentation can be found in the [README](https://github.com/Trust-Machines/core-eng/stacks-signer-api/README.md).
*/

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

/// The cli module for the signer binary
pub mod cli;
/// The signer client for communicating with stackerdb/stacks nodes
pub mod client;
/// The configuration module for the signer
pub mod config;
/// The primary runloop for the signer
pub mod runloop;
/// The signer module for processing events
pub mod signer;
