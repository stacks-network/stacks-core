#![forbid(missing_docs)]
/*!
# stacks-signer: a libary for creating a Stacks compliant signer. A default implementation binary is also provided.
Usage documentation can be found in the [README](https://github.com/Trust-Machines/core-eng/stacks-signer-api/README.md).
*/
/// The cli module for the signer binary
pub mod cli;
/// The configuration module for the signer
pub mod config;
/// All crypto related modules
pub mod crypto;
/// The primary runloop for the signer
pub mod runloop;
/// The signer client for communicating with stackerdb/stacks nodes
pub mod stacks_client;
/// Util functions
pub mod utils;
