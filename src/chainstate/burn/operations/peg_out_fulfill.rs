use clarity::codec::StacksMessageCodec;

use crate::burnchains::BurnchainBlockHeader;
use crate::burnchains::BurnchainTransaction;
use crate::chainstate::burn::Opcodes;
use crate::types::chainstate::StacksAddress;
use crate::types::Address;

use crate::chainstate::burn::operations::Error as OpError;
use crate::chainstate::burn::operations::PegOutFulfillOp;

impl PegOutFulfillOp {
    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
    ) -> Result<Self, OpError> {
        todo!();
    }

    fn parse_data(data: &[u8]) -> Result<StacksAddress, ParseError> {
        todo!();
    }

    pub fn check(&self) -> Result<(), OpError> {
        todo!();
    }
}

enum ParseError {
    AddressParsing,
}

impl From<ParseError> for OpError {
    fn from(_: ParseError) -> Self {
        Self::ParseError
    }
}

#[cfg(test)]
mod tests {}
