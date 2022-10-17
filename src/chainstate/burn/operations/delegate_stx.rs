use std::io::{Read, Write};
use crate::chainstate::burn::operations::{
    parse_u64_from_be, parse_u128_from_be, BlockstackOperationType, PreStxOp, DelegateStxOp,
};
use crate::burnchains::{BurnchainBlockHeader, Txid};
use crate::chainstate::stacks::address::PoxAddress;
use crate::burnchains::{BurnchainTransaction};
use crate::types::chainstate::{BurnchainHeaderHash, StacksAddress};
use crate::chainstate::burn::operations::Error as op_error;
use crate::codec::{write_next, Error as codec_error, StacksMessageCodec};
use crate::chainstate::burn::Opcodes;

// CHECK
struct ParsedData {
    delegated_ustx: u128,
    until_burn_height: Option<u64>,
}

impl DelegateStxOp {
    // CHECK
    #[cfg(test)]
    pub fn new(
        sender: &StacksAddress,
        delegate_to: &StacksAddress,
        reward_addr: &Option<PoxAddress>,
        delegated_ustx: u128,
        until_burn_height: Option<u64>,
    ) -> DelegateStxOp {

        DelegateStxOp {
            sender: sender.clone(),
            delegate_to: delegate_to.clone(),
            reward_addr: reward_addr.clone(),
            delegated_ustx,
            until_burn_height,
            // to be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash([0u8; 32]),
        }
    }

    pub fn from_tx(
        block_header: &BurnchainBlockHeader,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<DelegateStxOp, op_error> {
        DelegateStxOp::parse_from_tx(
            block_header.block_height,
            &block_header.block_hash,
            tx,
            sender,
        )
    }

    fn parse_data(data: &Vec<u8>) -> Option<ParsedData> {
        /*
            Wire format:

            0      2  3                19           28
            |------|--|----------------|------------|
             magic  op delegated ustx   until burn height
                                                              

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped
        */
        // magic + op are omitted
        if data.len() < 26 {
            // too short to have required data
            warn!(
                "DELEGATE_STX payload is malformed ({} bytes)",
                data.len()
            );
            return None;
        }

        let delegated_ustx = parse_u128_from_be(&data[0..16]).unwrap();

        let until_burn_height = {
            if data[16] == 1 {
                let burn_height = parse_u64_from_be(&data[17..25]).unwrap();
                Some(burn_height)
            } else {
                None
            }
        };

        Some(ParsedData {
            delegated_ustx,
            until_burn_height, 
        })
    }

    pub fn parse_from_tx(
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        tx: &BurnchainTransaction,
        sender: &StacksAddress,
    ) -> Result<DelegateStxOp, op_error> {
        let outputs = tx.get_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if outputs.len() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::DelegateStx as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = DelegateStxOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        let output = outputs[0]
            .address
            .clone()
            .try_into_stacks_address()
            .ok_or_else(|| {
                warn!("Invalid tx: output 1 must be representable as a StacksAddress");
                op_error::InvalidInput
            })?;

        // coerce a hash mode for this address if need be, since we'll need it when we feed this
        // address into the .pox contract
        let reward_addr = if outputs.len() >= 2 {
            Some(outputs[1].address.clone().coerce_hash_mode())
        } else {
            None
        }; 
        
        Ok(DelegateStxOp {
            sender: sender.clone(),
            reward_addr: reward_addr,
            delegate_to: output, 
            delegated_ustx: data.delegated_ustx,
            until_burn_height: data.until_burn_height,
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }

    
    pub fn check(&self) -> Result<(), op_error> {
        if self.delegated_ustx == 0 {
            warn!("Invalid DelegateStxOp, must have positive ustx");
            return Err(op_error::DelegateStxMustBePositive);
        }

        Ok(())
    }
       
}

// Q_JUDE - TODO - broken
impl StacksMessageCodec for DelegateStxOp {
    /*
            Wire format:

        0      2  3                     24               40 41       50
        |------|--|---------------------|----------------|--|--------|
         magic  op  delegate to           delegated ustx  opt       until burn height
                                                          

    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::DelegateStx as u8))?;
        self.delegate_to.consensus_serialize(fd)?;
        fd.write_all(&self.delegated_ustx.to_be_bytes())
            .map_err(|e| codec_error::WriteError(e))?;
        write_next(fd, &(self.reward_addr.is_some() as u8))?;
        write_next(fd, &(self.until_burn_height.is_some() as u8))?;

        // Q-JUDE
        if let Some(height) = self.until_burn_height {
            fd.write_all(&(1 as u64).to_be_bytes())
                .map_err(|e| codec_error::WriteError(e))?;
            fd.write_all(&height.to_be_bytes())
                .map_err(|e| codec_error::WriteError(e))?;
        } else {
            fd.write_all(&(0 as u64).to_be_bytes())
                .map_err(|e| codec_error::WriteError(e))?;
        }
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<DelegateStxOp, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}


mod tests {
    use clarity::address::AddressHashMode;
    use clarity::types::chainstate::BurnchainHeaderHash;
    use stacks_common::util::hash::*;
    use crate::burnchains::BurnchainTransaction;
    use crate::burnchains::bitcoin::address::{BitcoinAddress, BitcoinAddressType};
    use crate::burnchains::bitcoin::{BitcoinInputType, BitcoinNetworkType, BitcoinTxInput, BitcoinTxOutput};
    use crate::burnchains::{Txid, bitcoin::BitcoinTransaction};
    use crate::chainstate::burn::Opcodes;
    use crate::chainstate::burn::operations::DelegateStxOp;
    use crate::types::chainstate::StacksAddress;
    use crate::chainstate::stacks::address::PoxAddress;
    use crate::chainstate::stacks::address::StacksAddressExtensions;
    
    #[test]
    fn test_parse_delegate_stx() {
        let tx = BitcoinTransaction {
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::DelegateStx as u8,
            data: vec![1; 80],
            data_amt: 0,
            inputs: vec![BitcoinTxInput {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    },
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress {
                        addrtype: BitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    },
                },
            ],
        };

        let sender = StacksAddress {
            version: 0,
            bytes: Hash160([0; 20]),
        };
        let op = DelegateStxOp::parse_from_tx(
            16843022,
            &BurnchainHeaderHash([0; 32]),
            &BurnchainTransaction::Bitcoin(tx.clone()),
            &sender,
        )
        .unwrap();

        assert_eq!(&op.sender, &sender);
        assert_eq!(
            &op.reward_addr,
            &Some(PoxAddress::Standard(
                StacksAddress::from_bitcoin_address(&tx.outputs[1].address),
                Some(AddressHashMode::SerializeP2PKH)
            ))
        );
        assert_eq!(op.delegated_ustx, u128::from_be_bytes([1; 16]));
        assert_eq!(op.delegate_to, StacksAddress::new(22, Hash160([1u8; 20])));
        assert_eq!(op.until_burn_height, Some(u64::from_be_bytes([1; 8]))); 
    }
}