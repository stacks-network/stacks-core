/*
 copyright: (c) 2013-2019 by Blockstack PBC, a public benefit corporation.

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

use net::StacksMessageCodec;
use net::Error as net_error;
use net::codec::{read_next, write_next};

use burnchains::Txid;

use chainstate::stacks::StacksAddress;
use chainstate::stacks::TransactionAuth;
use chainstate::stacks::TransactionAnchorMode;
use chainstate::stacks::TransactionPayloadID;
use chainstate::stacks::TransactionPayload;
use chainstate::stacks::TransactionPayment;
use chainstate::stacks::TransactionSmartContract;
use chainstate::stacks::StacksTransaction;

use util::hash::DoubleSha256;

impl StacksMessageCodec for TransactionPayment {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.paid);
        write_next(&mut res, &self.recipient);
        res
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<TransactionPayment, net_error> {
        let paid : u64                  = read_next(buf, index, max_size)?;
        let recipient : StacksAddress   = read_next(buf, index, max_size)?;

        Ok(TransactionPayment {
            paid,
            recipient
        })
    }
}

impl StacksMessageCodec for TransactionSmartContract {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        write_next(&mut res, &self.code_body);
        res
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<TransactionSmartContract, net_error> {
        let code_body : Vec<u8> = read_next(buf, index, max_size)?;
        Ok(TransactionSmartContract {
            code_body
        })
    }
}

impl StacksMessageCodec for StacksTransaction {
    fn serialize(&self) -> Vec<u8> {
        let mut ret = vec![];
        let anchor_mode = self.anchor_mode;

        write_next(&mut ret, &self.version);
        write_next(&mut ret, &self.principal);
        write_next(&mut ret, &self.auth);
        write_next(&mut ret, &self.fee);
        write_next(&mut ret, &(self.anchor_mode as u8));

        // payload will be formatted as "type (u8) payload (vec<u8>)"
        let transaction_type_id : u8 = 
            match self.payload {
                TransactionPayload::Payment(ref _t) => TransactionPayloadID::Payment as u8,
                TransactionPayload::SmartContract(ref _t) => TransactionPayloadID::SmartContract as u8,
            };
        
        write_next(&mut ret, &transaction_type_id);

        match self.payload {
            TransactionPayload::Payment(ref t) => write_next(&mut ret, t),
            TransactionPayload::SmartContract(ref t) => write_next(&mut ret, t),
        };
        ret
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<StacksTransaction, net_error> {
        let version : u8                = read_next(buf, index, max_size)?;
        let principal : StacksAddress   = read_next(buf, index, max_size)?;
        let auth : TransactionAuth      = read_next(buf, index, max_size)?;
        let fee : u64                   = read_next(buf, index, max_size)?;
        let transaction_anchor_id : u8  = read_next(buf, index, max_size)?;
        let transaction_type_id : u8    = read_next(buf, index, max_size)?;

        let anchor_mode = 
            if transaction_anchor_id == (TransactionAnchorMode::OffChainOnly as u8) {
                TransactionAnchorMode::OffChainOnly
            }
            else if transaction_anchor_id == (TransactionAnchorMode::OnChainOnly as u8) {
                TransactionAnchorMode::OnChainOnly
            }
            else if transaction_anchor_id == (TransactionAnchorMode::Any as u8) {
                TransactionAnchorMode::Any
            }
            else {
                return Err(net_error::DeserializeError);
            };

        let payload = 
            if transaction_type_id == (TransactionPayloadID::Payment as u8) {
                let payload_data = TransactionPayment::deserialize(buf, index, max_size)?;
                TransactionPayload::Payment(payload_data)
            }
            else if transaction_type_id == (TransactionPayloadID::SmartContract as u8) {
                let payload_data = TransactionSmartContract::deserialize(buf, index, max_size)?;
                TransactionPayload::SmartContract(payload_data)
            }
            else {
                return Err(net_error::DeserializeError);
            };

        Ok(StacksTransaction {
            version,
            principal,
            auth,
            fee,
            anchor_mode,
            payload
        })
    }
}

impl StacksTransaction {
    /// a txid of a stacks transaction is its double-sha256 hash
    pub fn txid(&self) -> Txid {
        let bytes_vec = self.serialize();
        let h = DoubleSha256::from_data(&bytes_vec[..]);
        
        // NOTE: safe to unwrap here since a double-sha256 and a txid are both 32 bytes
        Txid::from_bytes(h.as_bytes()).unwrap()
    }
}
