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

use chainstate::stacks::TransactionAuth;
use chainstate::stacks::StacksPublicKey;
use net::StacksPublicKeyBuffer;
use net::MessageSignature;

impl StacksMessageCodec for TransactionAuth {
    fn serialize(&self) -> Vec<u8> {
        let mut res = vec![];
        let public_key_buffers : Vec<StacksPublicKeyBuffer> = self.public_keys
            .iter()
            .map(|pubk| StacksPublicKeyBuffer::from_public_key(&pubk))
            .collect();

        write_next(&mut res, &self.nonce);
        write_next(&mut res, &public_key_buffers);
        write_next(&mut res, &self.signatures);
        write_next(&mut res, &self.signatures_required);
        res
    }

    fn deserialize(buf: &Vec<u8>, index: &mut u32, max_size: u32) -> Result<TransactionAuth, net_error> {
        let nonce : u64                                     = read_next(buf, index, max_size)?;
        let public_key_buffers: Vec<StacksPublicKeyBuffer>  = read_next(buf, index, max_size)?;
        let signatures: Vec<MessageSignature>               = read_next(buf, index, max_size)?;
        let signatures_required: u16                        = read_next(buf, index, max_size)?;

        // attempt to parse all public keys
        let mut public_keys = vec![];
        for pubkey_buf in &public_key_buffers {
            let pubk = pubkey_buf.to_public_key()?;
            public_keys.push(pubk);
        }

        Ok(TransactionAuth {
            nonce,
            public_keys,
            signatures,
            signatures_required
        })
    }
}
