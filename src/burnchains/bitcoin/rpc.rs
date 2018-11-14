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

use jsonrpc::client::Client as jsonrpc_client;

use burnchains::bitcoin::Error as btc_error;

// grab-bag of JSONRPC methods that we use
pub struct BitcoinRPC {
    pub client: jsonrpc_client
}

// return value for getblockcount 
#[derive(Deserialize)]
struct GetBlockCount {
    block_count: u64
}

impl BitcoinRPC {
    pub fn new(url: String, user: Option<String>, passwd: Option<String>) -> BitcoinRPC {
        BitcoinRPC {
            client: jsonrpc_client::new(url, user, passwd)
        }
    }

    pub fn getblockcount(&self) -> Result<u64, btc_error> {
        let req = self.client.build_request("getblockcount".to_owned(), vec![]);
        let res = self.client.send_request(&req)
                .and_then(|resp| resp.into_result::<GetBlockCount>());

        return match res {
            Ok(getblockcount) => {
                Ok(getblockcount.block_count)
            }
            Err(e) => {
                Err(btc_error::JSONRPCError(e))
            }
        };
    }
}
        

