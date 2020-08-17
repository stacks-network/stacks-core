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

use chainstate::stacks::StacksAddress;
use chainstate::stacks::db::StacksChainState;
use chainstate::stacks::Error;
use chainstate::stacks::StacksBlockHeader;

use burnchains::bitcoin::address::BitcoinAddress;
use burnchains::Address;
use address::AddressHashMode;

use chainstate::burn::db::sortdb::SortitionDB;

use vm::types::{
    StandardPrincipalData,
    QualifiedContractIdentifier,
    Value,
    TupleData,
    PrincipalData
};

use chainstate::stacks::StacksBlockId;

use burnchains::Burnchain;

use vm::representations::ContractName;

use util::hash::Hash160;

use std::convert::TryFrom;
use std::convert::TryInto;
use std::boxed::Box;

pub const STACKS_BOOT_CODE_CONTRACT_ADDRESS : &'static str = "ST000000000000000000002AMW42H";

pub const STACKS_BOOT_CODE : &'static [(&'static str, &'static str)] = &[
    ("pox-api", std::include_str!("pox.clar")),     // Clarity prevents us from using anything shorter than 5 characters, so 'pox' isn't an option :(
    ("lookup", std::include_str!("lockup.clar"))
];

pub fn boot_code_addr() -> StacksAddress {
    StacksAddress::from_string(&STACKS_BOOT_CODE_CONTRACT_ADDRESS.clone()).unwrap()
}    

pub fn boot_code_id(name: &str) -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::new(StandardPrincipalData::from(boot_code_addr()), ContractName::try_from(name.to_string()).unwrap())
}

/// Extract a PoX address from its tuple representation
fn tuple_to_pox_addr(tuple_data: TupleData) -> (AddressHashMode, Hash160) {
    let version_value = tuple_data.get("version").expect("FATAL: no 'version' field in pox-addr").to_owned();
    let hashbytes_value = tuple_data.get("hashbytes").expect("FATAL: no 'hashbytes' field in pox-addr").to_owned();

    let version_u8 : u8 = version_value.expect_u128().try_into().expect("FATAL: PoX version is not a supported version byte");
    let version : AddressHashMode = version_u8.try_into().expect("FATAL: PoX version is not a supported version byte");

    let hashbytes_vec = hashbytes_value.expect_buff(20);

    let mut hashbytes_20 = [0u8; 20];
    hashbytes_20.copy_from_slice(&hashbytes_vec[0..20]);
    let hashbytes = Hash160(hashbytes_20);

    (version, hashbytes)
}

impl Value {
    pub fn expect_u128(self) -> u128 {
        if let Value::UInt(inner) = self {
            inner
        }
        else {
            panic!(format!("Value '{:?}' is not a u128", &self));
        }
    }

    pub fn expect_i128(self) -> i128 {
        if let Value::Int(inner) = self {
            inner
        }
        else {
            panic!(format!("Value '{:?}' is not an i128", &self));
        }
    }

    pub fn expect_buff(self, sz: usize) -> Vec<u8> {
        if let Value::Buffer(buffdata) = self {
            if buffdata.data.len() == sz {
                buffdata.data
            }
            else {
                panic!(format!("Value buffer has len {}, expected {}", buffdata.data.len(), sz));
            }
        }
        else {
            panic!(format!("Value '{:?}' is not a buff", &self));
        }
    }

    pub fn expect_bool(self) -> bool {
        if let Value::Bool(b) = self {
            b
        }
        else {
            panic!(format!("Value '{:?}' is not a bool", &self));
        }
    }

    pub fn expect_tuple(self) -> TupleData {
        if let Value::Tuple(data) = self {
            data
        }
        else {
            panic!(format!("Value '{:?}' is not a tuple", &self));
        }
    }

    pub fn expect_optional(self) -> Option<Value> {
        if let Value::Optional(opt) = self {
            match opt.data {
                Some(boxed_value) => Some(*boxed_value),
                None => None
            }
        }
        else {
            panic!(format!("Value '{:?}' is not an optional", &self));
        }
    }

    pub fn expect_principal(self) -> PrincipalData {
        if let Value::Principal(p) = self {
            p
        }
        else {
            panic!(format!("Value '{:?}' is not a principal", &self));
        }
    }

    pub fn expect_result(self) -> Result<Value, Value> {
        if let Value::Response(res_data) = self {
            if res_data.committed {
                Ok(*res_data.data)
            }
            else {
                Err(*res_data.data)
            }
        }
        else {
            panic!("FATAL: not a response");
        }
    }
    
    pub fn expect_result_ok(self) -> Value {
        if let Value::Response(res_data) = self {
            if res_data.committed {
                *res_data.data
            }
            else {
                panic!("FATAL: not a (ok ..)");
            }
        }
        else {
            panic!("FATAL: not a response");
        }
    }

    pub fn expect_result_err(self) -> Value {
        if let Value::Response(res_data) = self {
            if !res_data.committed {
                *res_data.data
            }
            else {
                panic!("FATAL: not a (err ..)");
            }
        }
        else {
            panic!("FATAL: not a response");
        }
    }
}

impl StacksChainState {
    fn eval_boot_code_read_only(&mut self, sortdb: &SortitionDB, stacks_block_id: &StacksBlockId, boot_contract_name: &str, code: &str) -> Result<Value, Error> {
        let iconn = sortdb.index_conn();
        self.clarity_eval_read_only_checked(&iconn, &stacks_block_id, &boot_code_id(boot_contract_name), code)
    }

    /// Determine which reward cycle this particular block lives in.
    pub fn get_reward_cycle(&mut self, burnchain: &Burnchain, block_id: &StacksBlockId) -> Result<u128, Error> {
        let parent_block_id = StacksChainState::get_parent_block_id(&self.headers_db, block_id)?
            .ok_or(Error::PoxNoRewardCycle)?;

        let parent_header_info = StacksChainState::get_stacks_block_header_info_by_index_block_hash(&self.headers_db, &parent_block_id)?
            .ok_or(Error::PoxNoRewardCycle)?;

        // NOTE: the parent's burn block height is what's exposed as burn-block-height in the VM
        Ok((((parent_header_info.burn_header_height as u64) - burnchain.first_block_height) / burnchain.reward_cycle_period) as u128)
    }

    /// Determine the minimum amount of STX per reward address required to stack
    #[cfg(test)]
    pub fn get_stacking_minimum(&mut self, sortdb: &SortitionDB, stacks_block_id: &StacksBlockId) -> Result<u128, Error> {
        self.eval_boot_code_read_only(sortdb, stacks_block_id, "pox-api", &format!("(at-block 0x{} (get-stacking-minimum))", &stacks_block_id))
            .map(|value| value.expect_u128())
    }
    
    /// Determine how many uSTX are stacked in a given reward cycle
    #[cfg(test)]
    pub fn get_total_ustx_stacked(&mut self, sortdb: &SortitionDB, stacks_block_id: &StacksBlockId, reward_cycle: u128) -> Result<u128, Error> {
        self.eval_boot_code_read_only(sortdb, stacks_block_id, "pox-api", &format!("(at-block 0x{} (get-total-ustx-stacked u{}))", &stacks_block_id, reward_cycle))
            .map(|value| value.expect_u128())
    }

    /// List all PoX addresses and amount of uSTX stacked, at a particular block.
    /// Each address will have at least (get-stacking-minimum) tokens.
    pub fn get_reward_addresses(&mut self, burnchain: &Burnchain, sortdb: &SortitionDB, block_id: &StacksBlockId) -> Result<Vec<((AddressHashMode, Hash160), u128)>, Error> {
        let reward_cycle = self.get_reward_cycle(burnchain, block_id)?;

        // how many in this cycle?
        let num_addrs = self.eval_boot_code_read_only(sortdb, block_id, "pox-api", &format!("(get-reward-set-size u{})", reward_cycle))?
            .expect_u128();

        debug!("At block {:?} (reward cycle {}): {} PoX reward addresses", block_id, reward_cycle, num_addrs);

        let mut ret = vec![];
        for i in 0..num_addrs {
            // value should be (optional (tuple (pox-addr (tuple (...))) (total-ustx uint))).
            // Get the tuple.
            let tuple_data = self.eval_boot_code_read_only(sortdb, block_id, "pox-api", &format!("(get-reward-set-pox-address u{} u{})", reward_cycle, i))?
                .expect_optional()
                .expect(&format!("FATAL: missing PoX address in slot {} out of {} in reward cycle {}", i, num_addrs, reward_cycle))
                .expect_tuple();

            let pox_addr_tuple = tuple_data
                .get("pox-addr")
                .expect(&format!("FATAL: no 'pox-addr' in return value from (get-reward-set-pox-address u{} u{})", reward_cycle, i))
                .to_owned()
                .expect_tuple();

            let pox_addr = tuple_to_pox_addr(pox_addr_tuple);

            let total_ustx = tuple_data
                .get("total-ustx")
                .expect(&format!("FATAL: no 'total-ustx' in return value from (get-reward-set-pox-address u{} u{})", reward_cycle, i))
                .to_owned()
                .expect_u128();

            ret.push((pox_addr, total_ustx));
        }

        Ok(ret)
    }
}

#[cfg(test)]
pub mod test {
    use chainstate::stacks::Error as chainstate_error;
    use chainstate::stacks::db::*;
    use chainstate::stacks::db::test::*;
    use chainstate::stacks::*;
    use chainstate::burn::*;
    use chainstate::burn::db::*;
    use chainstate::burn::db::sortdb::*;
    use chainstate::stacks::miner::*;
    use chainstate::stacks::miner::test::*;
   
    use burnchains::Address;
    use burnchains::PublicKey;

    use super::*;

    use net::test::*;
    
    use util::*;

    use vm::types::*;
    
    use std::fs;
    use std::convert::From;

    use util::hash::to_hex;

    fn key_to_stacks_addr(key: &StacksPrivateKey) -> StacksAddress {
        StacksAddress::from_public_keys(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, &AddressHashMode::SerializeP2PKH, 1, &vec![StacksPublicKey::from_private(key)]).unwrap()
    }
    
    fn instantiate_pox_peer(burnchain: &Burnchain, test_name: &str, port: u16) -> (TestPeer, Vec<StacksPrivateKey>) {
        let mut peer_config = TestPeerConfig::new(test_name, port, port + 1);
        peer_config.burnchain = burnchain.clone();
        peer_config.setup_code = format!("(contract-call? .pox-api set-burnchain-parameters u{} u{} u{})", burnchain.first_block_height, burnchain.registration_period, burnchain.reward_cycle_period);

        test_debug!("Setup code: '{}'", &peer_config.setup_code);

        let keys = [
            StacksPrivateKey::from_hex("7e3ee1f2a0ae11b785a1f0e725a9b3ab0a5fd6cc057d43763b0a85f256fdec5d01").unwrap(),
            StacksPrivateKey::from_hex("11d055ac8b0ab4f04c5eb5ea4b4def9c60ae338355d81c9411b27b4f49da2a8301").unwrap(),
            StacksPrivateKey::from_hex("00eed368626b96e482944e02cc136979973367491ea923efb57c482933dd7c0b01").unwrap(),
            StacksPrivateKey::from_hex("00380ff3c05350ee313f60f30313acb4b5fc21e50db4151bf0de4cd565eb823101").unwrap()
        ];

        let addrs : Vec<StacksAddress> = keys
            .iter()
            .map(|ref pk| key_to_stacks_addr(pk))
            .collect();

        let balances : Vec<(PrincipalData, u64)> = addrs
            .clone()
            .into_iter()
            .map(|addr| (addr.into(), 1024 * 1000000))
            .collect();

        peer_config.initial_balances = balances;
        let peer = TestPeer::new(peer_config);

        (peer, keys.to_vec())
    }

    fn eval_at_tip(peer: &mut TestPeer, boot_contract: &str, expr: &str) -> Value {
        let sortdb = peer.sortdb.take().unwrap();
        let (consensus_hash, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
        let stacks_block_id = StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_bhh);
        let iconn = sortdb.index_conn();
        let value = peer.chainstate().clarity_eval_read_only(&iconn, &stacks_block_id, &boot_code_id(boot_contract), expr);
        peer.sortdb = Some(sortdb);
        value
    }

    fn contract_id(addr: &StacksAddress, name: &str) -> QualifiedContractIdentifier {
        QualifiedContractIdentifier::new(StandardPrincipalData::from(addr.clone()), ContractName::try_from(name.to_string()).unwrap())
    }

    fn eval_contract_at_tip(peer: &mut TestPeer, addr: &StacksAddress, name: &str, expr: &str) -> Value {
        let sortdb = peer.sortdb.take().unwrap();
        let (consensus_hash, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
        let stacks_block_id = StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_bhh);
        let iconn = sortdb.index_conn();
        let value = peer.chainstate().clarity_eval_read_only(&iconn, &stacks_block_id, &contract_id(addr, name), expr);
        peer.sortdb = Some(sortdb);
        value
    }
    
    fn get_liquid_ustx(peer: &mut TestPeer) -> u128 {
        let value = eval_at_tip(peer, "pox-api", "total-liquid-ustx");
        if let Value::UInt(inner_uint) = value {
            return inner_uint;
        }
        else {
            panic!("total-liquid-ustx isn't a uint");
        }
    }

    fn get_balance(peer: &mut TestPeer, addr: &StacksAddress) -> u128 {
        let value = eval_at_tip(peer, "pox-api", &format!("(stx-get-balance '{})", addr.to_string()));
        if let Value::UInt(balance) = value {
            return balance;
        }
        else {
            panic!("stx-get-balance isn't a uint");
        }
    }

    fn get_stacker_info(peer: &mut TestPeer, addr: &StacksAddress) -> Option<(u128, (AddressHashMode, Hash160), u128, u128, Option<PrincipalData>)> {
        let value_opt = eval_at_tip(peer, "pox-api", &format!("(get-stacker-info '{})", addr.to_string()));
        let data = 
            if let Some(d) = value_opt.expect_optional() {
                d
            }
            else {
                return None
            };

        let data = data.expect_tuple();

        let amount_ustx = data.get("amount-ustx").unwrap().to_owned().expect_u128();
        let pox_addr = tuple_to_pox_addr(data.get("pox-addr").unwrap().to_owned().expect_tuple());
        let lock_period = data.get("lock-period").unwrap().to_owned().expect_u128();
        let first_reward_cycle = data.get("first-reward-cycle").unwrap().to_owned().expect_u128();
        let delegate_opt = data.get("delegate").unwrap().to_owned().expect_optional().map(|v| v.expect_principal());

        Some((amount_ustx, pox_addr, lock_period, first_reward_cycle, delegate_opt))
    }

    fn with_sortdb<F, R>(peer: &mut TestPeer, todo: F) -> R
    where
        F: FnOnce(&mut StacksChainState, &SortitionDB) -> R
    {
        let sortdb = peer.sortdb.take().unwrap();
        let r = todo(peer.chainstate(), &sortdb);
        peer.sortdb = Some(sortdb);
        r
    }

    fn make_pox_addr(addr_version: AddressHashMode, addr_bytes: Hash160) -> Value {
        Value::Tuple(TupleData::from_data(vec![
            (ClarityName::try_from("version".to_owned()).unwrap(), Value::UInt((addr_version as u8) as u128)),
            (ClarityName::try_from("hashbytes".to_owned()).unwrap(), Value::Buffer(BuffData { data: addr_bytes.as_bytes().to_vec() }))
        ]).unwrap())
    }

    fn make_pox_lockup(key: &StacksPrivateKey, nonce: u64, amount: u128, addr_version: AddressHashMode, addr_bytes: Hash160, lock_period: u128) -> StacksTransaction {
        // (define-public (stack-stx (amount-ustx uint)
        //                           (pox-addr (tuple (version uint) (hashbytes (buff 20))))
        //                           (lock-period uint))
        
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut pox_lockup = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                                    TransactionPayload::new_contract_call(boot_code_addr(),
                                                                                         "pox-api",
                                                                                         "stack-stx",
                                                                                         vec![
                                                                                            Value::UInt(amount),
                                                                                            make_pox_addr(addr_version, addr_bytes),
                                                                                            Value::UInt(lock_period)
                                                                                         ]).unwrap());
        pox_lockup.chain_id = 0x80000000;
        pox_lockup.auth.set_origin_nonce(nonce);
        pox_lockup.set_post_condition_mode(TransactionPostConditionMode::Allow);
        pox_lockup.set_fee_rate(0);

        let mut tx_signer = StacksTransactionSigner::new(&pox_lockup);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }

    fn make_bare_contract(key: &StacksPrivateKey, nonce: u64, name: &str, code: &str) -> StacksTransaction {
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut bare_code = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                                   TransactionPayload::new_smart_contract(&name.to_string(), &code.to_string()).unwrap());
        bare_code.chain_id = 0x80000000;
        bare_code.auth.set_origin_nonce(nonce);
        bare_code.set_post_condition_mode(TransactionPostConditionMode::Allow);
        bare_code.set_fee_rate(0);

        let mut tx_signer = StacksTransactionSigner::new(&bare_code);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }
    
    fn make_register_delegate(key: &StacksPrivateKey, nonce: u64, 
                              addr_version: AddressHashMode, addr_bytes: Hash160, 
                              tenure_burn_block_begin: u128, 
                              tenure_reward_cycles: u128) -> StacksTransaction {
        // (define-public (register-delegate (pox-addr (tuple (version uint) (hashbytes (buff 20))))
        //                                   (tenure-burn-block-begin uint)
        //                                   (tenure-reward-cycles uint)))
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut register_delegate = StacksTransaction::new(
                                        TransactionVersion::Testnet, auth,
                                        TransactionPayload::new_contract_call(boot_code_addr(),
                                                                             "pox-api",
                                                                             "register-delegate",
                                                                             vec![
                                                                                make_pox_addr(addr_version, addr_bytes),
                                                                                Value::UInt(tenure_burn_block_begin),
                                                                                Value::UInt(tenure_reward_cycles),
                                                                             ]).unwrap());
        register_delegate.chain_id = 0x80000000;
        register_delegate.auth.set_origin_nonce(nonce);
        register_delegate.set_post_condition_mode(TransactionPostConditionMode::Deny);
        register_delegate.set_fee_rate(0);

        let mut tx_signer = StacksTransactionSigner::new(&register_delegate);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }

    fn make_delegate_stx(key: &StacksPrivateKey, nonce: u64, delegate: &StacksAddress, amount: u128) -> StacksTransaction {
        // (define-public (delegate-stx (delegate principal)
        //                              (amount-ustx uint))
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        
        let mut delegate_stx = StacksTransaction::new(
                                        TransactionVersion::Testnet, auth,
                                        TransactionPayload::new_contract_call(boot_code_addr(),
                                                                             "pox-api",
                                                                             "delegate-stx",
                                                                             vec![
                                                                                Value::Principal(PrincipalData::Standard(StandardPrincipalData::from(delegate.clone()))),
                                                                                Value::UInt(amount)
                                                                             ]).unwrap());
        delegate_stx.chain_id = 0x80000000;
        delegate_stx.auth.set_origin_nonce(nonce);
        delegate_stx.set_post_condition_mode(TransactionPostConditionMode::Allow);
        delegate_stx.set_fee_rate(0);

        let mut tx_signer = StacksTransactionSigner::new(&delegate_stx);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }
    
    fn make_delegate(key: &StacksPrivateKey, nonce: u64) -> StacksTransaction {
        // (define-public (delegate-stack-stx))
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        
        let mut delegate = StacksTransaction::new(
                                        TransactionVersion::Testnet, auth,
                                        TransactionPayload::new_contract_call(boot_code_addr(),
                                                                             "pox-api",
                                                                             "delegate-stack-stx",
                                                                             vec![]).unwrap());

        delegate.chain_id = 0x80000000;
        delegate.auth.set_origin_nonce(nonce);
        delegate.set_post_condition_mode(TransactionPostConditionMode::Allow);
        delegate.set_fee_rate(0);

        let mut tx_signer = StacksTransactionSigner::new(&delegate);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }
    
    fn get_parent_tip(parent_opt: &Option<&StacksBlock>, chainstate: &StacksChainState, sortdb: &SortitionDB) -> StacksHeaderInfo {
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        let parent_tip = match parent_opt {
            None => {
                StacksChainState::get_genesis_header_info(&chainstate.headers_db).unwrap()
            }
            Some(block) => {
                let ic = sortdb.index_conn();
                let snapshot = SortitionDB::get_block_snapshot_for_winning_stacks_block(&ic, &tip.sortition_id, &block.block_hash()).unwrap().unwrap();      // succeeds because we don't fork
                StacksChainState::get_anchored_block_header_info(&chainstate.headers_db, &snapshot.consensus_hash, &snapshot.winning_stacks_block_hash).unwrap().unwrap()
            }
        };
        parent_tip
    }

    #[test]
    fn test_liquid_ustx() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.reward_cycle_period = 5;
        burnchain.registration_period = 2;

        let (mut peer, keys) = instantiate_pox_peer(&burnchain, "test-liquid-ustx", 6000);

        let num_blocks = 10;
        let mut expected_liquid_ustx = 1024 * 1000000 * (keys.len() as u128); 

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let block_txs = vec![
                    coinbase_tx
                ];

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
            
            let liquid_ustx = get_liquid_ustx(&mut peer);
            assert_eq!(liquid_ustx, expected_liquid_ustx);

            if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW) as usize {
                // add mature coinbases
                expected_liquid_ustx += 500 * 1000000;
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_single_tx_sender() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.reward_cycle_period = 5;
        burnchain.registration_period = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-single-tx-sender", 6002);

        let num_blocks = 10;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut alice_reward_cycle = 0;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![
                    coinbase_tx
                ];

                if tenure_id == 1 {
                    // Alice locks up exactly 25% of the liquid STX supply, so this should succeed.
                    let alice_lockup = make_pox_lockup(&alice, 0, 1024 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 12);
                    block_txs.push(alice_lockup);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());

            if tenure_id <= 1 {
                if tenure_id < 1 {
                    // Alice has not locked up STX
                    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                    assert_eq!(alice_balance, 1024 * 1000000);
                }

                // stacking minimum should be floor(total-liquid-ustx / 20000)
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                assert_eq!(min_ustx, total_liquid_ustx / 20000);

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                alice_reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                eprintln!("\nalice reward cycle: {}\ncur reward cycle: {}\n", alice_reward_cycle, cur_reward_cycle);
            }
            else {
                // Alice's address is locked as of the next reward cycle
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                // Alice has locked up STX no matter what
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 0);
                
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)).unwrap();
                
                eprintln!("\ntenure: {}\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);

                if cur_reward_cycle >= alice_reward_cycle {
                    // this will grow as more miner rewards are unlocked, so be wary
                    if tenure_id >= 8 {
                        // miner rewards increased liquid supply, so less than 25% is locked.
                        // minimum participation decreases.
                        assert!(total_liquid_ustx > 4 * 1024 * 1000000);
                        assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    }
                    else {
                        // still at 25% or more locked
                        assert!(total_liquid_ustx <= 4 * 1024 * 1000000);
                        assert!(min_ustx >= total_liquid_ustx / 5000);
                    }

                    let (amount_ustx, pox_addr, lock_period, first_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice)).unwrap();
                    eprintln!("\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);
                    
                    // one reward address, and it's Alice's
                    // either way, there's a single reward address
                    assert_eq!(reward_addrs.len(), 1);
                    assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                    assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                    assert_eq!(reward_addrs[0].1, 1024 * 1000000);
                }
                else {
                    // no reward addresses
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    assert_eq!(reward_addrs.len(), 0);
                }
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_multi_tx_sender() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.reward_cycle_period = 5;
        burnchain.registration_period = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-multi-tx-sender", 6004);

        let num_blocks = 10;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut first_reward_cycle = 0;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![
                    coinbase_tx
                ];

                if tenure_id == 1 {
                    // Alice locks up exactly 25% of the liquid STX supply, so this should succeed.
                    let alice_lockup = make_pox_lockup(&alice, 0, 1024 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 12);
                    block_txs.push(alice_lockup);
                    
                    // Bob locks up 20% of the liquid STX supply, so this should succeed
                    let bob_lockup = make_pox_lockup(&bob, 0, (4 * 1024 * 1000000) / 5, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&bob).bytes, 12);
                    block_txs.push(bob_lockup);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());

            if tenure_id <= 1 {
                if tenure_id < 1 {
                    // Alice has not locked up STX
                    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                    assert_eq!(alice_balance, 1024 * 1000000);
                    
                    // Bob has not locked up STX
                    let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob));
                    assert_eq!(bob_balance, 1024 * 1000000);
                }

                // stacking minimum should be floor(total-liquid-ustx / 20000)
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                assert_eq!(min_ustx, total_liquid_ustx / 20000);

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                first_reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                eprintln!("\nalice reward cycle: {}\ncur reward cycle: {}\n", first_reward_cycle, cur_reward_cycle);
            }
            else {
                // Alice's and Bob's addresses are locked as of the next reward cycle
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                // Alice and Bob have locked up STX no matter what
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 0);
                
                let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob));
                assert_eq!(bob_balance, 1024 * 1000000 - (4 * 1024 * 1000000) / 5);
                
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                
                eprintln!("\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\n", cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx);

                if cur_reward_cycle >= first_reward_cycle {
                    // this will grow as more miner rewards are unlocked, so be wary
                    if tenure_id >= 8 {
                        // miner rewards increased liquid supply, so less than 25% is locked.
                        // minimum participation decreases.
                        assert!(total_liquid_ustx > 4 * 1024 * 1000000);
                    }
                    else {
                        // still at 25% or more locked
                        assert!(total_liquid_ustx <= 4 * 1024 * 1000000);
                    }
                    
                    // well over 25% locked, so this is always true
                    assert_eq!(min_ustx, total_liquid_ustx / 5000);

                    // two reward addresses, and they're Alice's and Bob's.
                    // They are present in insertion order
                    assert_eq!(reward_addrs.len(), 2);
                    assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                    assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                    assert_eq!(reward_addrs[0].1, 1024 * 1000000);
                    
                    assert_eq!((reward_addrs[1].0).0, AddressHashMode::SerializeP2PKH);
                    assert_eq!((reward_addrs[1].0).1, key_to_stacks_addr(&bob).bytes);
                    assert_eq!(reward_addrs[1].1, (4 * 1024 * 1000000) / 5);
                }
                else {
                    // no reward addresses
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    assert_eq!(reward_addrs.len(), 0);
                }
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_no_double_stacking() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.reward_cycle_period = 5;
        burnchain.registration_period = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-no-double-stacking", 6006);

        let num_blocks = 3;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut first_reward_cycle = 0;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![
                    coinbase_tx
                ];

                if tenure_id == 1 {
                    // Alice locks up exactly 12.5% of the liquid STX supply, twice.
                    // Only the first one succeeds.
                    let alice_lockup_1 = make_pox_lockup(&alice, 0, 1024 * 1000000 / 2, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 12);
                    block_txs.push(alice_lockup_1);
                   
                    // will be rejected
                    let alice_lockup_2 = make_pox_lockup(&alice, 1, 1024 * 1000000 / 4, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 12);
                    block_txs.push(alice_lockup_2);
                }
                if tenure_id == 2 {
                    // should fail -- Alice's PoX address is already in use, so Bob can't use it.
                    let bob_test_tx = make_bare_contract(&bob, 0, "bob-test", &format!(
                        "(define-data-var bob-test-run bool false)
                        (let (
                            (res
                                (contract-call? '{}.pox-api stack-stx u256000000 (tuple (version u0) (hashbytes 0xae1593226f85e49a7eaff5b633ff687695438cc9)) u12))
                        )
                        (begin
                            (asserts! (is-eq (err 12) res)
                                (err res))

                            (var-set bob-test-run true)
                        ))
                        ", STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                    block_txs.push(bob_test_tx);

                    // should fail -- Alice has already stacked.
                    let alice_test_tx = make_bare_contract(&alice, 2, "alice-test", &format!(
                        "(define-data-var alice-test-run bool false)
                        (let (
                            (res
                                (contract-call? '{}.pox-api stack-stx u512000000 (tuple (version u0) (hashbytes 0xffffffffffffffffffffffffffffffffffffffff)) u12))
                        )
                        (begin
                            (asserts! (is-eq (err 3) res)
                                (err res))

                            (var-set alice-test-run true)
                        ))
                        ", STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                    block_txs.push(alice_test_tx);

                    // should fail -- Charlie doesn't have enough uSTX
                    let charlie_test_tx = make_bare_contract(&charlie, 0, "charlie-test", &format!(
                        "(define-data-var charlie-test-run bool false)
                        (let (
                            (res
                                (contract-call? '{}.pox-api stack-stx u1024000000000 (tuple (version u0) (hashbytes 0xfefefefefefefefefefefefefefefefefefefefe)) u12))
                        )
                        (begin
                            (asserts! (is-eq (err 1) res)
                                (err res))

                            (var-set charlie-test-run true)
                        ))
                        ", STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                    block_txs.push(charlie_test_tx);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());

            if tenure_id == 0 {
                // Alice has not locked up half of her STX
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000);
            }
            else if tenure_id == 1 {
                // only half locked
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000 / 2);
            }
            else if tenure_id > 1 {
                // only half locked, still
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000 / 2);
            }

            if tenure_id <= 1 {
                // stacking minimum should be floor(total-liquid-ustx / 20000)
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                assert_eq!(min_ustx, total_liquid_ustx / 20000);

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                first_reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                eprintln!("\nalice reward cycle: {}\ncur reward cycle: {}\n", first_reward_cycle, cur_reward_cycle);
            }
            else if tenure_id == 2 {
                let alice_test_result = eval_contract_at_tip(&mut peer, &key_to_stacks_addr(&alice), "alice-test", "(var-get alice-test-run)");
                let bob_test_result = eval_contract_at_tip(&mut peer, &key_to_stacks_addr(&bob), "bob-test", "(var-get bob-test-run)");
                let charlie_test_result = eval_contract_at_tip(&mut peer, &key_to_stacks_addr(&charlie), "charlie-test", "(var-get charlie-test-run)");
               
                eprintln!("\nalice: {:?}, bob: {:?}, charlie: {:?}\n", &alice_test_result, &bob_test_result, &charlie_test_result);

                assert!(alice_test_result.expect_bool());
                assert!(bob_test_result.expect_bool());
                assert!(charlie_test_result.expect_bool());
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_register_delegate_single_tx_sender() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.reward_cycle_period = 5;
        burnchain.registration_period = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-register-delegate-single-tx-sender", 6008);

        let num_blocks = 10;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![
                    coinbase_tx
                ];

                if tenure_id == 2 {
                    // Danielle registers as a delegate.
                    let danielle_delegate = make_register_delegate(&danielle, 0, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes, parent_tip.burn_header_height as u128, 12);

                    // Alice delegates her STX to danielle, and meets the minimum threshold
                    let alice_delegate = make_delegate_stx(&alice, 0, &key_to_stacks_addr(&danielle), 1024 * 1000000);
                    
                    block_txs.push(danielle_delegate);
                    block_txs.push(alice_delegate);
                }
                if tenure_id == 3 {
                    // should fail -- danielle cannot register as a delegate again
                    let danielle_test_tx = make_bare_contract(&danielle, 1, "danielle-test", &format!(
                        "(define-data-var danielle-test-run bool false)
                        (let (
                            (res-del
                                (contract-call? '{}.pox-api register-delegate (tuple (version u0) (hashbytes 0xae1593226f85e49a7eaff5b633ff687695438cc9)) u100 u6))
                            
                            (res-stx
                                (contract-call? '{}.pox-api stack-stx u256000000 (tuple (version u0) (hashbytes 0xae1593226f85e49a7eaff5b633ff687695438cc9)) u12))
                        )
                        (begin
                            (asserts! (is-eq (err 8) res-stx)
                                (err res-stx))

                            (asserts! (is-eq (err 15) res-del)
                                (err res-del))

                            (var-set danielle-test-run true)
                        ))
                        ", STACKS_BOOT_CODE_CONTRACT_ADDRESS, STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                    block_txs.push(danielle_test_tx);

                    // should succeed -- danielle activates the delegation
                    let danielle_delegate = make_delegate(&danielle, 2);
                    block_txs.push(danielle_delegate);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());

            if tenure_id < 2 {
                // Alice has done nothing
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000);
            }
            else if tenure_id == 2 {
                // Danielle has become a delegate over Alice's tokens
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                    "(let (
                        (alice '{})
                        (danielle '{})
                        (alice-ustx u{})
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle is a delegate
                        (asserts! (is-some (map-get? delegate-control {{ delegate: danielle }}))
                            (err \"Danielle is not a delegate\"))

                        ;; Alice is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: alice }}))
                            (err \"Alice is not a stacker\"))

                        ;; Alice's delegate is Danielle
                        (asserts! (is-eq (some (some danielle)) (get delegate (map-get? stacking-state {{ stacker: alice }})))
                            (err \"Danielle is not the delegate of Alice\"))

                        ;; Danielle has Alice's stacks
                        (asserts! (is-eq (some alice-ustx) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))
                            (err \"Danielle does not control Alice's tokens\"))

                        ;; Danielle is _not_ a Stacker, yet
                        (asserts! (is-none (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is a Stacker already\"))

                        ;; Danielle's PoX address is marked registered
                        (asserts! (is-pox-addr-registered (tuple (version u0) (hashbytes danielle-addrbytes)) u0 u2000)
                            (err \"Danielle PoX address is not registered\"))

                        ;; Danielle's PoX address is _not_ in the reward cycles, though!
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is registered to a reward cycle\"))

                        (ok true)
                    ))
                    ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&danielle), 1024 * 1000000, &to_hex(&key_to_stacks_addr(&danielle).bytes.0)));

                assert!(danielle_query_result.expect_result_ok().expect_bool());
                
                // Alice delegated everything to Danielle
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 0);

                // No PoX addresses yet
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);
            }
            else if tenure_id == 3 {
                // Danielle is now a Stacker
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                    "(let (
                        (danielle '{})
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is not a Stacker\"))

                        ;; Danielle's PoX address is registered somewhere between reward cycles 0 and 2000
                        (asserts! (is-pox-addr-registered (tuple (version u0) (hashbytes danielle-addrbytes)) u0 u2000)
                            (err \"Danielle PoX address not registered\"))

                        ;; Danielle's PoX address is not currently active
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (current-pox-reward-cycle) }})))
                            (err \"Danielle PoX address is registered to the pre-first reward cycle\"))

                        ;; Danielle's PoX address is in the first and last reward cycles
                        (asserts! (is-eq (some u1) (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is not registered to the first reward cycle\"))
                        
                        (asserts! (is-eq (some u1) (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u12 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is not registered to the last reward cycle\"))
                        
                        ;; Danielle's PoX address is no longer active after the last reward cycle
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u13 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is registered beyond end of the last reward cycle\"))

                        true
                    ))
                    ", &key_to_stacks_addr(&danielle), &to_hex(&key_to_stacks_addr(&danielle).bytes.0)));

                assert!(danielle_query_result.expect_bool());
            }

            else if tenure_id >= 8 {
                // next reward cycle is active.
                // danielle's reward address is present, and it represents alice's tokens.
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 1);

                assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&danielle).bytes);
                assert_eq!(reward_addrs[0].1, 1024 * 1000000);
            }
        }
    }

    #[test]
    fn test_pox_lockup_register_delegate_multi_tx_sender() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.reward_cycle_period = 5;
        burnchain.registration_period = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-register-delegate-multi-tx-sender", 6010);

        let num_blocks = 10;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut alice_stacked = 0;
        let mut bob_stacked = 0;
        let mut min_ustx_before_stacking = 0;
        let mut tip_index_block = StacksBlockId([0u8; 32]);

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            if tenure_id == 2 {
                min_ustx_before_stacking = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                assert!(min_ustx_before_stacking > 0);

                alice_stacked = min_ustx_before_stacking - 1;
                bob_stacked = 1;
            }

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![
                    coinbase_tx
                ];

                if tenure_id == 2 {
                    assert!(min_ustx_before_stacking > 0);

                    // Danielle registers as a delegate.
                    let danielle_delegate = make_register_delegate(&danielle, 0, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes, parent_tip.burn_header_height as u128, 12);

                    // Alice delegates her STX to danielle, and does _not_ meet the minimum threshold by herself!
                    let alice_delegate = make_delegate_stx(&alice, 0, &key_to_stacks_addr(&danielle), alice_stacked);

                    // Bob delegates 1 uSTX to danielle, pushing the total over the minimum!
                    let bob_delegate = make_delegate_stx(&bob, 0, &key_to_stacks_addr(&danielle), bob_stacked);
                    
                    block_txs.push(danielle_delegate);
                    block_txs.push(alice_delegate);
                    block_txs.push(bob_delegate);
                }
                if tenure_id == 3 {
                    // should succeed -- danielle activates the delegation
                    let danielle_delegate = make_delegate(&danielle, 1);
                    block_txs.push(danielle_delegate);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());

            if tenure_id < 2 {
                // Alice has done nothing
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000);

                // Bob has done nothing
                let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob));
                assert_eq!(bob_balance, 1024 * 1000000);
            }
            else if tenure_id == 2 {
                // Danielle has become a delegate over Alice's tokens _and_ Bob's tokens
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                    "(let (
                        (alice '{})
                        (bob '{})
                        (danielle '{})
                        (alice-ustx u{})
                        (bob-ustx u{})
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle is a delegate
                        (asserts! (is-some (map-get? delegate-control {{ delegate: danielle }}))
                            (err \"Danielle is not a delegate\"))

                        ;; Alice is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: alice }}))
                            (err \"Alice is not a stacker\"))
                        
                        ;; Bob is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: bob }}))
                            (err \"Bob is not a stacker\"))

                        ;; Alice's delegate is Danielle
                        (asserts! (is-eq (some (some danielle)) (get delegate (map-get? stacking-state {{ stacker: alice }})))
                            (err \"Danielle is not the delegate of Alice\"))
                        
                        ;; Bob's delegate is Danielle
                        (asserts! (is-eq (some (some danielle)) (get delegate (map-get? stacking-state {{ stacker: bob }})))
                            (err \"Danielle is not the delegate of Alice\"))

                        ;; Danielle has Alice's STX and Bob's STX
                        (asserts! (is-eq (some (+ alice-ustx bob-ustx)) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))
                            (err \"Danielle does not control Alice's tokens\"))

                        ;; Danielle is _not_ a Stacker, yet
                        (asserts! (is-none (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is a Stacker already\"))

                        ;; Danielle's PoX address is marked registered
                        (asserts! (is-pox-addr-registered (tuple (version u0) (hashbytes danielle-addrbytes)) u0 u2000)
                            (err \"Danielle PoX address is not registered\"))

                        ;; Danielle's PoX address is _not_ in the reward cycles, though!
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is registered to a reward cycle\"))

                        (ok true)
                    ))
                    ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&bob), &key_to_stacks_addr(&danielle), alice_stacked, bob_stacked, &to_hex(&key_to_stacks_addr(&danielle).bytes.0)));

                assert!(danielle_query_result.expect_result_ok().expect_bool());
                
                // Alice delegated balance to Danielle
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000 - alice_stacked);
                
                // Bob delegated balance to Danielle
                let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob));
                assert_eq!(bob_balance, 1024 * 1000000 - bob_stacked);

                // No PoX addresses yet
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);
            }
            else if tenure_id == 3 {
                // Danielle is now a Stacker
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                    "(let (
                        (danielle '{})
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is not a Stacker\"))

                        ;; Danielle's PoX address is registered somewhere between reward cycles 0 and 2000
                        (asserts! (is-pox-addr-registered (tuple (version u0) (hashbytes danielle-addrbytes)) u0 u2000)
                            (err \"Danielle PoX address not registered\"))

                        ;; Danielle's PoX address is not currently active
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (current-pox-reward-cycle) }})))
                            (err \"Danielle PoX address is registered to the pre-first reward cycle\"))

                        ;; Danielle's PoX address is in the first and last reward cycles
                        (asserts! (is-eq (some u1) (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is not registered to the first reward cycle\"))
                        
                        (asserts! (is-eq (some u1) (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u12 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is not registered to the last reward cycle\"))
                        
                        ;; Danielle's PoX address is no longer active after the last reward cycle
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u13 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is registered beyond end of the last reward cycle\"))

                        true
                    ))
                    ", &key_to_stacks_addr(&danielle), &to_hex(&key_to_stacks_addr(&danielle).bytes.0)));

                assert!(danielle_query_result.expect_bool());
            }
            else if tenure_id >= 8 {
                // next reward cycle is active.
                // danielle's reward address is present, and it represents alice's and bob's tokens.
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 1);

                assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&danielle).bytes);
                assert_eq!(reward_addrs[0].1, alice_stacked + bob_stacked);
            }
        }
    }

    #[test]
    fn test_pox_lockup_single_tx_sender_unlock() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.reward_cycle_period = 5;
        burnchain.registration_period = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-single-tx-sender", 6012);

        let num_blocks = 20;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut alice_reward_cycle = 0;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![
                    coinbase_tx
                ];

                if tenure_id == 1 {
                    // Alice locks up exactly 25% of the liquid STX supply, so this should succeed.
                    let alice_lockup = make_pox_lockup(&alice, 0, 1024 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 1);
                    block_txs.push(alice_lockup);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());

            if tenure_id <= 1 {
                if tenure_id < 1 {
                    // Alice has not locked up STX
                    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                    assert_eq!(alice_balance, 1024 * 1000000);
                }

                // stacking minimum should be floor(total-liquid-ustx / 20000)
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                assert_eq!(min_ustx, total_liquid_ustx / 20000);

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                alice_reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                eprintln!("\nalice reward cycle: {}\ncur reward cycle: {}\n", alice_reward_cycle, cur_reward_cycle);
            }
            else {
                // Alice's address is locked as of the next reward cycle
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)).unwrap();
                
                eprintln!("\ntenure: {}\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);

                if cur_reward_cycle >= alice_reward_cycle {
                    // this will grow as more miner rewards are unlocked, so be wary
                    if tenure_id >= 8 {
                        // miner rewards increased liquid supply, so less than 25% is locked.
                        // minimum participation decreases.
                        assert!(total_liquid_ustx > 4 * 1024 * 1000000);
                        assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    }
                    else {
                        // still at 25% or more locked
                        assert!(total_liquid_ustx <= 4 * 1024 * 1000000);
                        assert!(min_ustx >= total_liquid_ustx / 5000);
                    }

                    if cur_reward_cycle == alice_reward_cycle {
                        let (amount_ustx, pox_addr, lock_period, first_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice)).unwrap();
                        eprintln!("\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);
                        
                        // one reward address, and it's Alice's
                        // either way, there's a single reward address
                        assert_eq!(reward_addrs.len(), 1);
                        assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                        assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                        assert_eq!(reward_addrs[0].1, 1024 * 1000000);
                    
                        // All of Alice's tokens are locked
                        assert_eq!(alice_balance, 0);
                    }
                    else {
                        // unlock should have happened
                        assert_eq!(alice_balance, 1024 * 1000000);
        
                        // alice shouldn't be a stacker
                        let info = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice));
                        assert!(get_stacker_info(&mut peer, &key_to_stacks_addr(&alice)).is_none());
                        
                        // empty reward cycle
                        assert_eq!(reward_addrs.len(), 0);
                    
                        // min STX is reset
                        assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    }
                }
                else {
                    // no reward addresses
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    assert_eq!(reward_addrs.len(), 0);
                }
            }
        }
    }

    // TODO: liquid ustx must decrease on burn!
    // TODO: test Stacking with a contract
    // TODO: test Stacking-rejection with a contract
    // TODO: need Stacking-rejection with a BTC address -- contract name in OP_RETURN?
    // TODO: test lazy unlock with standard principal -- should restore locked STX on next transaction
    // TODO: test lazy unlcok with contract principal -- should restore locked STX on next stx-transfer?
    // TODO: make it so principal balances queried lazily check lock state
    // TODO: check lazy unlock/relock in PoX
   
    /*
    #[test]
    fn test_pox_lockup_withdraw() {
        let (mut peer, mut keys) = instantiate_pox_peer("test-pox-lockup-withdraw", 6012);

        let num_blocks = 20;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut cur_reward_cycle = 0;
        let mut alice_reward_cycle = 0;
        let mut alice_withdraw_reward_cycle = 0;
        let mut tried_bad_withdraw = false;
        let mut alice_withdrawn = false;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();
            
            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![
                    coinbase_tx
                ];

                if tenure_id == 1 {
                    // Alice locks up exactly 25% of the liquid STX supply, so this should succeed.
                    let alice_lockup = make_pox_lockup(&alice, 0, 1024 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 1);
                    block_txs.push(alice_lockup);
                }
                else if cur_reward_cycle > 0 && cur_reward_cycle < alice_withdraw_reward_cycle {
                    // verify that we _can't_ withdraw
                    if !tried_bad_withdraw {
                        let danielle_test_tx = make_bare_contract(&alice, 1, "bad-withdraw-test", &format!(
                            "(define-data-var withdraw-test-run bool false)
                            (let (
                                (recipient '{})
                            )
                            (begin
                                (let (
                                    (withdraw-res
                                        (contract-call? '{}.pox-api withdraw-stx recipient))
                                )
                                (begin
                                    ;; stx are still locked
                                    (asserts! (is-eq (err 6) withdraw-res)
                                        (err withdraw-res))
                                ))

                                (var-set withdraw-test-run true)
                            ))
                            ", &key_to_stacks_addr(&alice), STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                        block_txs.push(danielle_test_tx);

                        tried_bad_withdraw = true;
                        test_debug!("try-bad-withdraw transaction sent");
                    }
                }
                else if cur_reward_cycle > 0 && cur_reward_cycle == alice_withdraw_reward_cycle {
                    if !alice_withdrawn {
                        let alice_withdraw = make_withdraw_stx(&alice, 2, &key_to_stacks_addr(&alice));
                        block_txs.push(alice_withdraw);

                        alice_withdrawn = true;
                        test_debug!("withdraw transaction sent");
                    }
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            // refresh
            cur_reward_cycle = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();
            let total_liquid_ustx = get_liquid_ustx(&mut peer);

            if tenure_id < 1 {
                // Alice has not locked up STX
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000);
            }
            else if tenure_id == 1 {

                // stacking minimum should be floor(total-liquid-ustx / 20000)
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb)).unwrap();
                assert_eq!(min_ustx, total_liquid_ustx / 20000);

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked, as well as the
                // cycle in which we can withdraw them.
                alice_reward_cycle = 1 + cur_reward_cycle;
                alice_withdraw_reward_cycle = alice_reward_cycle + 1;
                let cur_reward_cycle = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();

                eprintln!("\nalice reward cycle: {}\ncur reward cycle: {}\n", alice_reward_cycle, cur_reward_cycle);
            }
            else {
                // Alice has locked up STX no matter what, until she withdraws it
                if !alice_withdrawn {
                    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                    assert_eq!(alice_balance, 0);
                }
                
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                
                eprintln!("\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\n", cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx);

                if cur_reward_cycle == alice_reward_cycle {
                    // alice is in the reward cycle, and cannot withdraw.  Verify this
                    let alice_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                        "(let (
                            (alice '{})
                            (alice-addrbytes 0x{})
                        )
                        (begin
                            ;; Alice is a Stacker
                            (asserts! (is-some (map-get? stacking-state {{ stacker: alice }}))
                                (err \"Alice is not a Stacker\"))

                            ;; Alice's PoX address is registered
                            (asserts! (is-pox-addr-registered (tuple (version u0) (hashbytes alice-addrbytes)) pox-reward-cycle (+ u1 pox-reward-cycle))
                                (err \"Alice PoX address not registered\"))

                            ;; Alice's PoX address is currently active
                            (asserts! (is-eq (some u1) (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: pox-reward-cycle }})))
                                (err \"Alice PoX address is not currently active\"))

                            ;; Alice's PoX address will not be active in the next cycle
                            (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 pox-reward-cycle) }})))
                                (err \"ALice PoX address still registered to the next reward cycle\"))

                            true
                        ))
                        ", &key_to_stacks_addr(&alice), &to_hex(&key_to_stacks_addr(&alice).bytes.0)));

                    assert!(alice_query_result.expect_bool());

                    let withdraw_failed = eval_contract_at_tip(&mut peer, &key_to_stacks_addr(&alice), "bad-withdraw-test", "(var-get withdraw-test-run)");
                    assert!(withdraw_failed.expect_bool());
                }
                else if cur_reward_cycle > alice_reward_cycle {
                    // alice is no longer in her single reward cycle, and can withdraw
                    let alice_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                        "(let (
                            (alice '{})
                            (alice-addrbytes 0x{})
                            (alice-withdrawn {})
                        )
                        (begin
                            ;; Alice is a Stacker, until we withdraw!
                            (asserts! (or (and alice-withdrawn (is-none (map-get? stacking-state {{ stacker: alice }})))
                                          (and (not alice-withdrawn) (is-some (map-get? stacking-state {{ stacker: alice }}))))
                                (err \"Alice is not a Stacker at the right time\"))

                            ;; Alice's PoX address is not registered
                            (asserts! (not (is-pox-addr-registered (tuple (version u0) (hashbytes alice-addrbytes)) pox-reward-cycle (+ u1 pox-reward-cycle)))
                                (err \"Alice PoX address still registered\"))

                            ;; Alice's PoX address is not currently active
                            (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: pox-reward-cycle }})))
                                (err \"Alice PoX address is still active\"))

                            true
                        ))
                        ", &key_to_stacks_addr(&alice), &to_hex(&key_to_stacks_addr(&alice).bytes.0), alice_withdrawn));

                    assert!(alice_query_result.expect_bool());

                    if alice_withdrawn {
                        // alice got her uSTX back
                        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                        assert_eq!(alice_balance, 1024 * 1000000);
                    }
                }
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_register_delegate_withdraw_single() {
        let (mut peer, mut keys) = instantiate_pox_peer("test-pox-lockup-register-delegate-withdraw-single", 6014);

        let num_blocks = 16;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();
        
        let mut cur_reward_cycle = 0;
        let mut alice_reward_cycle = 0;
        let mut alice_withdraw_reward_cycle = 0;
        let mut alice_withdrawn = false;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![
                    coinbase_tx
                ];

                if tenure_id == 2 {
                    // Danielle registers as a delegate.
                    let danielle_delegate = make_register_delegate(&danielle, 0, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes, parent_tip.burn_header_height as u128, 1, None);

                    // Alice delegates her STX to danielle, and meets the minimum threshold
                    let alice_delegate = make_delegate_stx(&alice, 0, &key_to_stacks_addr(&danielle), 1024 * 1000000);
                    
                    block_txs.push(danielle_delegate);
                    block_txs.push(alice_delegate);

                    alice_reward_cycle = 1 + cur_reward_cycle;
                    alice_withdraw_reward_cycle = alice_reward_cycle + 1;
                }
                else if tenure_id == 3 {
                    // should succeed -- danielle activates the delegation
                    let danielle_delegate = make_delegate(&danielle, 1);
                    block_txs.push(danielle_delegate);
                }
                else if cur_reward_cycle > 0 && cur_reward_cycle == alice_withdraw_reward_cycle {
                    if !alice_withdrawn {
                        let alice_withdraw = make_withdraw_stx(&alice, 1, &key_to_stacks_addr(&alice));
                        block_txs.push(alice_withdraw);

                        alice_withdrawn = true;
                        test_debug!("withdraw transaction sent");
                    }
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            cur_reward_cycle = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();

            if tenure_id < 2 {
                // Alice has done nothing
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000);
            }
            else if tenure_id == 2 {
                // Danielle has become a delegate over Alice's tokens
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                    "(let (
                        (alice '{})
                        (danielle '{})
                        (alice-ustx u{})
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle is a delegate
                        (asserts! (is-some (map-get? delegate-control {{ delegate: danielle }}))
                            (err \"Danielle is not a delegate\"))

                        ;; Alice is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: alice }}))
                            (err \"Alice is not a stacker\"))

                        ;; Alice's delegate is Danielle
                        (asserts! (is-eq (some (some danielle)) (get delegate (map-get? stacking-state {{ stacker: alice }})))
                            (err \"Danielle is not the delegate of Alice\"))

                        ;; Danielle has Alice's stacks
                        (asserts! (is-eq (some alice-ustx) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))
                            (err \"Danielle does not control Alice's tokens\"))

                        ;; Danielle is _not_ a Stacker, yet
                        (asserts! (is-none (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is a Stacker already\"))

                        ;; Danielle's PoX address is _not_ in the reward cycles, though!
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 pox-reward-cycle) }})))
                            (err \"Danielle PoX address is registered to a reward cycle\"))

                        (ok true)
                    ))
                    ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&danielle), 1024 * 1000000, &to_hex(&key_to_stacks_addr(&danielle).bytes.0)));

                assert!(danielle_query_result.expect_result_ok().expect_bool());
                
                // Alice delegated everything to Danielle
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 0);

                // No PoX addresses yet
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                assert_eq!(reward_addrs.len(), 0);
            }
            else if tenure_id == 3 {
                // Danielle is now a Stacker
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                    "(let (
                        (danielle '{})
                    )
                    (begin
                        ;; Danielle is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is not a Stacker\"))

                        true
                    ))
                    ", &key_to_stacks_addr(&danielle)));

                assert!(danielle_query_result.expect_bool());
            }
            else {
                if cur_reward_cycle == alice_reward_cycle {
                    // alice is in the reward cycle, and cannot withdraw from danielle.  Verify this
                    let alice_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                        "(let (
                            (alice '{})
                            (danielle '{})
                            (danielle-addrbytes 0x{})
                            (alice-stacked u{})
                        )
                        (begin
                            ;; Alice is a Stacker
                            (asserts! (is-some (map-get? stacking-state {{ stacker: alice }}))
                                (err \"Alice is not a Stacker\"))
                            
                            ;; Danielle is a Stacker
                            (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                                (err \"Danielle is not a Stacker\"))

                            ;; Danielle's PoX address is registered
                            (asserts! (is-pox-addr-registered (tuple (version u0) (hashbytes danielle-addrbytes)) pox-reward-cycle (+ u1 pox-reward-cycle))
                                (err \"Danielle PoX address not registered\"))

                            ;; Danielle's PoX address is currently active
                            (asserts! (is-eq (some u1) (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: pox-reward-cycle }})))
                                (err \"Danielle PoX address is not currently active\"))

                            ;; Danielle's PoX address will not be active in the next cycle
                            (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 pox-reward-cycle) }})))
                                (err \"Danielle PoX address still registered to the next reward cycle\"))

                            ;; Danielle has Alice's STX 
                            (asserts! (is-eq (some alice-stacked) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))
                                (err \"Danielle does not control Alice's tokens\"))

                            true
                        ))
                        ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&danielle), &to_hex(&key_to_stacks_addr(&danielle).bytes.0), 1024 * 1000000));

                    assert!(alice_query_result.expect_bool());
                }
                else if cur_reward_cycle > alice_reward_cycle {
                    // alice is no longer in her single delegated reward cycle, and can withdraw
                    let alice_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                        "(let (
                            (alice '{})
                            (danielle '{})
                            (danielle-addrbytes 0x{})
                            (alice-withdrawn {})
                            (alice-ustx u{})
                        )
                        (begin
                            ;; Alice is a Stacker, until we withdraw!
                            (asserts! (or (and alice-withdrawn (is-none (map-get? stacking-state {{ stacker: alice }})))
                                          (and (not alice-withdrawn) (is-some (map-get? stacking-state {{ stacker: alice }}))))
                                (err \"Alice is not a Stacker at the right time\"))

                            ;; Danielle's PoX address is not registered
                            (asserts! (not (is-pox-addr-registered (tuple (version u0) (hashbytes danielle-addrbytes)) pox-reward-cycle (+ u1 pox-reward-cycle)))
                                (err \"Danielle PoX address still registered\"))

                            ;; Danielle's PoX address is not currently active
                            (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: pox-reward-cycle }})))
                                (err \"Danielle PoX address is still active\"))

                            ;; Danielle remains a Stacker
                            (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                                (err \"Danielle is not a Stacker\"))
                            
                            ;; Danielle has no-one's STX
                            (asserts! (or (and alice-withdrawn (is-eq (some u0) (get total-ustx (map-get? delegate-control {{ delegate: danielle }}))))
                                          (and (not alice-withdrawn) (is-eq (some alice-ustx) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))))
                                (err \"Danielle does not control Alice's tokens\"))

                            true
                        ))
                        ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&danielle), &to_hex(&key_to_stacks_addr(&danielle).bytes.0), alice_withdrawn, 1024 * 1000000));

                    assert!(alice_query_result.expect_bool());

                    if alice_withdrawn {
                        // alice got her uSTX back
                        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                        assert_eq!(alice_balance, 1024 * 1000000);
                    }
                }
            }
        }
        assert!(alice_withdrawn);
    }

    #[test]
    fn test_pox_lockup_register_delegate_withdraw_multi() {
        let (mut peer, mut keys) = instantiate_pox_peer("test-pox-lockup-register-delegate-withdraw-multi", 6016);

        let num_blocks = 20;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();
        
        let mut cur_reward_cycle = 0;
        let mut reward_cycle = 0;
        let mut withdraw_reward_cycle = 0;
        let mut alice_withdrawn = false;
        let mut danielle_withdrawn = false;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let mut block_txs = vec![
                    coinbase_tx
                ];

                if tenure_id == 2 {
                    // Danielle registers as a delegate.
                    // She can claim Bob's STX one reward cycle after her tenure ends
                    let danielle_delegate = make_register_delegate(&danielle, 0, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes, parent_tip.burn_header_height as u128, 1);

                    // Alice and Bob delegate their STX to danielle, and meets the minimum threshold
                    let alice_delegate = make_delegate_stx(&alice, 0, &key_to_stacks_addr(&danielle), 1024 * 1000000);
                    let bob_delegate = make_delegate_stx(&bob, 0, &key_to_stacks_addr(&danielle), 1024 * 1000000);
                    
                    block_txs.push(danielle_delegate);
                    block_txs.push(alice_delegate);
                    block_txs.push(bob_delegate);

                    reward_cycle = 1 + cur_reward_cycle;
                    withdraw_reward_cycle = reward_cycle + 1;
                }
                else if tenure_id == 3 {
                    // should succeed -- danielle activates the delegation
                    let danielle_delegate = make_delegate(&danielle, 1);
                    block_txs.push(danielle_delegate);
                }
                else if cur_reward_cycle > 0 && cur_reward_cycle == withdraw_reward_cycle {
                    if !alice_withdrawn {
                        let alice_withdraw = make_withdraw_stx(&alice, 1, &key_to_stacks_addr(&alice));
                        block_txs.push(alice_withdraw);

                        alice_withdrawn = true;
                        test_debug!("withdraw transaction sent");
                    }
                }
                else if cur_reward_cycle > 0 && cur_reward_cycle == withdraw_reward_cycle + 1 {
                    if !danielle_withdrawn {
                        let danielle_withdraw = make_delegate_withdraw_stx(&danielle, 2, &key_to_stacks_addr(&alice));
                        block_txs.push(danielle_withdraw);

                        danielle_withdrawn = true;
                        test_debug!("delegate-withdraw transaction sent");
                    }
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_hash = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());
            cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_hash).unwrap();

            if tenure_id < 2 {
                // Alice has done nothing
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000);
            }
            else if tenure_id == 2 {
                // Danielle has become a delegate over Alice's tokens
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                    "(let (
                        (alice '{})
                        (bob '{})
                        (danielle '{})
                        (alice-ustx u{})
                        (bob-ustx u{})
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle is a delegate
                        (asserts! (is-some (map-get? delegate-control {{ delegate: danielle }}))
                            (err \"Danielle is not a delegate\"))

                        ;; Alice is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: alice }}))
                            (err \"Alice is not a stacker\"))
                        
                        ;; Bob is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: bob }}))
                            (err \"Bob is not a stacker\"))

                        ;; Alice's delegate is Danielle
                        (asserts! (is-eq (some (some danielle)) (get delegate (map-get? stacking-state {{ stacker: alice }})))
                            (err \"Danielle is not the delegate of Alice\"))
                        
                        ;; Bob's delegate is Danielle
                        (asserts! (is-eq (some (some danielle)) (get delegate (map-get? stacking-state {{ stacker: bob }})))
                            (err \"Danielle is not the delegate of Bob\"))

                        ;; Danielle has Alice's and Bob's STX
                        (asserts! (is-eq (some (+ alice-ustx bob-ustx)) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))
                            (err \"Danielle does not control Alice's tokens\"))

                        ;; Danielle is _not_ a Stacker, yet
                        (asserts! (is-none (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is a Stacker already\"))

                        ;; Danielle's PoX address is _not_ in the reward cycles, though!
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 pox-reward-cycle) }})))
                            (err \"Danielle PoX address is registered to a reward cycle\"))

                        (ok true)
                    ))
                    ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&bob), &key_to_stacks_addr(&danielle), 1024 * 1000000, 1024 * 1000000, &to_hex(&key_to_stacks_addr(&danielle).bytes.0)));

                assert!(danielle_query_result.expect_result_ok().expect_bool());
                
                // Alice delegated everything to Danielle
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 0);

                // No PoX addresses yet
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                assert_eq!(reward_addrs.len(), 0);
            }
            else if tenure_id == 3 {
                // Danielle is now a Stacker
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                    "(let (
                        (danielle '{})
                    )
                    (begin
                        ;; Danielle is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is not a Stacker\"))

                        true
                    ))
                    ", &key_to_stacks_addr(&danielle)));

                assert!(danielle_query_result.expect_bool());
            }
            else {
                if cur_reward_cycle == reward_cycle {
                    // alice and bob are in the reward cycle, and cannot withdraw from danielle.  Verify this
                    let alice_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                        "(let (
                            (alice '{})
                            (bob '{})
                            (danielle '{})
                            (danielle-addrbytes 0x{})
                            (alice-stacked u{})
                            (bob-stacked u{})
                        )
                        (begin
                            ;; Alice is a Stacker
                            (asserts! (is-some (map-get? stacking-state {{ stacker: alice }}))
                                (err \"Alice is not a Stacker\"))
                            
                            ;; Bob is a Stacker
                            (asserts! (is-some (map-get? stacking-state {{ stacker: bob }}))
                                (err \"Bob is not a Stacker\"))
                            
                            ;; Danielle is a Stacker
                            (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                                (err \"Danielle is not a Stacker\"))

                            ;; Danielle's PoX address is registered
                            (asserts! (is-pox-addr-registered (tuple (version u0) (hashbytes danielle-addrbytes)) pox-reward-cycle (+ u1 pox-reward-cycle))
                                (err \"Danielle PoX address not registered\"))

                            ;; Danielle's PoX address is currently active
                            (asserts! (is-eq (some u1) (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: pox-reward-cycle }})))
                                (err \"Danielle PoX address is not currently active\"))

                            ;; Danielle's PoX address will not be active in the next cycle
                            (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 pox-reward-cycle) }})))
                                (err \"Danielle PoX address still registered to the next reward cycle\"))

                            ;; Danielle has Alice's and Bob's STX
                            (asserts! (is-eq (some (+ alice-stacked bob-stacked)) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))
                                (err \"Danielle does not control Alice's tokens\"))

                            true
                        ))
                        ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&bob), &key_to_stacks_addr(&danielle), &to_hex(&key_to_stacks_addr(&danielle).bytes.0), 1024 * 1000000, 1024 * 1000000));

                    assert!(alice_query_result.expect_bool());
                }
                else if cur_reward_cycle > reward_cycle {
                    // alice is no longer in her single delegated reward cycle, and can withdraw
                    let query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox-api", &format!(
                        "(let (
                            (alice '{})
                            (bob '{})
                            (danielle '{})
                            (danielle-addrbytes 0x{})
                            (alice-withdrawn {})
                            (danielle-withdrawn {})
                            (alice-ustx u{})
                            (bob-ustx u{})
                        )
                        (begin
                            ;; Alice is a Stacker, until we withdraw!
                            (asserts! (or (and alice-withdrawn (is-none (map-get? stacking-state {{ stacker: alice }})))
                                          (and (not alice-withdrawn) (is-some (map-get? stacking-state {{ stacker: alice }}))))
                                (err \"Alice is not a Stacker at the right time\"))
                            
                            ;; Bob is a Stacker
                            (asserts! (is-some (map-get? stacking-state {{ stacker: bob }}))
                                (err \"Bob is not a Stacker at the right time\"))

                            ;; Danielle's PoX address is not registered
                            (asserts! (not (is-pox-addr-registered (tuple (version u0) (hashbytes danielle-addrbytes)) pox-reward-cycle (+ u1 pox-reward-cycle)))
                                (err \"Danielle PoX address still registered\"))

                            ;; Danielle's PoX address is not currently active
                            (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: pox-reward-cycle }})))
                                (err \"Danielle PoX address is still active\"))

                            ;; Danielle remains a Stacker, until withdrawing herself
                            (asserts! (or (and danielle-withdrawn (is-none (map-get? stacking-state {{ stacker: danielle }})))
                                          (and (not danielle-withdrawn) (is-some (map-get? stacking-state {{ stacker: danielle }}))))
                                (err \"Danielle is not a Stacker at the right time\"))
                            
                            ;; Danielle has either Alice + Bob's STX, or just Bob's STX if Alice has withdrawn.
                            ;; If Danielle has withdrawn, then she does not control any STX.
                            (if (not danielle-withdrawn)
                                (asserts! (or (and alice-withdrawn (is-eq (some alice-ustx) (get total-ustx (map-get? delegate-control {{ delegate: danielle }}))))
                                              (and (not alice-withdrawn) (is-eq (some (+ alice-ustx bob-ustx)) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))))
                                    (err \"Danielle does not control Alice's tokens\"))
                                (asserts! (is-eq (some u0) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))
                                    (err \"Danielle controls some STX after withdraw\"))
                            )
                            true
                        ))
                        ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&bob), &key_to_stacks_addr(&danielle), &to_hex(&key_to_stacks_addr(&danielle).bytes.0), alice_withdrawn, danielle_withdrawn, 1024 * 1000000, 1024 * 1000000));

                    assert!(query_result.expect_bool());

                    if alice_withdrawn {
                        // alice got her uSTX back
                        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                        assert_eq!(alice_balance, 1024 * 1000000);
                        
                        test_debug!("Alice withdrew her STX");
                    }
                    if danielle_withdrawn {
                        // danielle got bob's uSTX
                        let danielle_balance = get_balance(&mut peer, &key_to_stacks_addr(&danielle));
                        assert_eq!(danielle_balance, 2 * 1024 * 1000000);
                        
                        let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob));
                        assert_eq!(bob_balance, 0);

                        test_debug!("Danielle recovered Bob's STX");
                    }
                }
            }
        }
        assert!(alice_withdrawn);
        assert!(danielle_withdrawn);
    }
    */
}
