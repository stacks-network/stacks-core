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
    PrincipalData,
    SequenceData
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
    ("pox", std::include_str!("pox.clar")),
    ("lookup", std::include_str!("lockup.clar"))
];

pub fn boot_code_addr() -> StacksAddress {
    StacksAddress::from_string(&STACKS_BOOT_CODE_CONTRACT_ADDRESS.clone()).unwrap()
}    

pub fn boot_code_id(name: &str) -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::new(StandardPrincipalData::from(boot_code_addr()), ContractName::try_from(name.to_string()).unwrap())
}

pub fn make_contract_id(addr: &StacksAddress, name: &str) -> QualifiedContractIdentifier {
    QualifiedContractIdentifier::new(StandardPrincipalData::from(addr.clone()), ContractName::try_from(name.to_string()).unwrap())
}

/// Extract a PoX address from its tuple representation
fn tuple_to_pox_addr(tuple_data: TupleData) -> (AddressHashMode, Hash160) {
    let version_value = tuple_data.get("version").expect("FATAL: no 'version' field in pox-addr").to_owned();
    let hashbytes_value = tuple_data.get("hashbytes").expect("FATAL: no 'hashbytes' field in pox-addr").to_owned();

    let version_u8 = version_value.expect_buff(1)[0];
    let version : AddressHashMode = version_u8.try_into().expect("FATAL: PoX version is not a supported version byte");

    let hashbytes_vec = hashbytes_value.expect_buff(20);

    let mut hashbytes_20 = [0u8; 20];
    hashbytes_20.copy_from_slice(&hashbytes_vec[0..20]);
    let hashbytes = Hash160(hashbytes_20);

    (version, hashbytes)
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
        Ok((((parent_header_info.burn_header_height as u64) - burnchain.first_block_height) / burnchain.pox_constants.reward_cycle_length as u64) as u128)
    }

    /// Determine the minimum amount of STX per reward address required to stack in the _next_
    /// reward cycle
    #[cfg(test)]
    pub fn get_stacking_minimum(&mut self, sortdb: &SortitionDB, stacks_block_id: &StacksBlockId) -> Result<u128, Error> {
        self.eval_boot_code_read_only(sortdb, stacks_block_id, "pox", &format!("(at-block 0x{} (get-stacking-minimum (+ u1 (current-pox-reward-cycle))))", &stacks_block_id))
            .map(|value| value.expect_u128())
    }
    
    /// Determine how many uSTX are stacked in a given reward cycle
    #[cfg(test)]
    pub fn get_total_ustx_stacked(&mut self, sortdb: &SortitionDB, stacks_block_id: &StacksBlockId, reward_cycle: u128) -> Result<u128, Error> {
        self.eval_boot_code_read_only(sortdb, stacks_block_id, "pox", &format!("(at-block 0x{} (get-total-ustx-stacked u{}))", &stacks_block_id, reward_cycle))
            .map(|value| value.expect_u128())
    }

    /// Is PoX active in the given reward cycle?
    pub fn is_pox_active(&mut self, sortdb: &SortitionDB, stacks_block_id: &StacksBlockId, reward_cycle: u128) -> Result<bool, Error> {
        self.eval_boot_code_read_only(sortdb, stacks_block_id, "pox", &format!("(at-block 0x{} (is-pox-active u{}))", &stacks_block_id, reward_cycle))
            .map(|value| value.expect_bool())
    }

    /// List all PoX addresses and amount of uSTX stacked, at a particular block.
    /// Each address will have at least (get-stacking-minimum) tokens.
    pub fn get_reward_addresses(&mut self, burnchain: &Burnchain, sortdb: &SortitionDB, block_id: &StacksBlockId) -> Result<Vec<((AddressHashMode, Hash160), u128)>, Error> {
        let reward_cycle = self.get_reward_cycle(burnchain, block_id)?;
        if !self.is_pox_active(sortdb, block_id, reward_cycle)? {
            debug!("PoX was voted disabled in block {} (reward cycle {})", block_id, reward_cycle);
            return Ok(vec![]);
        }

        // how many in this cycle?
        let num_addrs = self.eval_boot_code_read_only(sortdb, block_id, "pox", &format!("(get-reward-set-size u{})", reward_cycle))?
            .expect_u128();

        debug!("At block {:?} (reward cycle {}): {} PoX reward addresses", block_id, reward_cycle, num_addrs);

        let mut ret = vec![];
        for i in 0..num_addrs {
            // value should be (optional (tuple (pox-addr (tuple (...))) (total-ustx uint))).
            // Get the tuple.
            let tuple_data = self.eval_boot_code_read_only(sortdb, block_id, "pox", &format!("(get-reward-set-pox-address u{} u{})", reward_cycle, i))?
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
    use vm::contracts::Contract;
    
    use std::fs;
    use std::convert::From;

    use util::hash::to_hex;

    fn key_to_stacks_addr(key: &StacksPrivateKey) -> StacksAddress {
        StacksAddress::from_public_keys(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, &AddressHashMode::SerializeP2PKH, 1, &vec![StacksPublicKey::from_private(key)]).unwrap()
    }
    
    fn instantiate_pox_peer(burnchain: &Burnchain, test_name: &str, port: u16) -> (TestPeer, Vec<StacksPrivateKey>) {
        let mut peer_config = TestPeerConfig::new(test_name, port, port + 1);
        peer_config.burnchain = burnchain.clone();
        peer_config.setup_code = format!("(contract-call? .pox set-burnchain-parameters u{} u{} u{} u{})",
                                          burnchain.first_block_height, burnchain.pox_constants.prepare_length, burnchain.pox_constants.reward_cycle_length, burnchain.pox_constants.pox_rejection_fraction);

        test_debug!("Setup code: '{}'", &peer_config.setup_code);

        let keys = [
            StacksPrivateKey::from_hex("7e3ee1f2a0ae11b785a1f0e725a9b3ab0a5fd6cc057d43763b0a85f256fdec5d01").unwrap(),
            StacksPrivateKey::from_hex("11d055ac8b0ab4f04c5eb5ea4b4def9c60ae338355d81c9411b27b4f49da2a8301").unwrap(),
            StacksPrivateKey::from_hex("00eed368626b96e482944e02cc136979973367491ea923efb57c482933dd7c0b01").unwrap(),
            StacksPrivateKey::from_hex("00380ff3c05350ee313f60f30313acb4b5fc21e50db4151bf0de4cd565eb823101").unwrap(),
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
        let value = eval_at_tip(peer, "pox", "total-liquid-ustx");
        if let Value::UInt(inner_uint) = value {
            return inner_uint;
        }
        else {
            panic!("total-liquid-ustx isn't a uint");
        }
    }

    fn get_balance(peer: &mut TestPeer, addr: &PrincipalData) -> u128 {
        let value = eval_at_tip(peer, "pox", &format!("(stx-get-balance '{})", addr.to_string()));
        if let Value::UInt(balance) = value {
            return balance;
        }
        else {
            panic!("stx-get-balance isn't a uint");
        }
    }

    fn get_stacker_info(peer: &mut TestPeer, addr: &PrincipalData) -> Option<(u128, (AddressHashMode, Hash160), u128, u128, Option<PrincipalData>)> {
        let value_opt = eval_at_tip(peer, "pox", &format!("(get-stacker-info '{})", addr.to_string()));
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

    fn get_delegate_control_info(peer: &mut TestPeer, addr: &PrincipalData) -> Option<(u128, (AddressHashMode, Hash160), u128, u128, u128)> {
        let value_opt = eval_at_tip(peer, "pox", &format!("(get-delegate-control-info '{})", addr.to_string()));
        let data = 
            if let Some(d) = value_opt.expect_optional() {
                d
            }
            else {
                return None
            };

        let data = data.expect_tuple();

        let amount_ustx = data.get("total-ustx").unwrap().to_owned().expect_u128();
        let pox_addr = tuple_to_pox_addr(data.get("pox-addr").unwrap().to_owned().expect_tuple());
        let burn_block_height_start = data.get("burn-block-height-start").unwrap().to_owned().expect_u128();
        let first_reward_cycle = data.get("first-reward-cycle").unwrap().to_owned().expect_u128();
        let tenure_cycles = data.get("tenure-cycles").unwrap().to_owned().expect_u128();

        Some((amount_ustx, pox_addr, burn_block_height_start, first_reward_cycle, tenure_cycles))
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

    fn get_account(peer: &mut TestPeer, addr: &PrincipalData) -> StacksAccount {
        let account = with_sortdb(peer, |ref mut chainstate, ref mut sortdb| {
            let (consensus_hash, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
            let stacks_block_id = StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_bhh);
            chainstate.with_read_only_clarity_tx(&sortdb.index_conn(), &stacks_block_id, |clarity_tx| {
                StacksChainState::get_account(clarity_tx, addr)
            })
        });
        account
    }
    
    fn get_contract(peer: &mut TestPeer, addr: &QualifiedContractIdentifier) -> Option<Contract> {
        let contract_opt = with_sortdb(peer, |ref mut chainstate, ref mut sortdb| {
            let (consensus_hash, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash(sortdb.conn()).unwrap();
            let stacks_block_id = StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_bhh);
            chainstate.with_read_only_clarity_tx(&sortdb.index_conn(), &stacks_block_id, |clarity_tx| {
                StacksChainState::get_contract(clarity_tx, addr).unwrap()
            })
        });
        contract_opt
    }

    fn make_pox_addr(addr_version: AddressHashMode, addr_bytes: Hash160) -> Value {
        Value::Tuple(TupleData::from_data(vec![
            (ClarityName::try_from("version".to_owned()).unwrap(), Value::buff_from_byte(addr_version as u8)),
            (ClarityName::try_from("hashbytes".to_owned()).unwrap(), Value::Sequence(SequenceData::Buffer(BuffData { data: addr_bytes.as_bytes().to_vec() })))
        ]).unwrap())
    }

    fn make_pox_lockup(key: &StacksPrivateKey, nonce: u64, amount: u128, addr_version: AddressHashMode, addr_bytes: Hash160, lock_period: u128) -> StacksTransaction {
        // (define-public (stack-stx (amount-ustx uint)
        //                           (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
        //                           (lock-period uint))
        
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut pox_lockup = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                                    TransactionPayload::new_contract_call(boot_code_addr(),
                                                                                         "pox",
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

    // make a stream of invalid pox-lockup transactions
    fn make_invalid_pox_lockups(key: &StacksPrivateKey, mut nonce: u64) -> Vec<StacksTransaction> {
        let mut ret = vec![];

        let amount = 1;
        let lock_period = 1;
        let addr_bytes = Hash160([0u8; 20]);

        let bad_pox_addr_version = Value::Tuple(TupleData::from_data(vec![
            (ClarityName::try_from("version".to_owned()).unwrap(), Value::UInt(100)),
            (ClarityName::try_from("hashbytes".to_owned()).unwrap(), Value::Sequence(SequenceData::Buffer(BuffData { data: addr_bytes.as_bytes().to_vec() })))
        ]).unwrap());

        let generator = |amount, pox_addr, lock_period, nonce| {
            let auth = TransactionAuth::from_p2pkh(key).unwrap();
            let addr = auth.origin().address_testnet();
            let mut pox_lockup = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                                        TransactionPayload::new_contract_call(boot_code_addr(),
                                                                                             "pox",
                                                                                             "stack-stx",
                                                                                             vec![
                                                                                                Value::UInt(amount),
                                                                                                pox_addr,
                                                                                                Value::UInt(lock_period)
                                                                                             ]).unwrap());
            pox_lockup.chain_id = 0x80000000;
            pox_lockup.auth.set_origin_nonce(nonce);
            pox_lockup.set_post_condition_mode(TransactionPostConditionMode::Allow);
            pox_lockup.set_fee_rate(0);

            let mut tx_signer = StacksTransactionSigner::new(&pox_lockup);
            tx_signer.sign_origin(key).unwrap();
            tx_signer.get_tx().unwrap()
        };
        
        let bad_pox_addr_tx = generator(amount, bad_pox_addr_version, lock_period, nonce);
        ret.push(bad_pox_addr_tx);
        nonce += 1;

        let bad_lock_period_short = generator(amount, make_pox_addr(AddressHashMode::SerializeP2PKH, addr_bytes.clone()), 0, nonce);
        ret.push(bad_lock_period_short);
        nonce += 1;

        let bad_lock_period_long = generator(amount, make_pox_addr(AddressHashMode::SerializeP2PKH, addr_bytes.clone()), 13, nonce);
        ret.push(bad_lock_period_long);
        nonce += 1;

        let bad_amount = generator(0, make_pox_addr(AddressHashMode::SerializeP2PKH, addr_bytes.clone()), 1, nonce);
        ret.push(bad_amount);

        ret
    }
    
    // make a stream of invalid register-delegate transactions
    fn make_invalid_register_delegates(key: &StacksPrivateKey, mut nonce: u64) -> Vec<StacksTransaction> {
        let mut ret = vec![];

        let addr_bytes = Hash160([0u8; 20]);
        let lock_period = 1;
        let tenure_burn_block_begin = 1000;
        let tenure_reward_num_cycles = 1;
        let pox_addr = make_pox_addr(AddressHashMode::SerializeP2PKH, addr_bytes.clone());

        let bad_pox_addr_version = Value::Tuple(TupleData::from_data(vec![
            (ClarityName::try_from("version".to_owned()).unwrap(), Value::UInt(100)),
            (ClarityName::try_from("hashbytes".to_owned()).unwrap(), Value::Sequence(SequenceData::Buffer(BuffData { data: addr_bytes.as_bytes().to_vec() })))
        ]).unwrap());

        let generator = |pox_addr, tenure_burn_block_begin, tenure_reward_num_cycles, nonce| {
            let auth = TransactionAuth::from_p2pkh(key).unwrap();
            let addr = auth.origin().address_testnet();
            let mut pox_lockup = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                                        TransactionPayload::new_contract_call(boot_code_addr(),
                                                                                             "pox",
                                                                                             "register-delegate",
                                                                                             vec![
                                                                                                pox_addr,
                                                                                                Value::UInt(tenure_burn_block_begin),
                                                                                                Value::UInt(tenure_reward_num_cycles)
                                                                                            ]).unwrap());
            pox_lockup.chain_id = 0x80000000;
            pox_lockup.auth.set_origin_nonce(nonce);
            pox_lockup.set_post_condition_mode(TransactionPostConditionMode::Allow);
            pox_lockup.set_fee_rate(0);

            let mut tx_signer = StacksTransactionSigner::new(&pox_lockup);
            tx_signer.sign_origin(key).unwrap();
            tx_signer.get_tx().unwrap()
        };
        
        let bad_pox_addr_tx = generator(bad_pox_addr_version, tenure_burn_block_begin, tenure_reward_num_cycles, nonce);
        ret.push(bad_pox_addr_tx);
        nonce += 1;
        
        let bad_lock_period_short = generator(pox_addr.clone(), tenure_burn_block_begin, 0, nonce);
        ret.push(bad_lock_period_short);
        nonce += 1;
        
        let bad_lock_period_long = generator(pox_addr.clone(), tenure_burn_block_begin, 13, nonce);
        ret.push(bad_lock_period_long);
        nonce += 1;
        
        let bad_tenure_early = generator(pox_addr.clone(), 0, tenure_reward_num_cycles, nonce);
        ret.push(bad_tenure_early);

        ret
    }
    
    // make a stream of invalid delegate-stx transactions
    fn make_invalid_delegate_pox_lockups(key: &StacksPrivateKey, mut nonce: u64, delegate: PrincipalData) -> Vec<StacksTransaction> {
        let mut ret = vec![];

        let amount = 1;

        let generator = |amount| {
            let auth = TransactionAuth::from_p2pkh(key).unwrap();
            let addr = auth.origin().address_testnet();
            let mut pox_lockup = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                                        TransactionPayload::new_contract_call(boot_code_addr(),
                                                                                             "pox",
                                                                                             "delegate-stx",
                                                                                             vec![
                                                                                                Value::Principal(delegate),
                                                                                                Value::UInt(amount),
                                                                                             ]).unwrap());
            pox_lockup.chain_id = 0x80000000;
            pox_lockup.auth.set_origin_nonce(nonce);
            pox_lockup.set_post_condition_mode(TransactionPostConditionMode::Allow);
            pox_lockup.set_fee_rate(0);

            let mut tx_signer = StacksTransactionSigner::new(&pox_lockup);
            tx_signer.sign_origin(key).unwrap();
            tx_signer.get_tx().unwrap()
        };

        let bad_amount_standard = generator(0);
        ret.push(bad_amount_standard);
        nonce += 1;

        ret
    }
    
    fn make_bare_contract(key: &StacksPrivateKey, nonce: u64, fee_rate: u64, name: &str, code: &str) -> StacksTransaction {
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut bare_code = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                                   TransactionPayload::new_smart_contract(&name.to_string(), &code.to_string()).unwrap());
        bare_code.chain_id = 0x80000000;
        bare_code.auth.set_origin_nonce(nonce);
        bare_code.set_post_condition_mode(TransactionPostConditionMode::Allow);
        bare_code.set_fee_rate(fee_rate);

        let mut tx_signer = StacksTransactionSigner::new(&bare_code);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }

    fn make_token_transfer(key: &StacksPrivateKey, nonce: u64, fee_rate: u64, dest: PrincipalData, amount: u64) -> StacksTransaction {
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        
        let mut txn = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                             TransactionPayload::TokenTransfer(dest, amount, TokenTransferMemo([0u8; 34])));

        txn.chain_id = 0x80000000;
        txn.auth.set_origin_nonce(nonce);
        txn.set_post_condition_mode(TransactionPostConditionMode::Allow);
        txn.set_fee_rate(fee_rate);
        
        let mut tx_signer = StacksTransactionSigner::new(&txn);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }
    
    fn make_pox_lockup_contract(key: &StacksPrivateKey, nonce: u64, name: &str) -> StacksTransaction {
        let contract = format!("
        (define-public (do-contract-lockup (amount-ustx uint) (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20)))) (lock-period uint))
            (let (
                (this-contract (as-contract tx-sender))
            )
            (begin
                ;; take the stx from the tx-sender
                (stx-transfer? amount-ustx tx-sender this-contract)

                ;; this contract stacks the stx given to it
                (as-contract
                    (contract-call? '{}.pox stack-stx amount-ustx pox-addr lock-period))
            ))
        )

        ;; register this contract as a delegate
        (define-public (register-as-delegate (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
                                             (tenure-burn-block-height uint)
                                             (tenure-reward-cycles uint))
            (as-contract
                (contract-call? '{}.pox register-delegate pox-addr tenure-burn-block-height tenure-reward-cycles)))

        ;; delegate-stack any STX sent to this contract, if this contract is used as a delegate
        (define-public (do-delegate-stx)
            (as-contract
                (contract-call? '{}.pox delegate-stack-stx)))

        ;; get back STX from this contract
        (define-public (withdraw-stx (amount-ustx uint))
            (let (
                (recipient tx-sender)
            )
            (begin
                (as-contract
                    (stx-transfer? amount-ustx tx-sender recipient))
                (ok true)
            ))
        )
        ", boot_code_addr(), boot_code_addr(), boot_code_addr());
        let contract_tx = make_bare_contract(key, nonce, 0, name, &contract);
        contract_tx
    }

    // call after make_pox_lockup_contract gets mined
    fn make_pox_lockup_contract_call(key: &StacksPrivateKey, nonce: u64, contract_addr: &StacksAddress, name: &str, amount: u128, addr_version: AddressHashMode, addr_bytes: Hash160, lock_period: u128) -> StacksTransaction {
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut pox_lockup = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                                    TransactionPayload::new_contract_call(contract_addr.clone(),
                                                                                         name,
                                                                                         "do-contract-lockup",
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

    fn make_pox_register_delegate_contract_call(key: &StacksPrivateKey, nonce: u64, contract_addr: &StacksAddress, name: &str, addr_version: AddressHashMode, addr_bytes: Hash160, burn_block_height: u64, reward_cycles: u64) -> StacksTransaction {
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut tx = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                            TransactionPayload::new_contract_call(contract_addr.clone(),
                                                                                 name,
                                                                                 "register-as-delegate",
                                                                                 vec![
                                                                                    make_pox_addr(addr_version, addr_bytes),
                                                                                    Value::UInt(burn_block_height as u128),
                                                                                    Value::UInt(reward_cycles as u128),
                                                                                 ]).unwrap());
        tx.chain_id = 0x80000000;
        tx.auth.set_origin_nonce(nonce);
        tx.set_post_condition_mode(TransactionPostConditionMode::Allow);
        tx.set_fee_rate(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }
    
    fn make_pox_delegate_stx_contract_call(key: &StacksPrivateKey, nonce: u64, contract_addr: &StacksAddress, name: &str) -> StacksTransaction {
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut tx = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                            TransactionPayload::new_contract_call(contract_addr.clone(),
                                                                                 name,
                                                                                 "do-delegate-stx",
                                                                                 vec![]).unwrap());
        tx.chain_id = 0x80000000;
        tx.auth.set_origin_nonce(nonce);
        tx.set_post_condition_mode(TransactionPostConditionMode::Allow);
        tx.set_fee_rate(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }
    
    // call after make_pox_lockup_contract gets mined
    fn make_pox_withdraw_stx_contract_call(key: &StacksPrivateKey, nonce: u64, contract_addr: &StacksAddress, name: &str, amount: u128) -> StacksTransaction {
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut pox_lockup = StacksTransaction::new(TransactionVersion::Testnet, auth,
                                                    TransactionPayload::new_contract_call(contract_addr.clone(),
                                                                                         name,
                                                                                         "withdraw-stx",
                                                                                         vec![
                                                                                            Value::UInt(amount)
                                                                                         ]).unwrap());
        pox_lockup.chain_id = 0x80000000;
        pox_lockup.auth.set_origin_nonce(nonce);
        pox_lockup.set_post_condition_mode(TransactionPostConditionMode::Allow);
        pox_lockup.set_fee_rate(0);

        let mut tx_signer = StacksTransactionSigner::new(&pox_lockup);
        tx_signer.sign_origin(key).unwrap();
        tx_signer.get_tx().unwrap()
    }
    
    fn make_register_delegate(key: &StacksPrivateKey, nonce: u64, 
                              addr_version: AddressHashMode, addr_bytes: Hash160, 
                              tenure_burn_block_begin: u128, 
                              tenure_reward_cycles: u128) -> StacksTransaction {
        // (define-public (register-delegate (pox-addr (tuple (version (buff 1)) (hashbytes (buff 20))))
        //                                   (tenure-burn-block-begin uint)
        //                                   (tenure-reward-cycles uint)))
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        let mut register_delegate = StacksTransaction::new(
                                        TransactionVersion::Testnet, auth,
                                        TransactionPayload::new_contract_call(boot_code_addr(),
                                                                             "pox",
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

    fn make_delegate_stx(key: &StacksPrivateKey, nonce: u64, delegate: &PrincipalData, amount: u128) -> StacksTransaction {
        // (define-public (delegate-stx (delegate principal)
        //                              (amount-ustx uint))
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        
        let mut delegate_stx = StacksTransaction::new(
                                        TransactionVersion::Testnet, auth,
                                        TransactionPayload::new_contract_call(boot_code_addr(),
                                                                             "pox",
                                                                             "delegate-stx",
                                                                             vec![
                                                                                Value::Principal(delegate.clone()),
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
                                                                             "pox",
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
   
    fn make_pox_reject(key: &StacksPrivateKey, nonce: u64) -> StacksTransaction {
        // (define-public (reject-pox))
        let auth = TransactionAuth::from_p2pkh(key).unwrap();
        let addr = auth.origin().address_testnet();
        
        let mut tx = StacksTransaction::new(
                                        TransactionVersion::Testnet, auth,
                                        TransactionPayload::new_contract_call(boot_code_addr(),
                                                                             "pox",
                                                                             "reject-pox",
                                                                             vec![]).unwrap());

        tx.chain_id = 0x80000000;
        tx.auth.set_origin_nonce(nonce);
        tx.set_post_condition_mode(TransactionPostConditionMode::Allow);
        tx.set_fee_rate(0);

        let mut tx_signer = StacksTransactionSigner::new(&tx);
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
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

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
    fn test_liquid_ustx_burns() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-liquid-ustx", 6026);

        let num_blocks = 10;
        let mut expected_liquid_ustx = 1024 * 1000000 * (keys.len() as u128); 
        
        let alice = keys.pop().unwrap();

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

            let (burn_ops, stacks_block, microblocks) = peer.make_tenure(|ref mut miner, ref mut sortdb, ref mut chainstate, vrf_proof, ref parent_opt, ref parent_microblock_header_opt| {
                let parent_tip = get_parent_tip(parent_opt, chainstate, sortdb);
                let coinbase_tx = make_coinbase(miner, tenure_id);

                let burn_tx = make_bare_contract(&alice, tenure_id as u64, 0, &format!("alice-burns-{}", &tenure_id), "(stx-burn? u1 tx-sender)");

                let block_txs = vec![
                    coinbase_tx,
                    burn_tx
                ];

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);
            
            expected_liquid_ustx -= 1;
            
            let liquid_ustx = get_liquid_ustx(&mut peer);
            assert_eq!(liquid_ustx, expected_liquid_ustx);

            if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW) as usize {
                // add mature coinbases
                expected_liquid_ustx += 500 * 1000000;
            }
        }
    }

    #[test]
    fn test_pox_input_validity() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-input-validity", 6028);

        let num_blocks = 3;

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

                if tenure_id == 1 {
                    // Danielle registers as a delegate.
                    let danielle_delegate = make_register_delegate(&danielle, 0, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes, parent_tip.burn_header_height as u128, 12);
                    block_txs.push(danielle_delegate);
                }
                if tenure_id == 2 {
                    let mut invalid_lockups = make_invalid_pox_lockups(&alice, 0);
                    let mut invalid_delegate_lockups = make_invalid_delegate_pox_lockups(&bob, 0, key_to_stacks_addr(&danielle).into());
                    let mut invalid_delegate_registers = make_invalid_register_delegates(&charlie, 0);

                    block_txs.append(&mut invalid_lockups);
                    block_txs.append(&mut invalid_delegate_lockups);
                    block_txs.append(&mut invalid_delegate_registers);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            if tenure_id == 2 {
                // no lockups succeeded
                let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_account.stx_balance.amount_unlocked, 1024 * 1000000);
                assert_eq!(alice_account.stx_balance.amount_locked, 0);
                assert_eq!(alice_account.stx_balance.unlock_height, 0);

                // no delegate-lockups succeeded
                let bob_account = get_account(&mut peer, &key_to_stacks_addr(&bob).into());
                assert_eq!(bob_account.stx_balance.amount_unlocked, 1024 * 1000000);
                assert_eq!(bob_account.stx_balance.amount_locked, 0);
                assert_eq!(bob_account.stx_balance.unlock_height, 0);

                // no delegate registrations succeeded
                assert!(get_delegate_control_info(&mut peer, &key_to_stacks_addr(&charlie).into()).is_none());
                
                // except for the only legit one
                assert!(get_delegate_control_info(&mut peer, &key_to_stacks_addr(&danielle).into()).is_some());
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_single_tx_sender() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

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
                    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_balance, 1024 * 1000000);

                    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_account.stx_balance.amount_unlocked, 1024 * 1000000);
                    assert_eq!(alice_account.stx_balance.amount_locked, 0);
                    assert_eq!(alice_account.stx_balance.unlock_height, 0);
                
                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                }
                else {
                    // stacking minimum should be floor(total-liquid-ustx / 5000), since 25% is stacked
                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                    assert_eq!(min_ustx, total_liquid_ustx / 5000);
                }

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
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 0);
                 
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)).unwrap();
                
                eprintln!("\ntenure: {}\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);

                if cur_reward_cycle >= alice_reward_cycle {
                    // this will grow as more miner rewards are unlocked, so be wary
                    if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1) as usize {
                        // miner rewards increased liquid supply, so less than 25% is locked.
                        // minimum participation decreases.
                        assert!(total_liquid_ustx > 4 * 1024 * 1000000);
                        assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    }
                    else {
                        // still at 25% or more locked
                        assert!(total_liquid_ustx <= 4 * 1024 * 1000000);
                    }

                    let (amount_ustx, pox_addr, lock_period, first_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).unwrap();
                    eprintln!("\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);
                    
                    // one reward address, and it's Alice's
                    // either way, there's a single reward address
                    assert_eq!(reward_addrs.len(), 1);
                    assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                    assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                    assert_eq!(reward_addrs[0].1, 1024 * 1000000);

                    // Lock-up is consistent with stacker state
                    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_account.stx_balance.amount_unlocked, 0);
                    assert_eq!(alice_account.stx_balance.amount_locked, 1024 * 1000000);
                    assert_eq!(alice_account.stx_balance.unlock_height as u128, (first_reward_cycle + lock_period) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                }
                else {
                    // no reward addresses
                    assert_eq!(reward_addrs.len(), 0);
                }
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_contract() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-contract", 6018);

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
                    // make a contract, and have the contract do the stacking
                    let bob_contract = make_pox_lockup_contract(&bob, 0, "do-lockup");
                    block_txs.push(bob_contract);

                    let alice_stack = make_pox_lockup_contract_call(&alice, 0, &key_to_stacks_addr(&bob), "do-lockup", 1024 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 1);
                    block_txs.push(alice_stack);
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
                    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_balance, 1024 * 1000000);

                    // stacking minimum should be floor(total-liquid-ustx / 20000)
                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                }
                else {
                    // stacking minimum should be floor(total-liquid-ustx / 5000) now
                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                    assert_eq!(min_ustx, total_liquid_ustx / 5000);
                }

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                alice_reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                eprintln!("\nalice reward cycle: {}\ncur reward cycle: {}\n", alice_reward_cycle, cur_reward_cycle);
            }
            else {
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                // Alice's tokens got sent to the contract, so her balance is 0
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 0);

                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)).unwrap();
                
                eprintln!("\ntenure: {}\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);

                if cur_reward_cycle >= alice_reward_cycle {
                    // alice's tokens are locked for only one reward cycle
                    if cur_reward_cycle == alice_reward_cycle {
                        // this will grow as more miner rewards are unlocked, so be wary
                        if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1) as usize {
                            // height at which earliest miner rewards mature.
                            // miner rewards increased liquid supply, so less than 25% is locked.
                            // minimum participation decreases.
                            assert!(total_liquid_ustx > 4 * 1024 * 1000000);
                            assert_eq!(min_ustx, total_liquid_ustx / 20000);
                        }
                        else {
                            // still at 25% or more locked
                            assert!(total_liquid_ustx <= 4 * 1024 * 1000000);
                        }

                        // Alice is _not_ a stacker -- Bob's contract is!
                        let alice_info = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into());
                        assert!(alice_info.is_none());

                        // Bob is _not_ a stacker either.
                        let bob_info = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into());
                        assert!(bob_info.is_none());

                        // Bob's contract is a stacker
                        let (amount_ustx, pox_addr, lock_period, first_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into()).unwrap();
                        eprintln!("\nContract: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);
                        
                        // should be consistent with the API call
                        assert_eq!(lock_period, 1);
                        assert_eq!(first_reward_cycle, alice_reward_cycle);
                        assert_eq!(amount_ustx, 1024 * 1000000);

                        // one reward address, and it's Alice's
                        // either way, there's a single reward address
                        assert_eq!(reward_addrs.len(), 1);
                        assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                        assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                        assert_eq!(reward_addrs[0].1, 1024 * 1000000);

                        // contract's address's tokens are locked
                        let contract_balance = get_balance(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into());
                        assert_eq!(contract_balance, 0);
                          
                        // Lock-up is consistent with stacker state
                        let contract_account = get_account(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into());
                        assert_eq!(contract_account.stx_balance.amount_unlocked, 0);
                        assert_eq!(contract_account.stx_balance.amount_locked, 1024 * 1000000);
                        assert_eq!(contract_account.stx_balance.unlock_height as u128, (first_reward_cycle + lock_period) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    }
                    else {
                        // no longer locked
                        let contract_balance = get_balance(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into());
                        assert_eq!(contract_balance, 1024 * 1000000);

                        assert_eq!(reward_addrs.len(), 0);
                        
                        // Lock-up is lazy -- state has not been updated 
                        let contract_account = get_account(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into());
                        assert_eq!(contract_account.stx_balance.amount_unlocked, 0);
                        assert_eq!(contract_account.stx_balance.amount_locked, 1024 * 1000000);
                        assert_eq!(contract_account.stx_balance.unlock_height as u128, (alice_reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    }
                }
                else {
                    // no reward addresses
                    assert_eq!(reward_addrs.len(), 0);
                }
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_multi_tx_sender() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

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
                    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_balance, 1024 * 1000000);
                    
                    // Bob has not locked up STX
                    let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob).into());
                    assert_eq!(bob_balance, 1024 * 1000000);
                
                    // stacking minimum should be floor(total-liquid-ustx / 20000)
                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                }
                else {
                    // stacking minimum should be floor(total-liquid-ustx / 5000)
                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                    assert_eq!(min_ustx, total_liquid_ustx / 5000);
                }

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
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 0);
                
                let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob).into());
                assert_eq!(bob_balance, 1024 * 1000000 - (4 * 1024 * 1000000) / 5);
                
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                
                eprintln!("\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\n", cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx);

                if cur_reward_cycle >= first_reward_cycle {
                    // this will grow as more miner rewards are unlocked, so be wary
                    if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1) as usize {
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
                    assert_eq!(reward_addrs.len(), 0);
                }
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_no_double_stacking() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

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
                    let alice_lockup_1 = make_pox_lockup(&alice, 0, 512 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 12);
                    block_txs.push(alice_lockup_1);
                   
                    // will be rejected
                    let alice_lockup_2 = make_pox_lockup(&alice, 1, 512 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 12);
                    block_txs.push(alice_lockup_2);
                }
                if tenure_id == 2 {
                    // should fail -- Alice's PoX address is already in use, so Bob can't use it.
                    let bob_test_tx = make_bare_contract(&bob, 0, 0, "bob-test", &format!(
                        "(define-data-var bob-test-run bool false)
                        (let (
                            (res
                                (contract-call? '{}.pox stack-stx u256000000 (tuple (version 0x00) (hashbytes 0xae1593226f85e49a7eaff5b633ff687695438cc9)) u12))
                        )
                        (begin
                            (asserts! (is-eq (err 12) res)
                                (err res))

                            (var-set bob-test-run true)
                        ))
                        ", STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                    block_txs.push(bob_test_tx);

                    // should fail -- Alice has already stacked.
                    let alice_test_tx = make_bare_contract(&alice, 2, 0, "alice-test", &format!(
                        "(define-data-var alice-test-run bool false)
                        (let (
                            (res
                                (contract-call? '{}.pox stack-stx u512000000 (tuple (version 0x00) (hashbytes 0xffffffffffffffffffffffffffffffffffffffff)) u12))
                        )
                        (begin
                            (asserts! (is-eq (err 3) res)
                                (err res))

                            (var-set alice-test-run true)
                        ))
                        ", STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                    block_txs.push(alice_test_tx);

                    // should fail -- Charlie doesn't have enough uSTX
                    let charlie_test_tx = make_bare_contract(&charlie, 0, 0, "charlie-test", &format!(
                        "(define-data-var charlie-test-run bool false)
                        (let (
                            (res
                                (contract-call? '{}.pox stack-stx u1024000000000 (tuple (version 0x00) (hashbytes 0xfefefefefefefefefefefefefefefefefefefefe)) u12))
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
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 1024 * 1000000);
            }
            else if tenure_id == 1 {
                // only half locked
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 512 * 1000000);
            }
            else if tenure_id > 1 {
                // only half locked, still
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 512 * 1000000);
            }

            if tenure_id <= 1 {
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
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

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
                    let alice_delegate = make_delegate_stx(&alice, 0, &key_to_stacks_addr(&danielle).into(), 1024 * 1000000);
                    
                    block_txs.push(danielle_delegate);
                    block_txs.push(alice_delegate);
                }
                if tenure_id == 3 {
                    // should fail -- danielle cannot register as a delegate again
                    let danielle_test_tx = make_bare_contract(&danielle, 1, 0, "danielle-test", &format!(
                        "(define-data-var danielle-test-run bool false)
                        (let (
                            (res-del
                                (contract-call? '{}.pox register-delegate (tuple (version 0x00) (hashbytes 0xae1593226f85e49a7eaff5b633ff687695438cc9)) u100 u6))
                            
                            (res-stx
                                (contract-call? '{}.pox stack-stx u256000000 (tuple (version 0x00) (hashbytes 0xae1593226f85e49a7eaff5b633ff687695438cc9)) u12))
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
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 1024 * 1000000);
            }
            else if tenure_id == 2 {
                // Danielle has become a delegate over Alice's tokens
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox", &format!(
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
                        (asserts! (is-pox-addr-registered (tuple (version 0x00) (hashbytes danielle-addrbytes)) u0 u2000)
                            (err \"Danielle PoX address is not registered\"))

                        ;; Danielle's PoX address is _not_ in the reward cycles, though!
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is registered to a reward cycle\"))

                        (ok true)
                    ))
                    ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&danielle), 1024 * 1000000, &to_hex(&key_to_stacks_addr(&danielle).bytes.0)));

                assert!(danielle_query_result.expect_result_ok().expect_bool());
                
                // Alice delegated everything to Danielle
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 0);

                // No PoX addresses yet
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);
            }
            else if tenure_id == 3 {
                // Danielle is now a Stacker
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox", &format!(
                    "(let (
                        (danielle '{})
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is not a Stacker\"))

                        ;; Danielle's PoX address is registered somewhere between reward cycles 0 and 2000
                        (asserts! (is-pox-addr-registered (tuple (version 0x00) (hashbytes danielle-addrbytes)) u0 u2000)
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

            else if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1) as usize {
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
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

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
                    let alice_delegate = make_delegate_stx(&alice, 0, &key_to_stacks_addr(&danielle).into(), alice_stacked);

                    // Bob delegates 1 uSTX to danielle, pushing the total over the minimum!
                    let bob_delegate = make_delegate_stx(&bob, 0, &key_to_stacks_addr(&danielle).into(), bob_stacked);
                    
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
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 1024 * 1000000);

                // Bob has done nothing
                let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob).into());
                assert_eq!(bob_balance, 1024 * 1000000);
            }
            else if tenure_id == 2 {
                // Danielle has become a delegate over Alice's tokens _and_ Bob's tokens
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox", &format!(
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
                        (asserts! (is-pox-addr-registered (tuple (version 0x00) (hashbytes danielle-addrbytes)) u0 u2000)
                            (err \"Danielle PoX address is not registered\"))

                        ;; Danielle's PoX address is _not_ in the reward cycles, though!
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is registered to a reward cycle\"))

                        (ok true)
                    ))
                    ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&bob), &key_to_stacks_addr(&danielle), alice_stacked, bob_stacked, &to_hex(&key_to_stacks_addr(&danielle).bytes.0)));

                assert!(danielle_query_result.expect_result_ok().expect_bool());
                
                // Alice delegated balance to Danielle
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 1024 * 1000000 - alice_stacked);
                
                // Bob delegated balance to Danielle
                let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob).into());
                assert_eq!(bob_balance, 1024 * 1000000 - bob_stacked);

                // No PoX addresses yet
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);
            }
            else if tenure_id == 3 {
                // Danielle is now a Stacker
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox", &format!(
                    "(let (
                        (danielle '{})
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is not a Stacker\"))

                        ;; Danielle's PoX address is registered somewhere between reward cycles 0 and 2000
                        (asserts! (is-pox-addr-registered (tuple (version 0x00) (hashbytes danielle-addrbytes)) u0 u2000)
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
            else if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1) as usize {
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
    fn test_pox_lockup_register_delegate_contract() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-register-delegate-contract", 6020);

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
                    // Danielle creates a contract
                    let danielle_contract = make_pox_lockup_contract(&danielle, 0, "do-lockup");
                    block_txs.push(danielle_contract);

                    // Danielle's contract registers as a delegate
                    let danielle_contract_delegate = make_pox_register_delegate_contract_call(&danielle, 1, &key_to_stacks_addr(&danielle), "do-lockup", AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes, parent_tip.burn_header_height as u64, 12);
                    block_txs.push(danielle_contract_delegate);

                    // Alice delegates her STX to Danielle's contract
                    let alice_delegate = make_delegate_stx(&alice, 0, &make_contract_id(&key_to_stacks_addr(&danielle), "do-lockup").into(), 1024 * 1000000);
                    block_txs.push(alice_delegate);
                }
                if tenure_id == 3 {
                    // should fail -- danielle cannot register as a delegate again
                    let danielle_test_tx = make_bare_contract(&danielle, 1, 0, "danielle-test", &format!(
                        "(define-data-var danielle-test-run bool false)
                        (let (
                            (res-del
                                (contract-call? '{}.do-lockup register-as-delegate (tuple (version 0x00) (hashbytes 0xae1593226f85e49a7eaff5b633ff687695438cc9)) u100 u6))
                            
                            (res-stx
                                (contract-call? '{}.do-lockup do-contract-lockup u256000000 (tuple (version 0x00) (hashbytes 0xae1593226f85e49a7eaff5b633ff687695438cc9)) u12))
                        )
                        (begin
                            (asserts! (is-eq (err 8) res-stx)
                                (err res-stx))

                            (asserts! (is-eq (err 15) res-del)
                                (err res-del))

                            (var-set danielle-test-run true)
                        ))
                        ", &key_to_stacks_addr(&danielle), &key_to_stacks_addr(&danielle)));

                    block_txs.push(danielle_test_tx);

                    // should succeed -- danielle activates the delegation
                    let danielle_delegate = make_pox_delegate_stx_contract_call(&danielle, 2, &key_to_stacks_addr(&danielle), "do-lockup");
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
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 1024 * 1000000);
            }
            else if tenure_id == 2 {
                // Danielle's contract has become a delegate over Alice's tokens
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox", &format!(
                    "(let (
                        (alice '{})
                        (danielle '{}.do-lockup)
                        (alice-ustx u{})
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle's contract is a delegate
                        (asserts! (is-some (map-get? delegate-control {{ delegate: danielle }}))
                            (err \"Danielle is not a delegate\"))

                        ;; Alice is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: alice }}))
                            (err \"Alice is not a stacker\"))

                        ;; Alice's delegate is Danielle's contract
                        (asserts! (is-eq (some (some danielle)) (get delegate (map-get? stacking-state {{ stacker: alice }})))
                            (err \"Danielle is not the delegate of Alice\"))

                        ;; Danielle's contract has Alice's stacks
                        (asserts! (is-eq (some alice-ustx) (get total-ustx (map-get? delegate-control {{ delegate: danielle }})))
                            (err \"Danielle does not control Alice's tokens\"))

                        ;; Danielle's contract is _not_ a Stacker, yet
                        (asserts! (is-none (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is a Stacker already\"))

                        ;; Danielle's contract's PoX address is marked registered
                        (asserts! (is-pox-addr-registered (tuple (version 0x00) (hashbytes danielle-addrbytes)) u0 u2000)
                            (err \"Danielle PoX address is not registered\"))

                        ;; Danielle's contract's PoX address is _not_ in the reward cycles, though!
                        (asserts! (is-none (get len (map-get? reward-cycle-pox-address-list-len {{ reward-cycle: (+ u1 (current-pox-reward-cycle)) }})))
                            (err \"Danielle PoX address is registered to a reward cycle\"))

                        (ok true)
                    ))
                    ", &key_to_stacks_addr(&alice), &key_to_stacks_addr(&danielle), 1024 * 1000000, &to_hex(&key_to_stacks_addr(&danielle).bytes.0)));

                assert!(danielle_query_result.expect_result_ok().expect_bool());
                
                // Alice delegated everything to Danielle
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                assert_eq!(alice_balance, 0);

                // No PoX addresses yet
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);
            }
            else if tenure_id == 3 {
                // Danielle's contract is now a Stacker
                let danielle_query_result = eval_contract_at_tip(&mut peer, &boot_code_addr(), "pox", &format!(
                    "(let (
                        (danielle '{}.do-lockup)
                        (danielle-addrbytes 0x{})
                    )
                    (begin
                        ;; Danielle is a Stacker
                        (asserts! (is-some (map-get? stacking-state {{ stacker: danielle }}))
                            (err \"Danielle is not a Stacker\"))

                        ;; Danielle's PoX address is registered somewhere between reward cycles 0 and 2000
                        (asserts! (is-pox-addr-registered (tuple (version 0x00) (hashbytes danielle-addrbytes)) u0 u2000)
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

            else if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1) as usize {
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
    fn test_pox_lockup_single_tx_sender_unlock() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-single-tx-sender-unlock", 6012);

        let num_blocks = 2;

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
                    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_balance, 1024 * 1000000);

                    // stacking minimum should be floor(total-liquid-ustx / 20000)
                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                }
                else {
                    // stacking minimum should be floor(total-liquid-ustx / 5000)


                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();

                    assert_eq!(min_ustx, total_liquid_ustx / 5000);
                }

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

                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
                
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)).unwrap();
                
                eprintln!("\ntenure: {}\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);

                if cur_reward_cycle >= alice_reward_cycle {
                    // this will grow as more miner rewards are unlocked, so be wary
                    if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1) as usize {
                        // miner rewards increased liquid supply, so less than 25% is locked.
                        // minimum participation decreases.
                        assert!(total_liquid_ustx > 4 * 1024 * 1000000);
                        assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    }

                    if cur_reward_cycle == alice_reward_cycle {
                        let (amount_ustx, pox_addr, lock_period, first_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).unwrap();
                        eprintln!("\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);
                        
                        assert_eq!(first_reward_cycle, alice_reward_cycle);
                        assert_eq!(lock_period, 1);

                        // one reward address, and it's Alice's
                        // either way, there's a single reward address
                        assert_eq!(reward_addrs.len(), 1);
                        assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                        assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                        assert_eq!(reward_addrs[0].1, 1024 * 1000000);
                   
                        // All of Alice's tokens are locked
                        assert_eq!(alice_balance, 0);

                        // Lock-up is consistent with stacker state
                        let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                        assert_eq!(alice_account.stx_balance.amount_unlocked, 0);
                        assert_eq!(alice_account.stx_balance.amount_locked, 1024 * 1000000);
                        assert_eq!(alice_account.stx_balance.unlock_height as u128, (first_reward_cycle + lock_period) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    }
                    else {
                        // unlock should have happened
                        assert_eq!(alice_balance, 1024 * 1000000);
        
                        // alice shouldn't be a stacker
                        let info = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into());
                        assert!(get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).is_none());
                        
                        // empty reward cycle
                        assert_eq!(reward_addrs.len(), 0);
                    
                        // min STX is reset
                        assert_eq!(min_ustx, total_liquid_ustx / 20000);
                        
                        // Unlock is lazy
                        let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                        assert_eq!(alice_account.stx_balance.amount_unlocked, 0);
                        assert_eq!(alice_account.stx_balance.amount_locked, 1024 * 1000000);
                        assert_eq!(alice_account.stx_balance.unlock_height as u128, (alice_reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    }
                }
                else {
                    // no reward addresses
                    assert_eq!(reward_addrs.len(), 0);
                }
            }
        }
    }
    
    #[test]
    fn test_pox_lockup_unlock_relock() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-unlock-relock", 6014);

        let num_blocks = 20;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut first_reward_cycle = 0;
        let mut second_reward_cycle = 0;

        let mut test_before_first_reward_cycle = false;
        let mut test_in_first_reward_cycle = false;
        let mut test_between_reward_cycles = false;
        let mut test_in_second_reward_cycle = false;
        let mut test_after_second_reward_cycle = false;

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

                    // Bob creates a locking contract
                    let bob_contract = make_pox_lockup_contract(&bob, 0, "do-lockup");
                    block_txs.push(bob_contract);

                    let charlie_stack = make_pox_lockup_contract_call(&charlie, 0, &key_to_stacks_addr(&bob), "do-lockup", 1024 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&charlie).bytes, 1);
                    block_txs.push(charlie_stack);
                }
                else if tenure_id == 11 {
                    // Alice locks up half of her tokens
                    let alice_lockup = make_pox_lockup(&alice, 1, 512 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 1);
                    block_txs.push(alice_lockup);
                   
                    // Charlie locks up half of his tokens
                    let charlie_stack = make_pox_lockup_contract_call(&charlie, 1, &key_to_stacks_addr(&bob), "do-lockup", 512 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&charlie).bytes, 1);
                    block_txs.push(charlie_stack);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());
            let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

            let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
            let charlie_balance = get_balance(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into());
            
            let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
            let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
            let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)).unwrap();

            if tenure_id <= 1 {
                if tenure_id < 1 {
                    // Alice has not locked up STX
                    assert_eq!(alice_balance, 1024 * 1000000);

                    // Charlie's contract has not locked up STX
                    assert_eq!(charlie_balance, 0);

                    // stacking minimum should be floor(total-liquid-ustx / 20000), because we haven't
                    // stacked yet.
                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                }
                else {
                    // stacking minimum should be floor(total-liquid-ustx / 5000)
                    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                    assert_eq!(min_ustx, total_liquid_ustx / 5000);
                }

                // no reward addresses
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                first_reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                eprintln!("\nfirst reward cycle: {}\ncur reward cycle: {}\n", first_reward_cycle, cur_reward_cycle);

                assert!(first_reward_cycle > cur_reward_cycle);
                test_before_first_reward_cycle = true;
            }
            else if tenure_id == 10 {
                // Alice has unlocked
                assert_eq!(alice_balance, 1024 * 1000000);

                // Charlie's contract has unlocked
                assert_eq!(charlie_balance, 1024 * 1000000);
            }
            else if tenure_id == 11 {
                // should have just re-locked
                // stacking minimum should be floor(total-liquid-ustx / 20000), since we haven't
                // locked up 25% of the tokens yet
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
                assert_eq!(min_ustx, total_liquid_ustx / 20000);

                // no reward addresses
                assert_eq!(reward_addrs.len(), 0);
                
                // record the first reward cycle when Alice's tokens get stacked
                second_reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                assert!(second_reward_cycle > cur_reward_cycle);
                eprintln!("\nsecond reward cycle: {}\ncur reward cycle: {}\n", second_reward_cycle, cur_reward_cycle);
            }
            
            eprintln!("\ntenure: {}\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);

            // this will grow as more miner rewards are unlocked, so be wary
            if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1) as usize {
                // miner rewards increased liquid supply, so less than 25% is locked.
                // minimum participation decreases.
                assert!(total_liquid_ustx > 4 * 1024 * 1000000);
                assert_eq!(min_ustx, total_liquid_ustx / 20000);
            }
            else if tenure_id >= 1 && cur_reward_cycle < first_reward_cycle {
                // still at 25% or more locked
                assert!(total_liquid_ustx <= 4 * 1024 * 1000000);
            }
            else if tenure_id < 1 {
                // nothing locked yet
                assert_eq!(min_ustx, total_liquid_ustx / 20000);
            }

            if first_reward_cycle > 0 && second_reward_cycle == 0 {
                if cur_reward_cycle == first_reward_cycle {
                    test_in_first_reward_cycle = true;

                    // in Alice's first reward cycle
                    let (amount_ustx, pox_addr, lock_period, first_pox_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).unwrap();
                    eprintln!("\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);
                    
                    assert_eq!(first_reward_cycle, first_reward_cycle);
                    assert_eq!(lock_period, 1);
                    
                    // in Charlie's first reward cycle
                    let (amount_ustx, pox_addr, lock_period, first_pox_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).unwrap();
                    eprintln!("\nCharlie: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);
                    
                    assert_eq!(first_reward_cycle, first_pox_reward_cycle);
                    assert_eq!(lock_period, 1);

                    // two reward address, and it's Alice's and Charlie's
                    assert_eq!(reward_addrs.len(), 2);
                    assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                    assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                    assert_eq!(reward_addrs[0].1, 1024 * 1000000);
                    
                    assert_eq!((reward_addrs[1].0).0, AddressHashMode::SerializeP2PKH);
                    assert_eq!((reward_addrs[1].0).1, key_to_stacks_addr(&charlie).bytes);
                    assert_eq!(reward_addrs[1].1, 1024 * 1000000);
               
                    // All of Alice's and Charlie's tokens are locked
                    assert_eq!(alice_balance, 0);
                    assert_eq!(charlie_balance, 0);

                    // Lock-up is consistent with stacker state
                    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_account.stx_balance.amount_unlocked, 0);
                    assert_eq!(alice_account.stx_balance.amount_locked, 1024 * 1000000);
                    assert_eq!(alice_account.stx_balance.unlock_height as u128, (first_reward_cycle + lock_period) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    
                    // Lock-up is consistent with stacker state
                    let charlie_account = get_account(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into());
                    assert_eq!(charlie_account.stx_balance.amount_unlocked, 0);
                    assert_eq!(charlie_account.stx_balance.amount_locked, 1024 * 1000000);
                    assert_eq!(charlie_account.stx_balance.unlock_height as u128, (first_reward_cycle + lock_period) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                }
                else if cur_reward_cycle > first_reward_cycle {
                    test_between_reward_cycles = true;

                    // After Alice's first reward cycle, but before her second.
                    // unlock should have happened
                    assert_eq!(alice_balance, 1024 * 1000000);
                    assert_eq!(charlie_balance, 1024 * 1000000);
    
                    // alice shouldn't be a stacker
                    assert!(get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).is_none());
                    assert!(get_stacker_info(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into()).is_none());
                    
                    // empty reward cycle
                    assert_eq!(reward_addrs.len(), 0);
                
                    // min STX is reset
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    
                    // Unlock is lazy
                    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_account.stx_balance.amount_unlocked, 0);
                    assert_eq!(alice_account.stx_balance.amount_locked, 1024 * 1000000);
                    assert_eq!(alice_account.stx_balance.unlock_height as u128, (first_reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    
                    // Unlock is lazy
                    let charlie_account = get_account(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into());
                    assert_eq!(charlie_account.stx_balance.amount_unlocked, 0);
                    assert_eq!(charlie_account.stx_balance.amount_locked, 1024 * 1000000);
                    assert_eq!(charlie_account.stx_balance.unlock_height as u128, (first_reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                }
            }
            else if second_reward_cycle > 0 {
                if cur_reward_cycle == second_reward_cycle {
                    test_in_second_reward_cycle = true;

                    // in Alice's second reward cycle
                    let (amount_ustx, pox_addr, lock_period, first_pox_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).unwrap();
                    eprintln!("\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; second reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, second_reward_cycle);
                    
                    assert_eq!(first_pox_reward_cycle, second_reward_cycle);
                    assert_eq!(lock_period, 1);
                    
                    // in Charlie's second reward cycle
                    let (amount_ustx, pox_addr, lock_period, first_pox_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into()).unwrap();
                    eprintln!("\nCharlie: {} uSTX stacked for {} cycle(s); addr is {:?}; second reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, second_reward_cycle);
                    
                    assert_eq!(first_pox_reward_cycle, second_reward_cycle);
                    assert_eq!(lock_period, 1);

                    // one reward address, and it's Alice's
                    // either way, there's a single reward address
                    assert_eq!(reward_addrs.len(), 2);
                    assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                    assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                    assert_eq!(reward_addrs[0].1, 512 * 1000000);

                    assert_eq!((reward_addrs[1].0).0, AddressHashMode::SerializeP2PKH);
                    assert_eq!((reward_addrs[1].0).1, key_to_stacks_addr(&charlie).bytes);
                    assert_eq!(reward_addrs[1].1, 512 * 1000000);
               
                    // Half of Alice's tokens are locked
                    assert_eq!(alice_balance, 512 * 1000000);
                    assert_eq!(charlie_balance, 512 * 1000000);

                    // Lock-up is consistent with stacker state
                    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_account.stx_balance.amount_unlocked, 512 * 1000000);
                    assert_eq!(alice_account.stx_balance.amount_locked, 512 * 1000000);
                    assert_eq!(alice_account.stx_balance.unlock_height as u128, (second_reward_cycle + lock_period) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    
                    // Lock-up is consistent with stacker state
                    let charlie_account = get_account(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into());
                    assert_eq!(charlie_account.stx_balance.amount_unlocked, 512 * 1000000);
                    assert_eq!(charlie_account.stx_balance.amount_locked, 512 * 1000000);
                    assert_eq!(charlie_account.stx_balance.unlock_height as u128, (second_reward_cycle + lock_period) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                }
                else if cur_reward_cycle > second_reward_cycle {
                    test_after_second_reward_cycle = true;

                    // After Alice's second reward cycle
                    // unlock should have happened
                    assert_eq!(alice_balance, 1024 * 1000000);
                    assert_eq!(charlie_balance, 1024 * 1000000);
    
                    // alice and charlie shouldn't be stackers
                    assert!(get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).is_none());
                    assert!(get_stacker_info(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into()).is_none());
                    
                    // empty reward cycle
                    assert_eq!(reward_addrs.len(), 0);
                
                    // min STX is reset
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    
                    // Unlock is lazy
                    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_account.stx_balance.amount_unlocked, 512 * 1000000);
                    assert_eq!(alice_account.stx_balance.amount_locked, 512 * 1000000);
                    assert_eq!(alice_account.stx_balance.unlock_height as u128, (second_reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    
                    // Unlock is lazy
                    let charlie_account = get_account(&mut peer, &make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into());
                    assert_eq!(charlie_account.stx_balance.amount_unlocked, 512 * 1000000);
                    assert_eq!(charlie_account.stx_balance.amount_locked, 512 * 1000000);
                    assert_eq!(charlie_account.stx_balance.unlock_height as u128, (second_reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                }
            }
        }

        assert!(test_before_first_reward_cycle);
        assert!(test_in_first_reward_cycle);
        assert!(test_between_reward_cycles);
        assert!(test_in_second_reward_cycle);
        assert!(test_after_second_reward_cycle);
    }
    
    #[test]
    fn test_pox_lockup_unlock_on_spend() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-unlock-on-spend", 6016);

        let num_blocks = 20;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut reward_cycle = 0;

        let mut test_before_first_reward_cycle = false;
        let mut test_in_first_reward_cycle = false;
        let mut test_between_reward_cycles = false;

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
                    // everyone locks up all of their tokens
                    let alice_lockup = make_pox_lockup(&alice, 0, 512 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes, 1);
                    block_txs.push(alice_lockup);
                    
                    let bob_lockup = make_pox_lockup(&bob, 0, 1024 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&bob).bytes, 1);
                    block_txs.push(bob_lockup);
                    
                    let charlie_lockup = make_pox_lockup(&charlie, 0, 1024 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&charlie).bytes, 1);
                    block_txs.push(charlie_lockup);
                    
                    let danielle_lockup = make_pox_lockup(&danielle, 0, 1024 * 1000000, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes, 1);
                    block_txs.push(danielle_lockup);

                    let bob_contract = make_pox_lockup_contract(&bob, 1, "do-lockup");
                    block_txs.push(bob_contract);

                    let alice_stack = make_pox_lockup_contract_call(&alice, 1, &key_to_stacks_addr(&bob), "do-lockup", 512 * 1000000, AddressHashMode::SerializeP2SH, key_to_stacks_addr(&alice).bytes, 1);
                    block_txs.push(alice_stack);
                }
                else if tenure_id >= 2 && tenure_id <= 8 {
                    // try to spend tokens -- they should all fail with short-return
                    let alice_spend = make_bare_contract(&alice, 2, 0, "alice-try-spend", &format!("(begin (unwrap! (stx-transfer? u1 tx-sender '{}) (err 1)))", &key_to_stacks_addr(&danielle)));
                    block_txs.push(alice_spend);
                }
                else if tenure_id == 11 {
                    // Alice sends a transaction with a non-zero fee
                    let alice_tx = make_bare_contract(&alice, 2, 1, "alice-test", "(begin (print \"hello alice\"))");
                    block_txs.push(alice_tx);

                    // Bob sends a STX-transfer transaction 
                    let bob_tx = make_token_transfer(&bob, 2, 0, key_to_stacks_addr(&alice).into(), 1);
                    block_txs.push(bob_tx);

                    // Charlie runs a contract that transfers his STX tokens
                    let charlie_tx = make_bare_contract(&charlie, 1, 0, "charlie-test", &format!("(begin (stx-transfer? u1 tx-sender '{}))", &key_to_stacks_addr(&alice)));
                    block_txs.push(charlie_tx);

                    // Danielle burns some STX
                    let danielle_tx = make_bare_contract(&danielle, 1, 0, "danielle-test", "(begin (stx-burn? u1 tx-sender))");
                    block_txs.push(danielle_tx);

                    // Alice gets some of her STX back
                    let alice_withdraw_tx = make_pox_withdraw_stx_contract_call(&alice, 3, &key_to_stacks_addr(&bob), "do-lockup", 1);
                    block_txs.push(alice_withdraw_tx);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());
            let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

            let stacker_addrs : Vec<PrincipalData> = vec![
                key_to_stacks_addr(&alice).into(),
                key_to_stacks_addr(&bob).into(),
                key_to_stacks_addr(&charlie).into(),
                key_to_stacks_addr(&danielle).into(),
                make_contract_id(&key_to_stacks_addr(&bob), "do-lockup").into(),
            ];

            let expected_pox_addrs : Vec<(AddressHashMode, Hash160)> = vec![
                (AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&alice).bytes),
                (AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&bob).bytes),
                (AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&charlie).bytes),
                (AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes),
                (AddressHashMode::SerializeP2SH, key_to_stacks_addr(&alice).bytes)
            ];

            let balances : Vec<u128> = stacker_addrs
                .iter()
                .map(|principal| get_balance(&mut peer, principal))
                .collect();

            let balances_before_stacking : Vec<u128> = vec![
                1024 * 1000000,
                1024 * 1000000,
                1024 * 1000000,
                1024 * 1000000,
                0
            ];

            let balances_during_stacking : Vec<u128> = vec![
                0,
                0,
                0,
                0,
                0
            ];
            
            let balances_stacked : Vec<u128> = vec![
                512 * 1000000,
                1024 * 1000000,
                1024 * 1000000,
                1024 * 1000000,
                512 * 1000000
            ];
            
            let balances_after_stacking : Vec<u128> = vec![
                512 * 1000000,
                1024 * 1000000,
                1024 * 1000000,
                1024 * 1000000,
                512 * 1000000
            ];
            
            let balances_after_spending : Vec<u128> = vec![
                512 * 1000000 + 2,
                1024 * 1000000 - 1,
                1024 * 1000000 - 1,
                1024 * 1000000 - 1,
                512 * 1000000 - 1
            ];
            
            let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
            let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
            let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)).unwrap();
            
            eprintln!("\ntenure: {}\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);
            
            if tenure_id <= 1 {
                if tenure_id < 1 {
                    // no one has locked
                    for (balance, expected_balance) in balances.iter().zip(balances_before_stacking.iter()) {
                        assert_eq!(balance, expected_balance);
                    }

                    // stacking minimum should be floor(total-liquid-ustx / 20000), because we haven't
                    // stacked yet.
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                }
                else {
                    assert_eq!(min_ustx, total_liquid_ustx / 5000);
                }

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                eprintln!("first reward cycle: {}\ncur reward cycle: {}\n", reward_cycle, cur_reward_cycle);

                assert!(reward_cycle > cur_reward_cycle);
                test_before_first_reward_cycle = true;
            }
            else if tenure_id >= 2 && tenure_id <= 8 {
                // alice did _NOT_ spend
                assert!(get_contract(&mut peer, &make_contract_id(&key_to_stacks_addr(&alice), "alice-try-spend").into()).is_none());
            }

            if reward_cycle > 0 {
                if cur_reward_cycle == reward_cycle {
                    test_in_first_reward_cycle = true;

                    // in reward cycle
                    assert_eq!(reward_addrs.len(), expected_pox_addrs.len());

                    // in stacker order
                    for ((i, pox_addr), expected_stacked) in expected_pox_addrs.iter().enumerate().zip(balances_stacked.iter()) {
                        assert_eq!((reward_addrs[i].0).0, pox_addr.0);
                        assert_eq!((reward_addrs[i].0).1, pox_addr.1);
                        assert_eq!(reward_addrs[i].1, *expected_stacked);
                    }

                    // all stackers are present
                    for addr in stacker_addrs.iter() {
                        let (amount_ustx, pox_addr, lock_period, pox_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, addr).unwrap();
                        eprintln!("\naddr {}: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", addr, amount_ustx, lock_period, &pox_addr, reward_cycle);
                        
                        assert_eq!(pox_reward_cycle, reward_cycle);
                        assert_eq!(lock_period, 1);
                        assert!(delegate_opt.is_none());
                    }

                    // all tokens locked
                    for (balance, expected_balance) in balances.iter().zip(balances_during_stacking.iter()) {
                        assert_eq!(balance, expected_balance);
                    }

                    // Lock-up is consistent with stacker state
                    for (addr, expected_balance) in stacker_addrs.iter().zip(balances_stacked.iter()) {
                        let account = get_account(&mut peer, addr);
                        assert_eq!(account.stx_balance.amount_unlocked, 0);
                        assert_eq!(account.stx_balance.amount_locked, *expected_balance);
                        assert_eq!(account.stx_balance.unlock_height as u128, (reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    }
                }
                else if cur_reward_cycle > reward_cycle {
                    test_between_reward_cycles = true;

                    if tenure_id < 11 {
                        // all balances should have been restored
                        for (balance, expected_balance) in balances.iter().zip(balances_after_stacking.iter()) {
                            assert_eq!(balance, expected_balance);
                        }
                    }
                    else {
                        // some balances reduced, but none are zero
                        for (balance, expected_balance) in balances.iter().zip(balances_after_spending.iter()) {
                            assert_eq!(balance, expected_balance);
                        }
                    }

                    // no one's a stacker
                    for addr in stacker_addrs.iter() {
                        assert!(get_stacker_info(&mut peer, addr).is_none());
                    }

                    // empty reward cycle
                    assert_eq!(reward_addrs.len(), 0);
                
                    // min STX is reset
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);    
                }
            }

            if tenure_id >= 11 {
                // all balances are restored
                for (addr, expected_balance) in stacker_addrs.iter().zip(balances_after_spending.iter()) {
                    let account = get_account(&mut peer, addr);
                    assert_eq!(account.stx_balance.amount_unlocked, *expected_balance);
                    assert_eq!(account.stx_balance.amount_locked, 0);
                    assert_eq!(account.stx_balance.unlock_height, 0);
                }
            }
            else if cur_reward_cycle >= reward_cycle {
                // not unlocked, but unlock is lazy
                for (addr, (expected_locked, expected_balance)) in stacker_addrs.iter().zip(balances_stacked.iter().zip(balances_during_stacking.iter())) {
                    let account = get_account(&mut peer, addr);
                    assert_eq!(account.stx_balance.amount_unlocked, *expected_balance);
                    assert_eq!(account.stx_balance.amount_locked, *expected_locked);
                    assert_eq!(account.stx_balance.unlock_height as u128, (reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                }
            }
        }

        assert!(test_before_first_reward_cycle);
        assert!(test_in_first_reward_cycle);
        assert!(test_between_reward_cycles);
    }
    
    #[test]
    fn test_pox_delegate_lockup_unlock_on_spend() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-delegate-lockup-unlock-on-spend", 6022);

        let num_blocks = 10;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut reward_cycle = 0;

        let mut test_before_first_reward_cycle = false;
        let mut test_in_first_reward_cycle = false;
        let mut test_between_reward_cycles = false;

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
                    // danielle becomes a delegate
                    let danielle_delegate = make_register_delegate(&danielle, 0, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes, parent_tip.burn_header_height as u128, 1);
                    block_txs.push(danielle_delegate);

                    // everyone delegates to Danielle
                    let alice_delegate = make_delegate_stx(&alice, 0, &key_to_stacks_addr(&danielle).into(), 1024 * 1000000);
                    block_txs.push(alice_delegate);
                    
                    let bob_delegate = make_delegate_stx(&bob, 0, &key_to_stacks_addr(&danielle).into(), 1024 * 1000000);
                    block_txs.push(bob_delegate);
                    
                    let charlie_delegate = make_delegate_stx(&charlie, 0, &key_to_stacks_addr(&danielle).into(), 1024 * 1000000);
                    block_txs.push(charlie_delegate);

                    // danielle stacks them all
                    let danielle_stacks = make_delegate(&danielle, 1);
                    block_txs.push(danielle_stacks);
                }
                else if tenure_id >= 2 && tenure_id <= 8 {
                    // try to spend tokens -- they should all fail (i.e. the miner should reject them due to a short-return)
                    let alice_spend = make_bare_contract(&alice, 1, 0, "alice-try-spend", &format!("(begin (unwrap! (stx-transfer? u1 tx-sender '{}) (err 1)))", &key_to_stacks_addr(&danielle)));
                    block_txs.push(alice_spend);
                }
                else if tenure_id == 11 {
                    // Alice sends a transaction with a non-zero fee
                    let alice_tx = make_bare_contract(&alice, 1, 1, "alice-test", "(begin (print \"hello alice\"))");
                    block_txs.push(alice_tx);

                    // Bob sends a STX-transfer transaction 
                    let bob_tx = make_token_transfer(&bob, 1, 0, key_to_stacks_addr(&alice).into(), 1);
                    block_txs.push(bob_tx);

                    // Charlie runs a contract that transfers his STX tokens
                    let charlie_tx = make_bare_contract(&charlie, 1, 0, "charlie-test", &format!("(begin (stx-transfer? u1 tx-sender '{}))", &key_to_stacks_addr(&alice)));
                    block_txs.push(charlie_tx);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());
            let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

            let stacker_addrs : Vec<PrincipalData> = vec![
                key_to_stacks_addr(&alice).into(),
                key_to_stacks_addr(&bob).into(),
                key_to_stacks_addr(&charlie).into(),
            ];

            let expected_pox_addrs : Vec<(AddressHashMode, Hash160)> = vec![
                (AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes),
            ];

            let balances : Vec<u128> = stacker_addrs
                .iter()
                .map(|principal| get_balance(&mut peer, principal))
                .collect();

            let balances_before_stacking : Vec<u128> = vec![
                1024 * 1000000,
                1024 * 1000000,
                1024 * 1000000,
            ];

            let balances_during_stacking : Vec<u128> = vec![
                0,
                0,
                0
            ];
            
            let balances_stacked : Vec<u128> = vec![
                3 * 1024 * 1000000,
            ];
            
            let balances_after_stacking : Vec<u128> = vec![
                1024 * 1000000,
                1024 * 1000000,
                1024 * 1000000,
            ];
            
            let balances_after_spending : Vec<u128> = vec![
                1024 * 1000000 + 1,
                1024 * 1000000 - 1,
                1024 * 1000000 - 1,
            ];
            
            let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
            let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
            let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)).unwrap();
            
            eprintln!("\ntenure: {}\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\n", tenure_id, cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked);
            
            if tenure_id <= 1 {
                if tenure_id < 1 {
                    // no one has locked
                    for (balance, expected_balance) in balances.iter().zip(balances_before_stacking.iter()) {
                        assert_eq!(balance, expected_balance);
                    }

                    // stacking minimum should be floor(total-liquid-ustx / 20000), because we haven't
                    // stacked yet.
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                }
                else {
                    assert_eq!(min_ustx, total_liquid_ustx / 5000);
                }

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                eprintln!("first reward cycle: {}\ncur reward cycle: {}\n", reward_cycle, cur_reward_cycle);

                assert!(reward_cycle > cur_reward_cycle);
                test_before_first_reward_cycle = true;
            }
            else if tenure_id >= 2 && tenure_id <= 10 {
                // alice did _NOT_ spend
                assert!(get_contract(&mut peer, &make_contract_id(&key_to_stacks_addr(&alice), "alice-try-spend").into()).is_none());
            }

            if reward_cycle > 0 {
                if cur_reward_cycle == reward_cycle {
                    test_in_first_reward_cycle = true;

                    // in reward cycle
                    assert_eq!(reward_addrs.len(), expected_pox_addrs.len());

                    // in stacker order
                    for ((i, pox_addr), expected_stacked) in expected_pox_addrs.iter().enumerate().zip(balances_stacked.iter()) {
                        assert_eq!((reward_addrs[i].0).0, pox_addr.0);
                        assert_eq!((reward_addrs[i].0).1, pox_addr.1);
                        assert_eq!(reward_addrs[i].1, *expected_stacked);
                    }

                    // all stackers are present, and Danielle is their delegate
                    for addr in stacker_addrs.iter() {
                        let (amount_ustx, pox_addr, lock_period, pox_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, addr).unwrap();
                        eprintln!("\naddr {}: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", addr, amount_ustx, lock_period, &pox_addr, reward_cycle);
                        
                        assert_eq!(pox_reward_cycle, reward_cycle);
                        assert_eq!(lock_period, 1);
                        assert_eq!(delegate_opt, Some(key_to_stacks_addr(&danielle).into()));
                    }

                    // danielle is also a stacker
                    {
                        let (amount_ustx, pox_addr, lock_period, pox_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &key_to_stacks_addr(&danielle).into()).unwrap();
                        eprintln!("\naddr {}: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", &key_to_stacks_addr(&danielle), amount_ustx, lock_period, &pox_addr, reward_cycle);
                        
                        assert_eq!(pox_reward_cycle, reward_cycle);
                        assert_eq!(lock_period, 1);
                        assert_eq!(delegate_opt, None);
                    }

                    // all tokens locked
                    for (balance, expected_balance) in balances.iter().zip(balances_during_stacking.iter()) {
                        assert_eq!(balance, expected_balance);
                    }

                    // Lock-up is consistent with stacker state
                    for (addr, expected_balance) in stacker_addrs.iter().zip(balances_before_stacking.iter()) {
                        let account = get_account(&mut peer, addr);
                        assert_eq!(account.stx_balance.amount_unlocked, 0);
                        assert_eq!(account.stx_balance.amount_locked, *expected_balance);
                        assert_eq!(account.stx_balance.unlock_height as u128, (reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                    }
                }
                else if cur_reward_cycle > reward_cycle {
                    test_between_reward_cycles = true;

                    if tenure_id < 11 {
                        // all balances should have been restored
                        for (balance, expected_balance) in balances.iter().zip(balances_after_stacking.iter()) {
                            assert_eq!(balance, expected_balance);
                        }
                    }
                    else {
                        // some balances reduced, but none are zero
                        for (balance, expected_balance) in balances.iter().zip(balances_after_spending.iter()) {
                            assert_eq!(balance, expected_balance);
                        }
                    }

                    // no one's a stacker
                    for addr in stacker_addrs.iter() {
                        assert!(get_stacker_info(&mut peer, addr).is_none());
                    }
                    
                    // danielle is not a stacker
                    assert!(get_stacker_info(&mut peer, &key_to_stacks_addr(&danielle).into()).is_none());

                    // empty reward cycle
                    assert_eq!(reward_addrs.len(), 0);

                    // min STX is reset
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);    
                }
            }

            if tenure_id >= 11 {
                // all balances are restored
                for (addr, expected_balance) in stacker_addrs.iter().zip(balances_after_spending.iter()) {
                    let account = get_account(&mut peer, addr);
                    assert_eq!(account.stx_balance.amount_unlocked, *expected_balance);
                    assert_eq!(account.stx_balance.amount_locked, 0);
                    assert_eq!(account.stx_balance.unlock_height, 0);
                }
            }
            else if cur_reward_cycle >= reward_cycle {
                // not unlocked, but unlock is lazy
                for (addr, expected_balance) in stacker_addrs.iter().zip(balances_before_stacking.iter()) {
                    let account = get_account(&mut peer, addr);
                    assert_eq!(account.stx_balance.amount_unlocked, 0);
                    assert_eq!(account.stx_balance.amount_locked, *expected_balance);
                    assert_eq!(account.stx_balance.unlock_height as u128, (reward_cycle + 1) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                }
            }
        }

        assert!(test_before_first_reward_cycle);
        assert!(test_in_first_reward_cycle);
        assert!(test_between_reward_cycles);
    }
    
    #[test]
    fn test_pox_lockup_reject() {
        let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash([0u8; 32]));
        burnchain.pox_constants.reward_cycle_length = 5;
        burnchain.pox_constants.prepare_length = 2;
        burnchain.pox_constants.pox_rejection_fraction = 25;

        let (mut peer, mut keys) = instantiate_pox_peer(&burnchain, "test-pox-lockup-reject", 6024);

        let num_blocks = 15;

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

                    // Bob rejects with exactly 25% of the liquid STX supply (shouldn't affect
                    // anything).
                    let bob_reject = make_pox_reject(&bob, 0);
                    block_txs.push(bob_reject);

                    // Danielle becomes a delegator
                    let danielle_delegate = make_register_delegate(&danielle, 0, AddressHashMode::SerializeP2PKH, key_to_stacks_addr(&danielle).bytes, parent_tip.burn_header_height as u128, 12);
                    block_txs.push(danielle_delegate);
                }
                else if tenure_id == 2 {
                    // Charlie rejects
                    let charlie_reject = make_pox_reject(&charlie, 0);
                    block_txs.push(charlie_reject);

                    // Charlie tries to stack, but it should fail.
                    // Specifically, (stack-stx) should fail with (err 17).
                    // If it's the case, then this tx will NOT be mined.
                    let charlie_stack = make_bare_contract(&charlie, 1, 0, "charlie-try-stack",
                        &format!(
                            "(asserts! (not (is-eq (contract-call? '{}.pox stack-stx u1 {{ version: 0x01, hashbytes: 0x1111111111111111111111111111111111111111 }} u1) (err 17))) (err 1))",
                            boot_code_addr()));

                    block_txs.push(charlie_stack);
                    
                    // Charlie tries to stack to a delegator, but it should fail
                    // Specifically, (delegate-stx) should fail with (err 17).
                    // If it's the case, then this tx will NOT be mined.
                    let charlie_stack_delegator = make_bare_contract(&charlie, 1, 0, "charlie-try-stack-delegator",
                        &format!(
                            "(asserts! (not (is-eq (contract-call? '{}.pox delegate-stx '{} u1) (err 17))) (err 1))",
                            boot_code_addr(), &key_to_stacks_addr(&danielle)));

                    block_txs.push(charlie_stack_delegator);

                    // Alice tries to reject, but it should fail.
                    // Specifically, (reject-pox) should fail with (err 3) since Alice already
                    // stacked.
                    // If it's the case, then this tx will NOT be mined
                    let alice_reject = make_bare_contract(&alice, 1, 0, "alice-try-reject",
                        &format!(
                            "(asserts! (not (is-eq (contract-call? '{}.pox reject-pox) (err 3))) (err 1))",
                            boot_code_addr()));
                    
                    block_txs.push(alice_reject);

                    // Charlie tries to reject again, but it should fail.
                    // Specifically, (reject-pox) should fail with (err 17).
                    // If it's the case, then this tx will NOT be mined.
                    let charlie_reject = make_bare_contract(&charlie, 1, 0, "charlie-try-reject",
                        &format!(
                            "(asserts! (not (is-eq (contract-call? '{}.pox reject-pox) (err 17))) (err 1))",
                            boot_code_addr()));
                    
                    block_txs.push(charlie_reject);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();

                if tenure_id == 2 {
                    assert_eq!(anchored_block.txs.len(), 2);
                }

                (anchored_block, vec![])
            });

            let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);
            let tip_index_block = StacksBlockHeader::make_index_block_hash(&consensus_hash, &stacks_block.block_hash());
            let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
            let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());

            let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb, &tip_index_block)).unwrap();
            let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(&burnchain, sortdb, &tip_index_block)).unwrap();
            let total_stacked = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)).unwrap();
            let total_stacked_next = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle + 1)).unwrap();
            
            eprintln!("\ntenure: {}\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\ntotal-stacked: {}\ntotal-stacked next: {}\n", 
                      tenure_id, cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx, total_stacked, total_stacked_next);

            if tenure_id <= 1 {
                if tenure_id < 1 {
                    // Alice has not locked up STX
                    assert_eq!(alice_balance, 1024 * 1000000);

                    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_account.stx_balance.amount_unlocked, 1024 * 1000000);
                    assert_eq!(alice_account.stx_balance.amount_locked, 0);
                    assert_eq!(alice_account.stx_balance.unlock_height, 0);
                
                    // stacking minimum should be floor(total-liquid-ustx / 20000)
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                }
                else {
                    assert_eq!(min_ustx, total_liquid_ustx / 5000);
                }

                // no reward addresses
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                alice_reward_cycle = 1 + peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();
                let cur_reward_cycle = peer.chainstate().get_reward_cycle(&burnchain, &tip_index_block).unwrap();

                eprintln!("\nalice reward cycle: {}\ncur reward cycle: {}\n", alice_reward_cycle, cur_reward_cycle);
            }
            else {
                if tenure_id == 2 {
                    // charlie's contract did NOT materialize
                    assert!(get_contract(&mut peer, &make_contract_id(&key_to_stacks_addr(&charlie), "charlie-try-stack").into()).is_none());
                    assert!(get_contract(&mut peer, &make_contract_id(&key_to_stacks_addr(&charlie), "charlie-try-stack-delegator").into()).is_none());
                    assert!(get_contract(&mut peer, &make_contract_id(&key_to_stacks_addr(&charlie), "charlie-try-reject").into()).is_none());

                    // alice's contract did NOT materialize
                    assert!(get_contract(&mut peer, &make_contract_id(&key_to_stacks_addr(&alice), "alice-try-reject").into()).is_none());
                }

                // Alice's address is locked as of the next reward cycle
                // Alice has locked up STX no matter what
                assert_eq!(alice_balance, 0);

                if cur_reward_cycle >= alice_reward_cycle {
                    // this will grow as more miner rewards are unlocked, so be wary
                    if tenure_id >= (MINER_REWARD_MATURITY + MINER_REWARD_WINDOW + 1) as usize {
                        // miner rewards increased liquid supply, so less than 25% is locked.
                        // minimum participation decreases.
                        assert!(total_liquid_ustx > 4 * 1024 * 1000000);
                        assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    }
                    else {
                        // still at 25% or more locked
                        assert!(total_liquid_ustx <= 4 * 1024 * 1000000);
                    }

                    let (amount_ustx, pox_addr, lock_period, first_reward_cycle, delegate_opt) = get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).unwrap();
                    eprintln!("\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);
                    
                    if cur_reward_cycle == alice_reward_cycle {
                        // charlie rejected in this cycle, so no reward address
                        assert_eq!(reward_addrs.len(), 0);
                    }
                    else {
                        // charlie didn't reject this cycle, so Alice's reward address should be
                        // present
                        assert_eq!(reward_addrs.len(), 1);
                        assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                        assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                        assert_eq!(reward_addrs[0].1, 1024 * 1000000);
                    }

                    // Lock-up is consistent with stacker state
                    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
                    assert_eq!(alice_account.stx_balance.amount_unlocked, 0);
                    assert_eq!(alice_account.stx_balance.amount_locked, 1024 * 1000000);
                    assert_eq!(alice_account.stx_balance.unlock_height as u128, (first_reward_cycle + lock_period) * (burnchain.pox_constants.reward_cycle_length as u128) + (burnchain.first_block_height as u128));
                }
                else {
                    // no reward addresses
                    assert_eq!(reward_addrs.len(), 0);
                }
            }
        }
    }

    // TODO: need Stacking-rejection with a BTC address -- contract name in OP_RETURN? (NEXT)
}
