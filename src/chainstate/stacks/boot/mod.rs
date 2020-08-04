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
};

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

fn boot_code_addr() -> StacksAddress {
    StacksAddress::from_string(&STACKS_BOOT_CODE_CONTRACT_ADDRESS.clone()).unwrap()
}    

fn boot_code_id(name: &str) -> QualifiedContractIdentifier {
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
}

impl StacksChainState {
    fn eval_boot_code_read_only_at_chain_tip(&mut self, sortdb: &SortitionDB, boot_contract_name: &str, code: &str) -> Result<Value, Error> {
        let (consensus_hash, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash_stubbed(sortdb.conn()).unwrap();
        let stacks_block_id = StacksBlockHeader::make_index_block_hash(&consensus_hash, &block_bhh);
        let iconn = sortdb.index_conn();
        self.clarity_eval_read_only_checked(&iconn, &stacks_block_id, &boot_code_id(boot_contract_name), code)
    }

    /// Call (get-current-reward-cycle) at the canonical chain tip to get the current PoX reward
    /// cycle ID.
    pub fn get_current_reward_cycle(&mut self, sortdb: &SortitionDB) -> Result<u128, Error> {
        self.eval_boot_code_read_only_at_chain_tip(sortdb, "pox-api", "(get-current-reward-cycle)")
            .map(|value| value.expect_u128())
    }

    /// Call (get-stacking-minimum) at the canonical chain tip to get the current minimum PoX stack
    /// amount, in uSTX
    pub fn get_stacking_minimum(&mut self, sortdb: &SortitionDB) -> Result<u128, Error> {
        self.eval_boot_code_read_only_at_chain_tip(sortdb, "pox-api", "(get-stacking-minimum)")
            .map(|value| value.expect_u128())
    }

    /// List all PoX addresses and amount of uSTX stacked.
    /// Each address will have at least (get-stacking-minimum) tokens.
    pub fn get_reward_addresses(&mut self, sortdb: &SortitionDB) -> Result<Vec<((AddressHashMode, Hash160), u128)>, Error> {
        let reward_cycle = self.get_current_reward_cycle(sortdb)?;

        // how many in this cycle?
        let num_addrs = self.eval_boot_code_read_only_at_chain_tip(sortdb, "pox-api", &format!("(get-reward-set-size u{})", reward_cycle))
            .map(|value| value.expect_u128())?;

        let mut ret = vec![];
        for i in 0..num_addrs {
            match self.eval_boot_code_read_only_at_chain_tip(sortdb, "pox-api", &format!("(get-reward-set-pox-address u{} u{})", reward_cycle, i))? {
                Value::Optional(opt) => match opt.data {
                    Some(boxed_tuple_data) => match *boxed_tuple_data {
                        Value::Tuple(tuple_data) => {
                            let pox_addr_tuple = tuple_data.get("pox-addr")
                                .expect(&format!("FATAL: no 'pox-addr' in return value from (get-reward-set-pox-address u{} u{})", reward_cycle, i))
                                .to_owned();

                            let pox_addr =
                                if let Value::Tuple(pox_addr_data) = pox_addr_tuple {
                                    tuple_to_pox_addr(pox_addr_data)
                                }
                                else {
                                    panic!("FATAL: invalid PoX tuple structure");
                                };

                            let total_ustx = tuple_data.get("total-ustx")
                                .expect(&format!("FATAL: no 'total-ustx' in return value from (get-reward-set-pox-address u{} u{})", reward_cycle, i))
                                .to_owned()
                                .expect_u128();

                            ret.push((pox_addr, total_ustx));
                        },
                        _ => {
                            // inconsistency
                            panic!(format!("FATAL: got 'some' non-tuple value on (get-reward-set-pox-address {} {})", reward_cycle, i));
                        }
                    },
                    None => {
                        // inconsistency
                        panic!(format!("FATAL: got 'none' on (get-reward-set-pox-address {} {})", reward_cycle, i));
                    }
                },
                _ => {
                    // inconsistency
                    panic!(format!("FATAL: got non-option value on (get-reward-set-pox-address {} {})", reward_cycle, i));
                }
            }
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

    impl Value {
        fn expect_result_err(self) -> Value {
            if let Value::Response(res_data) = self {
                if !res_data.committed {
                    *res_data.data
                }
                else {
                    panic!("FATAL: not a (err ..)");
                }
            }
            else {
                panic!("FATAL: not a (response ..)");
            }
        }
    }

    fn key_to_stacks_addr(key: &StacksPrivateKey) -> StacksAddress {
        StacksAddress::from_public_keys(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, &AddressHashMode::SerializeP2PKH, 1, &vec![StacksPublicKey::from_private(key)]).unwrap()
    }
    
    fn instantiate_pox_peer(test_name: &str, port: u16) -> (TestPeer, Vec<StacksPrivateKey>) {
        let mut peer_config = TestPeerConfig::new(test_name, port, port + 1);

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
        let (consensus_hash, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash_stubbed(sortdb.conn()).unwrap();
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
        let (consensus_hash, block_bhh) = SortitionDB::get_canonical_stacks_chain_tip_hash_stubbed(sortdb.conn()).unwrap();
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

    fn get_parent_tip(parent_opt: &Option<&StacksBlock>, chainstate: &StacksChainState, sortdb: &SortitionDB) -> StacksHeaderInfo {
        let tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(sortdb.conn()).unwrap();
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
        let (mut peer, keys) = instantiate_pox_peer("test-liquid-ustx", 6000);

        let num_blocks = 10;
        let mut expected_liquid_ustx = 1024 * 1000000 * (keys.len() as u128); 

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

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
    fn test_pox_lockup_single() {
        let (mut peer, mut keys) = instantiate_pox_peer("test-pox-lockup-single", 6002);

        let num_blocks = 10;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut alice_reward_cycle = 0;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

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

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);

            if tenure_id <= 1 {
                if tenure_id < 1 {
                    // Alice has not locked up STX
                    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                    assert_eq!(alice_balance, 1024 * 1000000);
                }

                // stacking minimum should be floor(total-liquid-ustx / 20000)
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb)).unwrap();
                assert_eq!(min_ustx, total_liquid_ustx / 20000);

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                alice_reward_cycle = 1 + with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();
                let cur_reward_cycle = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();

                eprintln!("\nalice reward cycle: {}\ncur reward cycle: {}\n", alice_reward_cycle, cur_reward_cycle);
            }
            else {
                // Alice's address is locked as of the next reward cycle
                let cur_reward_cycle = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();

                // Alice has locked up STX no matter what
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 0);
                
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                
                eprintln!("\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal_liquid_ustx: {}\n", cur_reward_cycle, min_ustx, &reward_addrs, total_liquid_ustx);

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
    fn test_pox_lockup_multi() {
        let (mut peer, mut keys) = instantiate_pox_peer("test-pox-lockup-multi", 6004);

        let num_blocks = 10;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut first_reward_cycle = 0;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

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

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);

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
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb)).unwrap();
                assert_eq!(min_ustx, total_liquid_ustx / 20000);

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                first_reward_cycle = 1 + with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();
                let cur_reward_cycle = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();

                eprintln!("\nalice reward cycle: {}\ncur reward cycle: {}\n", first_reward_cycle, cur_reward_cycle);
            }
            else {
                // Alice's and Bob's addresses are locked as of the next reward cycle
                let cur_reward_cycle = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();

                // Alice and Bob have locked up STX no matter what
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 0);
                
                let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob));
                assert_eq!(bob_balance, 1024 * 1000000 - (4 * 1024 * 1000000) / 5);
                
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                
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
        let (mut peer, mut keys) = instantiate_pox_peer("test-pox-lockup-no-double-stacking", 6006);

        let num_blocks = 3;

        let alice = keys.pop().unwrap();
        let bob = keys.pop().unwrap();
        let charlie = keys.pop().unwrap();
        let danielle = keys.pop().unwrap();

        let mut first_reward_cycle = 0;

        for tenure_id in 0..num_blocks {
            let microblock_privkey = StacksPrivateKey::new();
            let microblock_pubkeyhash = Hash160::from_data(&StacksPublicKey::from_private(&microblock_privkey).to_bytes());
            let tip = SortitionDB::get_canonical_burn_chain_tip_stubbed(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

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
                    let bob_test_tx = make_bare_contract(&bob, 0, "bob-test", &format!(
                        "(define-data-var bob-test-run bool false)
                        (begin
                            (asserts! (is-eq (err 12) (contract-call? '{}.pox-api stack-stx u256000000 (tuple (version u0) (hashbytes 0xae1593226f85e49a7eaff5b633ff687695438cc9)) u12))
                                (err \"Failed duplicate PoX address check\"))

                            (var-set bob-test-run true)
                        )
                        ", STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                    block_txs.push(bob_test_tx);

                    let alice_test_tx = make_bare_contract(&alice, 2, "alice-test", &format!(
                        "(define-data-var alice-test-run bool false)
                        (begin
                            (asserts! (is-eq (err 3) (contract-call? '{}.pox-api stack-stx u512000000 (tuple (version u0) (hashbytes 0xffffffffffffffffffffffffffffffffffffffff)) u12))
                                (err \"Failed duplicate stacker check\"))

                            (var-set alice-test-run true)
                        )
                        ", STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                    block_txs.push(alice_test_tx);

                    let charlie_test_tx = make_bare_contract(&charlie, 0, "charlie-test", &format!(
                        "(define-data-var charlie-test-run bool false)
                        (begin
                            (asserts! (is-eq (err 1) (contract-call? '{}.pox-api stack-stx u1024000000000 (tuple (version u0) (hashbytes 0xfefefefefefefefefefefefefefefefefefefefe)) u12))
                                (err \"Failed insufficient funds check\"))

                            (var-set charlie-test-run true)
                        )
                        ", STACKS_BOOT_CODE_CONTRACT_ADDRESS));

                    block_txs.push(charlie_test_tx);
                }

                let block_builder = StacksBlockBuilder::make_block_builder(&parent_tip, vrf_proof, tip.total_burn, microblock_pubkeyhash).unwrap();
                let (anchored_block, _size, _cost) = StacksBlockBuilder::make_anchored_block_from_txs(block_builder, chainstate, &sortdb.index_conn(), block_txs).unwrap();
                (anchored_block, vec![])
            });

            peer.next_burnchain_block(burn_ops.clone());
            peer.process_stacks_epoch_at_tip(&stacks_block, &microblocks);

            let total_liquid_ustx = get_liquid_ustx(&mut peer);

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
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb)).unwrap();
                assert_eq!(min_ustx, total_liquid_ustx / 20000);

                // no reward addresses
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                assert_eq!(reward_addrs.len(), 0);

                // record the first reward cycle when Alice's tokens get stacked
                first_reward_cycle = 1 + with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();
                let cur_reward_cycle = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();

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
            /*
            else {
                // Alice's single address is locked as of the next reward cycle
                let cur_reward_cycle = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_current_reward_cycle(sortdb)).unwrap();

                // Alice has locked up STX no matter what
                let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice));
                assert_eq!(alice_balance, 1024 * 1000000 / 2);
                
                let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_stacking_minimum(sortdb)).unwrap();
                let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| chainstate.get_reward_addresses(sortdb)).unwrap();
                
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
                    
                    // well under 25% locked, so this is always true
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);

                    // only a single address (Alice's)
                    assert_eq!(reward_addrs.len(), 1);
                    assert_eq!((reward_addrs[0].0).0, AddressHashMode::SerializeP2PKH);
                    assert_eq!((reward_addrs[0].0).1, key_to_stacks_addr(&alice).bytes);
                    assert_eq!(reward_addrs[0].1, 1024 * 1000000 / 2);
                }
                else {
                    // no reward addresses
                    assert_eq!(min_ustx, total_liquid_ustx / 20000);
                    assert_eq!(reward_addrs.len(), 0);
                }
            }
            */
        }
    }
}
