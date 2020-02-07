use super::{MarfedKV, ClarityBackingStore};
use vm::errors::{ InterpreterResult as Result };
use chainstate::burn::BlockHeaderHash;
use std::collections::{HashMap};
use util::hash::{Sha512Trunc256Sum};
use vm::types::QualifiedContractIdentifier;
use std::{cmp::Eq, hash::Hash, clone::Clone};

pub struct RollbackContext {
    edits: Vec<(String, String)>,
    metadata_edits: Vec<((QualifiedContractIdentifier, String), String)>,
}

pub struct RollbackWrapper <'a> {
    // the underlying key-value storage.
    store: &'a mut dyn ClarityBackingStore,
    // lookup_map is a history of edits for a given key.
    //   in order of least-recent to most-recent at the tail.
    //   this allows ~ O(1) lookups, and ~ O(1) commits, roll-backs (amortized by # of PUTs).
    lookup_map: HashMap<String, Vec<String>>,
    metadata_lookup_map: HashMap<(QualifiedContractIdentifier, String), Vec<String>>,
    // stack keeps track of the most recent rollback context, which tells us which
    //   edits were performed by which context. at the moment, each context's edit history
    //   is a separate Vec which must be drained into the parent on commits, meaning that
    //   the amortized cost of committing a value isn't O(1), but actually O(k) where k is
    //   stack depth.
    //  TODO: The solution to this is to just have a _single_ edit stack, and merely store indexes
    //   to indicate a given contexts "start depth".
    stack: Vec<RollbackContext>
}

fn rollback_lookup_map<T>(key: &T, value: &String, lookup_map: &mut HashMap<T, Vec<String>>)
where T: Eq + Hash + Clone {
    let remove_edit_deque = {
        let key_edit_history = lookup_map.get_mut(key)
            .expect("ERROR: Clarity VM had edit log entry, but not lookup_map entry");
        let popped_value = key_edit_history.pop();
        assert_eq!(popped_value.as_ref(), Some(value));
        key_edit_history.len() == 0
    };
    if remove_edit_deque {
        lookup_map.remove(key);
    }
}

impl <'a> RollbackWrapper <'a> {
    pub fn new(store: &'a mut dyn ClarityBackingStore) -> RollbackWrapper {
        RollbackWrapper {
            store: store,
            lookup_map: HashMap::new(),
            metadata_lookup_map: HashMap::new(),
            stack: Vec::new()
        }
    }

    pub fn nest(&mut self) {
        self.stack.push(RollbackContext { edits: Vec::new(),
                                          metadata_edits: Vec::new() });
    }

    // Rollback the child's edits.
    //   this clears all edits from the child's edit queue,
    //     and removes any of those edits from the lookup map.
    pub fn rollback(&mut self) {
        let mut last_item = self.stack.pop()
            .expect("ERROR: Clarity VM attempted to commit past the stack.");

        last_item.edits.reverse();
        last_item.metadata_edits.reverse();

        for (key, value) in last_item.edits.drain(..) {
            rollback_lookup_map(&key, &value, &mut self.lookup_map);
        }

        for (key, value) in last_item.metadata_edits.drain(..) {
            rollback_lookup_map(&key, &value, &mut self.metadata_lookup_map);
        }
    }

    pub fn commit(&mut self) {
        let mut last_item = self.stack.pop()
            .expect("ERROR: Clarity VM attempted to commit past the stack.");

        if self.stack.len() == 0 {
            // committing to the backing store
            // reverse the lookup_map entries, because we want to commit them
            //   in the order they were performed, but we want to use pop()
            //   rather than remove(0)
            for (_, edit_history) in self.lookup_map.iter_mut() {
                edit_history.reverse();
            }
            for (key, value) in last_item.edits.iter() {
                rollback_lookup_map(key, &value, &mut self.lookup_map);
            }
            assert!(self.lookup_map.len() == 0);
            if last_item.edits.len() > 0 {
                self.store.put_all(last_item.edits);
            }


            for (_, edit_history) in self.metadata_lookup_map.iter_mut() {
                edit_history.reverse();
            }
            for (key, value) in last_item.metadata_edits.iter() {
                rollback_lookup_map(key, &value, &mut self.metadata_lookup_map);
            }
            assert!(self.metadata_lookup_map.len() == 0);
            if last_item.metadata_edits.len() > 0 {
                self.store.put_all_metadata(last_item.metadata_edits);
            }
        } else {
            // bubble up to the next item in the stack
            let next_up = self.stack.last_mut().unwrap();
            for (key, value) in last_item.edits.drain(..) {
                next_up.edits.push((key, value));
            }
            for (key, value) in last_item.metadata_edits.drain(..) {
                next_up.metadata_edits.push((key, value));
            }
        }
    }
}

fn inner_put<T>(lookup_map: &mut HashMap<T, Vec<String>>, edits: &mut Vec<(T, String)>, key: T, value: String)
where T: Eq + Hash + Clone {
    if !lookup_map.contains_key(&key) {
        lookup_map.insert(key.clone(), Vec::new());
    }
    let key_edit_deque = lookup_map.get_mut(&key).unwrap();
    key_edit_deque.push(value.clone());

    edits.push((key, value));
}

impl <'a> RollbackWrapper <'a> {
    pub fn put(&mut self, key: &str, value: &str) {
        let current = self.stack.last_mut()
            .expect("ERROR: Clarity VM attempted PUT on non-nested context.");

        inner_put(&mut self.lookup_map, &mut current.edits, key.to_string(), value.to_string())
    }

    pub fn set_block_hash(&mut self, bhh: BlockHeaderHash) -> Result<BlockHeaderHash> {
        self.store.set_block_hash(bhh)
    }

    pub fn get(&mut self, key: &str) -> Option<String> {
        self.stack.last()
            .expect("ERROR: Clarity VM attempted GET on non-nested context.");

        let lookup_result = self.lookup_map.get(key)
            .and_then(|x| x.last().cloned());

        lookup_result
            .or_else(|| self.store.get(key))
    }

    pub fn get_current_block_height(&mut self) -> u32 {
        self.store.get_current_block_height()
    }

    pub fn get_block_header_hash(&mut self, block_height: u32) -> Option<BlockHeaderHash> {
        self.store.get_block_at_height(block_height)
    }

    pub fn prepare_for_contract_metadata(&mut self, contract: &QualifiedContractIdentifier, content_hash: Sha512Trunc256Sum) {
        let key = MarfedKV::make_contract_hash_key(contract);
        let value = self.store.make_contract_commitment(content_hash);
        self.put(&key, &value)
    }

    pub fn insert_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str, value: &str) {
        let current = self.stack.last_mut()
            .expect("ERROR: Clarity VM attempted PUT on non-nested context.");

        let metadata_key = (contract.clone(), key.to_string());

        inner_put(&mut self.metadata_lookup_map, &mut current.metadata_edits, metadata_key, value.to_string())
    }

    // Throws a NoSuchContract error if contract doesn't exist,
    //   returns None if there is no such metadata field.
    pub fn get_metadata(&mut self, contract: &QualifiedContractIdentifier, key: &str) -> Result<Option<String>> {
        self.stack.last()
            .expect("ERROR: Clarity VM attempted GET on non-nested context.");

        // This is THEORETICALLY a spurious clone, but it's hard to turn something like
        //  (&A, &B) into &(A, B).
        let metadata_key = (contract.clone(), key.to_string());
        let lookup_result = self.metadata_lookup_map.get(&metadata_key)
            .and_then(|x| x.last().cloned());

        match lookup_result {
            Some(x) => Ok(Some(x)),
            None => {
                self.store.get_metadata(contract, key)
            }
        }
    }

    pub fn has_entry(&mut self, key: &str) -> bool {
        self.stack.last()
            .expect("ERROR: Clarity VM attempted GET on non-nested context.");
        if self.lookup_map.contains_key(key) {
            true
        } else {
            self.store.has_entry(key)
        }
    }

    pub fn has_metadata_entry(&mut self, contract: &QualifiedContractIdentifier, key: &str) -> bool {
        match self.get_metadata(contract, key) {
            Ok(Some(_)) => true,
            _ => false
        }
    }
}
