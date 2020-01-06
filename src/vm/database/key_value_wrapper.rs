use super::MarfedKV;
use vm::errors::{ InterpreterResult as Result };
use chainstate::burn::BlockHeaderHash;
use std::collections::{HashMap};

// These functions _do not_ return errors, rather, any errors in the underlying storage
//    will _panic_. The rationale for this is that under no condition should the interpreter
//    attempt to continue processing in the event of an unexpected storage error.
pub trait KeyValueStorage {
    fn put(&mut self, key: &str, value: &str);
    fn get(&mut self, key: &str) -> Option<String>;
    fn has_entry(&mut self, key: &str) -> bool;

    fn put_non_consensus(&mut self, key: &str, value: &str);
    fn get_non_consensus(&mut self, key: &str) -> Option<String>;

    /// begin, commit, rollback a save point identified by key
    ///    not all backends will implement this! this is used to clean up
    ///     any data from aborted blocks (not aborted transactions! that is handled
    ///      by the clarity vm directly).
    /// The block header hash is used for identifying savepoints.
    ///     this _cannot_ be used to rollback to arbitrary prior block hash, because that
    ///     blockhash would already have committed and no longer exist in the save point stack.
    /// this is a "lower-level" rollback than the roll backs performed in
    ///   ClarityDatabase or AnalysisDatabase -- this is done at the backing store level.
    fn begin(&mut self, _key: &BlockHeaderHash) {}
    fn commit(&mut self, _key: &BlockHeaderHash) {}
    fn rollback(&mut self, _key: &BlockHeaderHash) {}

    /// returns the previous block header hash on success
    fn set_block_hash(&mut self, _bhh: BlockHeaderHash) -> Result<BlockHeaderHash> {
        panic!("Attempted to evaluate changed block height with a generic backend");
    } 

    fn put_all(&mut self, mut items: Vec<(String, String)>) {
        for (key, value) in items.drain(..) {
            self.put(&key, &value);
        }
    }

}

pub struct RollbackContext {
    edits: Vec<(String, String)>,
    non_consensus_edits: Vec<(String, String)>,
}

pub struct RollbackWrapper <'a> {
    // the underlying key-value storage.
    store: &'a mut MarfedKV,
    // lookup_map is a history of edits for a given key.
    //   in order of least-recent to most-recent at the tail.
    //   this allows ~ O(1) lookups, and ~ O(1) commits, roll-backs (amortized by # of PUTs).
    lookup_map: HashMap<String, Vec<String>>,
    non_consensus_lookup_map: HashMap<String, Vec<String>>,
    // stack keeps track of the most recent rollback context, which tells us which
    //   edits were performed by which context. at the moment, each context's edit history
    //   is a separate Vec which must be drained into the parent on commits, meaning that
    //   the amortized cost of committing a value isn't O(1), but actually O(k) where k is
    //   stack depth.
    //  TODO: The solution to this is to just have a _single_ edit stack, and merely store indexes
    //   to indicate a given contexts "start depth".
    stack: Vec<RollbackContext>
}

fn rollback_lookup_map(key: &String, value: &String, lookup_map: &mut HashMap<String, Vec<String>>) {
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
    pub fn new(store: &'a mut MarfedKV) -> RollbackWrapper {
        RollbackWrapper {
            store: store,
            lookup_map: HashMap::new(),
            non_consensus_lookup_map: HashMap::new(),
            stack: Vec::new()
        }
    }

    pub fn nest(&mut self) {
        self.stack.push(RollbackContext { edits: Vec::new(),
                                          non_consensus_edits: Vec::new() });
    }

    // Rollback the child's edits.
    //   this clears all edits from the child's edit queue,
    //     and removes any of those edits from the lookup map.
    pub fn rollback(&mut self) {
        let mut last_item = self.stack.pop()
            .expect("ERROR: Clarity VM attempted to commit past the stack.");

        last_item.edits.reverse();
        last_item.non_consensus_edits.reverse();

        for (key, value) in last_item.edits.drain(..) {
            rollback_lookup_map(&key, &value, &mut self.lookup_map);
        }

        for (key, value) in last_item.non_consensus_edits.drain(..) {
            rollback_lookup_map(&key, &value, &mut self.non_consensus_lookup_map);
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
                rollback_lookup_map(&key, &value, &mut self.lookup_map);
            }
            assert!(self.lookup_map.len() == 0);
            if last_item.edits.len() > 0 {
                self.store.put_all(last_item.edits);
            }


            for (_, edit_history) in self.non_consensus_lookup_map.iter_mut() {
                edit_history.reverse();
            }
            for (key, value) in last_item.non_consensus_edits.iter() {
                rollback_lookup_map(&key, &value, &mut self.lookup_map);
            }
            assert!(self.non_consensus_lookup_map.len() == 0);
            if last_item.non_consensus_edits.len() > 0 {
                self.store.put_all_non_consensus(last_item.non_consensus_edits);
            }
        } else {
            // bubble up to the next item in the stack
            let next_up = self.stack.last_mut().unwrap();
            for (key, value) in last_item.edits.drain(..) {
                next_up.edits.push((key, value));
            }
            for (key, value) in last_item.non_consensus_edits.drain(..) {
                next_up.non_consensus_edits.push((key, value));
            }
        }
    }
}

fn inner_put(lookup_map: &mut HashMap<String, Vec<String>>, edits: &mut Vec<(String, String)>, key: &str, value: &str) {
    if !lookup_map.contains_key(key) {
        lookup_map.insert(key.to_string(), Vec::new());
    }
    let key_edit_deque = lookup_map.get_mut(key).unwrap();
    key_edit_deque.push(value.to_string());

    edits.push((key.to_string(), value.to_string()));
}

impl <'a> RollbackWrapper <'a> {
    pub fn put(&mut self, key: &str, value: &str) {
        let current = self.stack.last_mut()
            .expect("ERROR: Clarity VM attempted PUT on non-nested context.");

        inner_put(&mut self.lookup_map, &mut current.edits, key, value)
    }

    pub fn put_non_consensus(&mut self, key: &str, value: &str) {
        let current = self.stack.last_mut()
            .expect("ERROR: Clarity VM attempted PUT on non-nested context.");

        inner_put(&mut self.non_consensus_lookup_map, &mut current.non_consensus_edits, key, value)
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

    pub fn get_non_consensus(&mut self, key: &str) -> Option<String> {
        self.stack.last()
            .expect("ERROR: Clarity VM attempted GET on non-nested context.");

        let lookup_result = self.non_consensus_lookup_map.get(key)
            .and_then(|x| x.last().cloned());

        lookup_result
            .or_else(|| self.store.get_non_consensus(key))
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
}
