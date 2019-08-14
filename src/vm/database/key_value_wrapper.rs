use std::collections::{VecDeque, HashMap};

// These functions _do not_ return errors, rather, any errors in the underlying storage
//    will _panic_. The rationale for this is that under no condition should the interpreter
//    attempt to continue processing in the event of an unexpected storage error.
pub trait KeyValueStorage {
    fn put(&mut self, key: &str, value: &str);
    fn get(&mut self, key: &str) -> Option<String>;
    fn has_entry(&mut self, key: &str) -> bool;

    fn put_all(&mut self, mut items: Vec<(String, String)>) {
        for (key, value) in items.drain(..) {
            self.put(&key, &value);
        }
    }
}

trait Rollback <'a, 'b> {
    fn reap_child(&mut self, edits: Vec<(String, String)>,
                  lookup_map: &'b mut HashMap<String, VecDeque<String>>,
                  store: &'a mut KeyValueStorage);
}

pub struct RollbackContext {
    edits: Vec<(String, String)>
}

pub struct RollbackWrapper <'a> {
    // the underlying key-value storage.
    store: Box<KeyValueStorage + 'a>,
    // lookup_map is a history of edits for a given key.
    //   in order of least-recent to most-recent at the tail.
    //   this allows ~ O(1) lookups, and ~ O(1) commits, roll-backs (amortized by # of PUTs).
    lookup_map: HashMap<String, VecDeque<String>>,
    // stack keeps track of the most recent rollback context, which tells us which
    //   edits were performed by which context. at the moment, each context's edit history
    //   is a separate Vec which must be drained into the parent on commits, meaning that
    //   the amortized cost of committing a value isn't O(1), but actually O(k) where k is
    //   stack depth.
    //  TODO: The solution to this is to just have a _single_ edit stack, and merely store indexes
    //   to indicate a given contexts "start depth".
    stack: VecDeque<RollbackContext>
}

impl <'a> RollbackWrapper <'a> {
    pub fn new(store: Box<KeyValueStorage + 'a>) -> RollbackWrapper {
        RollbackWrapper {
            store: store,
            lookup_map: HashMap::new(),
            stack: VecDeque::new()
        }
    }

    pub fn nest(&mut self) {
        self.stack.push_back(RollbackContext { edits: Vec::new() });
    }

    // Rollback the child's edits.
    //   this clears all edits from the child's edit queue,
    //     and removes any of those edits from the lookup map.
    pub fn rollback(&mut self) {
        let mut last_item = self.stack.pop_back()
            .expect("ERROR: Clarity VM attempted to commit past the stack.");

        last_item.edits.reverse();

        for (key, value) in last_item.edits.drain(..) {
                let remove_edit_deque = {
                    let key_edit_history = self.lookup_map.get_mut(&key)
                        .expect("ERROR: Clarity VM had edit log entry, but not lookup_map entry");
                    let popped_value = key_edit_history.pop_back();
                    assert_eq!(popped_value.as_ref(), Some(&value));
                    key_edit_history.len() == 0
                };
                if remove_edit_deque {
                    self.lookup_map.remove(&key);
                }
        }
    }

    pub fn commit(&mut self) {
        let mut last_item = self.stack.pop_back()
            .expect("ERROR: Clarity VM attempted to commit past the stack.");

        if self.stack.len() == 0 {
            // committing to the backing store
            for (key, value) in last_item.edits.iter() {
                let remove_edit_deque = {
                    let key_edit_history = self.lookup_map.get_mut(key)
                        .expect("ERROR: Clarity VM had edit log entry, but not lookup_map entry");
                    let popped_value = key_edit_history.pop_front();
                    assert_eq!(popped_value.as_ref(), Some(value));
                    key_edit_history.len() == 0
                };
                if remove_edit_deque {
                    self.lookup_map.remove(key);
                }
            }
            assert!(self.lookup_map.len() == 0);
            if last_item.edits.len() > 0 {
                self.store.put_all(last_item.edits);
            }
        } else {
            // bubble up to the next item in the stack
            let next_up = self.stack.back_mut().unwrap();
            for (key, value) in last_item.edits.drain(..) {
                next_up.edits.push((key, value));
            }
        }
    }

}

impl <'a> KeyValueStorage for RollbackWrapper <'a> {
    fn put(&mut self, key: &str, value: &str) {
        let current = self.stack.back_mut()
            .expect("ERROR: Clarity VM attempted PUT on non-nested context.");

        if !self.lookup_map.contains_key(key) {
            self.lookup_map.insert(key.to_string(), VecDeque::new());
        }
        let key_edit_deque = self.lookup_map.get_mut(key).unwrap();
        key_edit_deque.push_back(value.to_string());

        current.edits.push((key.to_string(), value.to_string()));
    }

    fn get(&mut self, key: &str) -> Option<String> {
        let current = self.stack.back()
            .expect("ERROR: Clarity VM attempted GET on non-nested context.");

        let lookup_result = match self.lookup_map.get(key) {
            None => None,
            Some(key_edit_history) => {
                key_edit_history.back().cloned()
            },
        };
        if lookup_result.is_some() {
            lookup_result
        } else {
            self.store.get(key)
        }
    }

    fn has_entry(&mut self, key: &str) -> bool {
        let current = self.stack.back()
            .expect("ERROR: Clarity VM attempted GET on non-nested context.");
        if self.lookup_map.contains_key(key) {
            true
        } else {
            self.store.has_entry(key)
        }
    }
}
