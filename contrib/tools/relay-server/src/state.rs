use hashbrown::HashMap;

#[derive(Default)]
pub struct State {
    /// The value for this map is an index for the last read message for this node.
    highwaters: HashMap<String, usize>,
    queue: Vec<Vec<u8>>,
}

impl State {
    pub fn get(&mut self, node_id: String) -> Option<&Vec<u8>> {
        let first_unread = self
            .highwaters
            .get(&node_id)
            .map_or(0, |last_read| *last_read + 1);
        let result = self.queue.get(first_unread);
        if result != None {
            self.highwaters.insert(node_id, first_unread);
        };
        result
    }
    pub fn post(&mut self, msg: Vec<u8>) {
        self.queue.push(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    #[test]
    fn state_test() {
        let mut state = State::default();
        assert_eq!(None, state.get(1.to_string()));
        assert_eq!(None, state.get(3.to_string()));
        assert_eq!(0, state.highwaters.len());
        state.post("Msg # 0".as_bytes().to_vec());
        assert_eq!(
            Some(&"Msg # 0".as_bytes().to_vec()),
            state.get(1.to_string())
        );
        assert_eq!(
            Some(&"Msg # 0".as_bytes().to_vec()),
            state.get(5.to_string())
        );
        assert_eq!(
            Some(&"Msg # 0".as_bytes().to_vec()),
            state.get(4.to_string())
        );
        assert_eq!(None, state.get(1.to_string()));
        state.post("Msg # 1".as_bytes().to_vec());
        assert_eq!(
            Some(&"Msg # 1".as_bytes().to_vec()),
            state.get(1.to_string())
        );
        assert_eq!(
            Some(&"Msg # 0".as_bytes().to_vec()),
            state.get(3.to_string())
        );
        assert_eq!(
            Some(&"Msg # 1".as_bytes().to_vec()),
            state.get(5.to_string())
        );
        state.post("Msg # 2".as_bytes().to_vec());
        assert_eq!(
            Some(&"Msg # 2".as_bytes().to_vec()),
            state.get(1.to_string())
        );
        assert_eq!(
            Some(&"Msg # 1".as_bytes().to_vec()),
            state.get(4.to_string())
        );
        assert_eq!(
            Some(&"Msg # 2".as_bytes().to_vec()),
            state.get(4.to_string())
        );
    }
}
