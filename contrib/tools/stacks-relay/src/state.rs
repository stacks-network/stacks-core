use std::collections::HashMap;

#[derive(Default)]
pub struct State {
    // the value for this map is an index for the last read message.
    highwaters: HashMap<u64, usize>,
    queue: Vec<String>,
}

impl State {
    pub fn get(&mut self, node_id: u64) -> Option<&String> {
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
    pub fn post(&mut self, msg: String) {
        self.queue.push(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    #[test]
    fn state_test() {
        let mut state = State::default();
        assert_eq!(None, state.get(1));
        assert_eq!(None, state.get(3));
        assert_eq!(0, state.highwaters.len());
        state.post("Msg # 0".to_string());
        assert_eq!(Some(&"Msg # 0".to_string()), state.get(1));
        assert_eq!(Some(&"Msg # 0".to_string()), state.get(5));
        assert_eq!(Some(&"Msg # 0".to_string()), state.get(4));
        assert_eq!(None, state.get(1));
        state.post("Msg # 1".to_string());
        assert_eq!(Some(&"Msg # 1".to_string()), state.get(1));
        assert_eq!(Some(&"Msg # 0".to_string()), state.get(3));
        assert_eq!(Some(&"Msg # 1".to_string()), state.get(5));
        state.post("Msg # 2".to_string());
        assert_eq!(Some(&"Msg # 2".to_string()), state.get(1));
        assert_eq!(Some(&"Msg # 1".to_string()), state.get(4));
        assert_eq!(Some(&"Msg # 2".to_string()), state.get(4));
    }
}
