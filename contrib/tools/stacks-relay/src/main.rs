use std::collections::HashMap;

#[derive(Default)]
struct State {
    highwaters: HashMap<u64, usize>,
    queue: Vec<String>,
}

impl State {
    fn get(&mut self, node_id: u64) -> Option<&String> {
        match self.highwaters.get_mut(&node_id) {
            None => {
                let result = self.queue.get(0);
                if result != None {
                    self.highwaters.insert(node_id, 1);
                };
                result
            }
            Some(v) => {
                let i = *v;
                let result = self.queue.get(1);
                if result != None {
                    *v = i + 1;
                };
                result
            }
        }
    }
    fn post(&mut self, msg: String) {
        self.queue.push(msg);
    }
}

#[cfg(test)]
mod tests {
    use crate::State;
    #[test]
    fn state_test() {
        let mut state = State::default();
        assert_eq!(None, state.get(1));
        assert_eq!(None, state.get(3));
        assert_eq!(0, state.highwaters.len());
        state.post("Msg # 0".to_string());
        assert_eq!(Some(&"Msg # 0".to_string()), state.get(1));
        assert_eq!(Some(&"Msg # 0".to_string()), state.get(5));
        assert_eq!(None, state.get(1));
        state.post("Msg # 1".to_string());
        assert_eq!(Some(&"Msg # 1".to_string()), state.get(1));
        assert_eq!(Some(&"Msg # 0".to_string()), state.get(3));
        assert_eq!(Some(&"Msg # 1".to_string()), state.get(5));
    }
}

fn main() {
    println!("Hello, world!");
}
