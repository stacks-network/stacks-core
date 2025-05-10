use std::env;

pub fn get_node_url() -> String {
    env::var("STACKS_NODE_URL")
        .unwrap_or_else(|_| "https://stacks-node-api.mainnet.stacks.co".to_string())
}

pub fn get_bind_address() -> String {
    env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
}
