use std::env;
use std::path::Path;

pub fn load_env() {
    // Load environment variables from .env file in the package directory
    let env_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    println!("Loading environment variables from: {:?}", env_path);
    dotenv::from_path(env_path).ok();
}

pub fn get_node_url() -> String {
    env::var("STACKS_NODE_URL")
        .unwrap_or_else(|_| "https://stacks-node-api.mainnet.stacks.co".to_string())
}

pub fn get_bind_address() -> String {
    env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
}
