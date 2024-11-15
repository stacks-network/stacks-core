use serde::Serialize;
use serde::Deserialize;
use std::fs::File;

#[derive(Serialize, Deserialize)]
struct Versions {
    stacks_node: String,
    stacks_signer: String,
    blockstack_cli: String,
    clarity_cli: String,
    relay_server: String,
    stacks_inspect: String,
}

pub fn get_build_version(binary: &str) -> String {
    let versions = get_build_versions();
    match binary {
        "stacks-node" => versions.stacks_node,
        "stacks-signer" => versions.stacks_signer,
        "blockstack-cli" => versions.blockstack_cli,
        "clarity-cli" => versions.clarity_cli,
        "relay-server" => versions.relay_server,
        "stacks-inspect" => versions.stacks_inspect,
        _ => panic!("Binary not found"),
    }
}

fn get_build_versions() -> Versions {
    let file = File::open("../../versions.yaml").expect("Unable to open versions.yaml");
    let versions: Versions = serde_yaml::from_reader(file).expect("Unable to read versions.yaml");
    versions
}
