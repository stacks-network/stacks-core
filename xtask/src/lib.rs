use std::process::{Command, Stdio};

use std::{
    env,
    fs,
    path::{Path, PathBuf},
};

pub fn project_root() -> PathBuf {
    Path::new(
        &env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_owned()),
    )
    .ancestors()
    .nth(1)
    .unwrap()
    .to_path_buf()
}

pub fn run_release() {
    let dist = project_root().join("dist");
    let _res = fs::remove_dir_all(&dist);
    fs::create_dir_all(&dist).unwrap();

    if cfg!(target_os = "linux") {
        std::env::set_var("CC", "clang");
        run("cargo build --package stacks-testnet --manifest-path ./testnet/Cargo.toml --bin stacks-node --release --target x86_64-unknown-linux-gnu");
        // todo(ludo): enable musl builds instead
        // run!("cargo build --package stacks-testnet --manifest-path ./testnet/Cargo.toml --bin stacks-node --release --target x86_64-unknown-linux-musl --features vendored")?;
        // run!("strip ./target/x86_64-unknown-linux-musl/release/stacks-node")?;
    } else {
        run("cargo build --package stacks-testnet --manifest-path ./Cargo.toml --bin stacks-node --release");
    }

    let (src, dst) = if cfg!(target_os = "linux") {
        ("./target/x86_64-unknown-linux-gnu/release/stacks-node", "./dist/stacks-node-linux")
    } else if cfg!(target_os = "windows") {
        ("./target/release/stacks-node.exe", "./dist/stacks-node-windows.exe")
    } else if cfg!(target_os = "macos") {
        ("./target/release/stacks-node", "./dist/stacks-node-mac")
    } else {
        panic!("Unsupported OS")
    };

    fs::copy(src, dst).unwrap();
}

fn run(cmd: &str) {
    let mut args: Vec<String> = cmd.split_whitespace().map(|it| it.to_string()).collect();
    let binary = args.remove(0);

    println!("> {}", cmd);
    
    let output = Command::new(binary)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    println!("> {}", stdout);

    if !output.status.success() {
        panic!("Failed running: {}", cmd);
    }
}
