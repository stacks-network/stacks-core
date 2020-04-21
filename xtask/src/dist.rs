use std::path::PathBuf;

use anyhow::Result;

use crate::{
    not_bash::{fs2, pushd, rm_rf, run},
    project_root,
};

pub fn run_dist() -> Result<()> {
    let dist = project_root().join("dist");
    rm_rf(&dist)?;
    fs2::create_dir_all(&dist)?;

    if cfg!(target_os = "linux") {
        std::env::set_var("CC", "clang");
        run!(
            "cargo build --manifest-path ./Cargo.toml --bin stacks-blockchain --release
             --target x86_64-unknown-linux-musl
            "
            // We'd want to add, but that requires setting the right linker somehow
            // --features=jemalloc
        )?;
        run!("strip ./target/x86_64-unknown-linux-musl/release/stacks-blockchain")?;
    } else {
        run!("cargo build --manifest-path ./Cargo.toml --bin stacks-blockchain --release")?;
    }

    let (src, dst) = if cfg!(target_os = "linux") {
        ("./target/x86_64-unknown-linux-musl/release/stacks-blockchain", "./dist/stacks-blockchain-linux")
    } else if cfg!(target_os = "windows") {
        ("./target/release/stacks-blockchain.exe", "./dist/stacks-blockchain-windows.exe")
    } else if cfg!(target_os = "macos") {
        ("./target/release/stacks-blockchain", "./dist/stacks-blockchain-mac")
    } else {
        panic!("Unsupported OS")
    };

    fs2::copy(src, dst)?;

    Ok(())
}
