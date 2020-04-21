//! See https://github.com/matklad/cargo-xtask/.
//!
//! This binary defines various auxiliary build commands, which are not
//! expressible with just `cargo`. Notably, it provides `cargo xtask codegen`
//! for code generation and `cargo xtask install` for installation of
//! stacks-blockchain server and client.
//!
//! This binary is integrated into the `cargo` command line by using an alias in
//! `.cargo/config`.

use std::env;

use pico_args::Arguments;
use xtask::{
    dist::run_dist,
    run_release,
    Result,
};

fn main() -> Result<()> {

    let mut args = Arguments::from_env();
    let subcommand = args.subcommand()?.unwrap_or_default();

    match subcommand.as_str() {
        "release" => {
            let dry_run = args.contains("--dry-run");
            args.finish()?;
            run_release(dry_run)
        }
        "dist" => {
            args.finish()?;
            run_dist(client_opts)
        }
        _ => {
            eprintln!(
                "\
cargo xtask
Run custom build command.

USAGE:
    cargo xtask <SUBCOMMAND>

SUBCOMMANDS:
    format
    install-pre-commit-hook
    install
    dist"
            );
            Ok(())
        }
    }
}
