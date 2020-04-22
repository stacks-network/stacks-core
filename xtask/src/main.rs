use pico_args::Arguments;

use xtask::run_release;

fn main() {

    let mut args = Arguments::from_env();
    let subcommand = args.subcommand().unwrap().unwrap_or_default();

    match subcommand.as_str() {
        "release" => {
            args.finish().unwrap();
            run_release()
        }
        _ => {
            eprintln!(
                "\
cargo xtask
Run custom build command.

USAGE:
    cargo xtask <SUBCOMMAND>

SUBCOMMANDS:
    release"
            );
        }
    }
}
