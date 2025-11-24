# clarity-cli

A thin wrapper executable for the Clarity CLI exposed by `blockstack_lib::clarity_cli`. It forwards argv to the library, prints JSON output, and exits with the underlying status code.

Build:
```bash
cargo build -p clarity-cli
```

Usage:
```bash
./target/debug/clarity-cli --help
```

For advanced usage and subcommands, see the upstream Clarity CLI documentation or run with `--help`.
