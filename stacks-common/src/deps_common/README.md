# Statically-Linked Dependencies

In a bid to make this codebase safe against package churn, to minimize the
number of external dependencies that need to be fetched, and to hedge against
bugs in Cargo or remote hacks on crates.io, this directory will contain source
snapshots of important libraries this codebase depends on.

# Credits

* The `bech32` package was produced by Clark Moody
  (https://github.com/rust-bitcoin/rust-bech32).  License is MIT.
* The `bitcoin` package was produced by Andrew Poelstra (https://github.com/rust-bitcoin/rust-bitcoin).  License is CC0.
* The `httparse` package was produced by Sean McArthur
  (https://github.com/seanmonstar/httparse).  License is MIT.
* The `ctrlc` package was produced by Antti Keräne
  (https://github.com/Detegr/rust-ctrlc).  License is MIT.
