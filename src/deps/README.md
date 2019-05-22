# Statically-Linked Dependencies

In a bid to make this codebase safe against package churn, to minimize the
number of external dependencies that need to be fetched, and to hedge against
bugs in Cargo or remote hacks on crates.io, this directory will contain source
snapshots of important libraries this codebase depends on.
