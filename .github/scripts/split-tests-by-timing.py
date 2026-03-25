#!/usr/bin/env python3
"""Split nextest tests into time-balanced partitions using JUnit XML timing data.

Uses greedy bin-packing: assigns each test (heaviest first) to the lightest bucket.
Falls back gracefully when timing data is unavailable.

Usage:
    split-tests-by-timing.py <junit-dir> <partition> <total-partitions>

    junit-dir:        directory containing one or more junit.xml files
    partition:        1-indexed partition number (e.g., 3)
    total-partitions: total number of partitions (e.g., 12)

Output:
    A nextest filter expression on stdout, e.g.:
        test(=foo::bar) | test(=baz::qux) | ...

    Summary statistics on stderr.

Exit codes:
    0: success, filter expression printed
    1: error (bad args)
    2: no timing data found (caller should fall back to hash: partitioning)
"""

import glob
import sys
import xml.etree.ElementTree as ET


def parse_durations(junit_dir):
    """Extract {test_name: duration_seconds} from all JUnit XMLs in a directory."""
    durations = {}
    for path in glob.glob(f"{junit_dir}/**/junit.xml", recursive=True):
        try:
            for tc in ET.parse(path).iter("testcase"):
                name = tc.get("name")
                classname = tc.get("classname", "")
                time_s = tc.get("time")
                if name and time_s:
                    full_name = f"{classname}::{name}" if classname else name
                    durations[full_name] = float(time_s)
        except ET.ParseError:
            continue
    return durations


def bin_pack(tests_with_durations, num_buckets):
    """Greedy bin-packing: assign heaviest test to lightest bucket."""
    by_duration = sorted(tests_with_durations, key=lambda x: x[1], reverse=True)
    buckets = [[] for _ in range(num_buckets)]
    totals = [0.0] * num_buckets

    for name, duration in by_duration:
        lightest = min(range(num_buckets), key=lambda i: totals[i])
        buckets[lightest].append(name)
        totals[lightest] += duration

    return buckets, totals


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <junit-dir> <partition> <total-partitions>", file=sys.stderr)
        sys.exit(1)

    junit_dir = sys.argv[1]
    partition = int(sys.argv[2])
    total = int(sys.argv[3])

    if not (1 <= partition <= total):
        print(f"Error: partition {partition} not in [1, {total}]", file=sys.stderr)
        sys.exit(1)

    durations = parse_durations(junit_dir)

    if not durations:
        print("Warning: no test timing data found", file=sys.stderr)
        sys.exit(2)

    buckets, totals = bin_pack(list(durations.items()), total)
    idx = partition - 1

    # Output nextest filter expression
    print(" | ".join(f"test(={name})" for name in buckets[idx]))

    # Summary to stderr
    print(f"Partition {partition}/{total}: {len(buckets[idx])} tests, "
          f"~{totals[idx]:.0f}s (range: {min(totals):.0f}s - {max(totals):.0f}s)",
          file=sys.stderr)


if __name__ == "__main__":
    main()
