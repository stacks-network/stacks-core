#!/usr/bin/env python3
"""Balance tests while accounting for exclusive runner reservations."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TestWeight:
    """Historical runtime and execution-slot requirement for one test."""

    name: str
    seconds: float
    slots: int


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-list", required=True, type=Path)
    parser.add_argument("--weights", required=True, type=Path)
    parser.add_argument("--batch-count", required=True, type=int)
    parser.add_argument("--max-batch-size", required=True, type=int)
    return parser.parse_args()


def load_tests(test_list: Path, weights_file: Path) -> tuple[list[TestWeight], int]:
    """Load and validate the selected tests and their resource weights."""
    names = [name for name in test_list.read_text(encoding="utf-8").splitlines() if name]
    weights = json.loads(weights_file.read_text(encoding="utf-8"))
    default_seconds = weights.get("default_seconds")
    test_threads = weights.get("test_threads")
    recorded = weights.get("tests")

    if not isinstance(default_seconds, (int, float)) or default_seconds <= 0:
        raise ValueError("weights.default_seconds must be positive")
    if not isinstance(test_threads, int) or test_threads <= 0:
        raise ValueError("weights.test_threads must be a positive integer")
    if not isinstance(recorded, dict):
        raise ValueError("weights.tests must be an object")

    tests = []
    for name in names:
        weight = recorded.get(name, {"seconds": default_seconds, "slots": 1})
        seconds = weight.get("seconds")
        slots = weight.get("slots")
        if not isinstance(seconds, (int, float)) or seconds < 0:
            raise ValueError(f"invalid runtime for {name}: {seconds}")
        if not isinstance(slots, int) or slots not in {1, test_threads}:
            raise ValueError(
                f"{name} must reserve either one or all {test_threads} slots"
            )
        tests.append(TestWeight(name, float(seconds), slots))
    return tests, test_threads


def estimated_seconds(tests: list[TestWeight], test_threads: int) -> float:
    """Estimate nextest makespan for unit-slot and fully exclusive tests."""
    exclusive_seconds = sum(
        test.seconds for test in tests if test.slots == test_threads
    )
    lanes = [0.0] * test_threads
    concurrent = sorted(
        (test for test in tests if test.slots == 1),
        key=lambda test: (-test.seconds, test.name),
    )
    for test in concurrent:
        lane = min(range(test_threads), key=lambda index: (lanes[index], index))
        lanes[lane] += test.seconds
    return exclusive_seconds + max(lanes, default=0.0)


def balance(
    tests: list[TestWeight],
    test_threads: int,
    batch_count: int,
    max_batch_size: int,
) -> list[dict[str, object]]:
    """Greedily minimize the resulting resource-aware batch makespan."""
    if batch_count <= 0:
        raise ValueError("batch-count must be positive")
    if max_batch_size <= 0:
        raise ValueError("max-batch-size must be positive")
    if batch_count > len(tests):
        raise ValueError("batch-count exceeds the test count")
    if batch_count * max_batch_size < len(tests):
        raise ValueError("the configured batches cannot hold every test")

    batches: list[list[TestWeight]] = [[] for _ in range(batch_count)]
    ordered = sorted(
        tests,
        key=lambda test: (-(test.seconds * test.slots), test.name),
    )
    for test in ordered:
        eligible = [
            index
            for index, batch in enumerate(batches)
            if len(batch) < max_batch_size
        ]
        if not eligible:
            raise ValueError(f"unable to assign test: {test.name}")
        selected = min(
            eligible,
            key=lambda index: (
                estimated_seconds(batches[index] + [test], test_threads),
                len(batches[index]),
                index,
            ),
        )
        batches[selected].append(test)

    result = []
    for index, batch in enumerate(batches, start=1):
        result.append(
            {
                "index": index,
                "estimated_seconds": round(
                    estimated_seconds(batch, test_threads), 6
                ),
                "tests": [test.name for test in batch],
            }
        )

    expected = Counter(test.name for test in tests)
    emitted = Counter(name for batch in result for name in batch["tests"])
    if emitted != expected:
        raise ValueError("balancer output does not exactly cover the input test list")
    return result


def main() -> None:
    """Generate resource-aware test batches as JSON."""
    args = parse_args()
    try:
        tests, test_threads = load_tests(args.test_list, args.weights)
        result = balance(
            tests,
            test_threads,
            args.batch_count,
            args.max_batch_size,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
