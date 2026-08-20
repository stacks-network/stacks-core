#!/usr/bin/env python3
"""Generate runtime-balancer timing data from nextest JUnit reports."""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from xml.etree import ElementTree


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir",
        action="append",
        default=[],
        type=Path,
        help="Directory recursively containing junit*.xml files; repeatable",
    )
    parser.add_argument(
        "--source-run",
        required=True,
        type=int,
        help="GitHub Actions run ID recorded in the output",
    )
    parser.add_argument(
        "--minimum-seconds",
        default=0.0,
        type=float,
        help="Only retain tests at or above this duration (default: 0)",
    )
    parser.add_argument(
        "--default-percentile",
        default=75.0,
        type=float,
        help="Percentile used for tests absent from the timing data (default: 75)",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("junit_files", nargs="*", type=Path)
    args = parser.parse_args()

    if args.minimum_seconds < 0:
        parser.error("--minimum-seconds must be non-negative")
    if not 0 < args.default_percentile <= 100:
        parser.error("--default-percentile must be in (0, 100]")
    if not args.input_dir and not args.junit_files:
        parser.error("provide --input-dir or at least one JUnit file")

    return args


def discover_junit_files(
    input_dirs: list[Path], junit_files: list[Path]
) -> list[Path]:
    """Return a deterministic, deduplicated list of JUnit files."""
    discovered = set(junit_files)
    for input_dir in input_dirs:
        if not input_dir.is_dir():
            raise ValueError(f"JUnit input directory not found: {input_dir}")
        discovered.update(input_dir.rglob("junit*.xml"))

    files = sorted(path.resolve() for path in discovered)
    if not files:
        raise ValueError("no junit*.xml files found")
    for path in files:
        if not path.is_file():
            raise ValueError(f"JUnit file not found: {path}")
    return files


def collect_test_durations(junit_files: list[Path]) -> dict[str, float]:
    """Collect durations by exact test name across all test binaries."""
    instance_durations: dict[tuple[str, str], float] = {}
    for junit_file in junit_files:
        root = ElementTree.parse(junit_file).getroot()
        for testcase in root.iter("testcase"):
            name = testcase.get("name")
            duration = testcase.get("time")
            if name is None or duration is None:
                continue

            key = (testcase.get("classname", ""), name)
            parsed_duration = float(duration)
            instance_durations[key] = max(
                parsed_duration, instance_durations.get(key, 0.0)
            )

    durations: defaultdict[str, float] = defaultdict(float)
    for (_, name), duration in instance_durations.items():
        durations[name] += duration
    if not durations:
        raise ValueError("JUnit reports contain no timed test cases")
    return dict(durations)


def nearest_rank_percentile(values: list[float], percentile: float) -> float:
    """Return the nearest-rank percentile from a non-empty value list."""
    ordered = sorted(values)
    index = max(0, math.ceil(percentile / 100 * len(ordered)) - 1)
    return ordered[index]


def build_timing_data(
    durations: dict[str, float],
    source_run: int,
    minimum_seconds: float,
    default_percentile: float,
) -> dict[str, object]:
    """Build the stable JSON timing-data structure."""
    retained = {
        name: round(duration, 6)
        for name, duration in sorted(durations.items())
        if duration >= minimum_seconds
    }
    return {
        "source_run": source_run,
        "default_percentile": default_percentile,
        "default_seconds": round(
            nearest_rank_percentile(list(durations.values()), default_percentile), 6
        ),
        "minimum_recorded_seconds": minimum_seconds,
        "tests": retained,
    }


def main() -> None:
    """Generate and write a timing-data JSON file."""
    args = parse_args()
    try:
        junit_files = discover_junit_files(args.input_dir, args.junit_files)
        durations = collect_test_durations(junit_files)
    except (OSError, ValueError, ElementTree.ParseError) as error:
        raise SystemExit(str(error)) from error

    timing_data = build_timing_data(
        durations,
        args.source_run,
        args.minimum_seconds,
        args.default_percentile,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(timing_data, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
