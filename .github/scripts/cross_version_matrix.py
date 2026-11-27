#!/usr/bin/env python3
# Copyright (C) 2026 Stacks Open Internet Foundation
# SPDX-License-Identifier: GPL-3.0-or-later
"""Select published, stable release archives according to the checked-in policy."""
import json
from pathlib import Path
import re
import sys


def release_key(tag):
    """Numeric version components of a tag, e.g. "4.0.7" -> (4, 0, 7)."""
    return tuple(int(part) for part in re.findall(r"\d+", tag))


def baseline_matrix(releases, policy, override=""):
    """Fail closed when the required baseline or its shipped archive is missing."""
    # Releases older than min_release cannot run the scenarios' epoch schedule.
    minimum = release_key(policy["min_release"])
    tags = []
    for release in sorted(releases, key=lambda r: r.get("published_at") or "", reverse=True):
        if release.get("draft") or release.get("prerelease"):
            continue
        assets = {a["name"] for a in release["assets"]}
        tag = release["tag_name"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tag):
            continue
        if release_key(tag) < minimum:
            continue
        if "linux-glibc-x64.zip" in assets and tag not in tags:
            tags.append(tag)
    if override:
        if override not in tags:
            raise ValueError(f"Explicit baseline is not a published stable release at or above {policy['min_release']} with a Linux archive")
        return [{"version": override, "required": True}]
    result = []
    for row in policy["baselines"]:
        if row["rank"] >= len(tags):
            if row["required"]:
                raise ValueError("Required release baseline is unavailable")
            continue
        result.append({"version": tags[row["rank"]], "required": row["required"]})
    if not result:
        raise ValueError("No release baselines selected")
    return result


def scenario_matrix(nextest, policy):
    """Preserve Pinny's exact test paths while giving artifacts safe names."""
    cases = nextest["rust-suites"]["stacks-node::bin/stacks-node"]["testcases"]
    rows = []
    for name, case in cases.items():
        if case["ignored"] and name.startswith("tests::signer::cross_version::"):
            identifier = name.split("::t::", 1)[0].split("::")[-1]
            rows.append({"name": name, "id": identifier})
    if sorted(row["id"] for row in rows) != sorted(policy["scenarios"]):
        raise ValueError("Compiled scenarios do not match the support policy")
    return rows


if __name__ == "__main__":
    policy = json.loads((Path(__file__).parent.parent / "cross-version/policy.json").read_text())
    if sys.argv[1] == "--scenarios":
        result = scenario_matrix(json.loads(Path(sys.argv[2]).read_text()), policy)
        output = "tests"
    else:
        result = baseline_matrix(json.loads(Path(sys.argv[1]).read_text()), policy, sys.argv[2])
        output = "versions"
    print(output + "=" + json.dumps(result, separators=(",", ":")))
