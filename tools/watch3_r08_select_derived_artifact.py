#!/usr/bin/env python3
"""Locate one successful, checksum-gated, post-merge UgLy|OS derivative artifact.

Only GitHub's public Actions API, with caller's optional read-only token.
Refuses stale, expired, wrong-commit, duplicate or missing artifact.
No watch connections, no archive payload download or firmware writes.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

REPO = "UglyGameFace/Galaxy-3"
WORKFLOW = "watch3-r08-original-legacy-derivative.yml"
SOURCE_MAIN_SHA = "73aed5d38c0e96192ba480c490e90f4b9a2611c0"
PREFIX = "galaxy3-r08-DERIVED-LEGACY-EXT4-NOT-FLASHABLE-"


class ArtifactError(ValueError):
    pass


def choose(runs: dict, artifact_payloads: dict[int, dict]) -> dict:
    rows = runs.get("workflow_runs")
    if not isinstance(rows, list):
        raise ArtifactError("MISSING_WORKFLOW_RUN_LIST")
    eligible = [run for run in rows if
                run.get("head_sha") == SOURCE_MAIN_SHA
                and run.get("event") == "push"
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"]
    if len(eligible) != 1:
        raise ArtifactError("EXPECTED_ONE_SUCCESSFUL_EXACT_MERGE_RUN")
    run = eligible[0]
    run_id = run.get("id")
    if not isinstance(run_id, int) or run_id <= 0:
        raise ArtifactError("INVALID_RUN_ID")
    payload = artifact_payloads.get(run_id, {})
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list):
        raise ArtifactError("MISSING_ARTIFACT_LIST")
    matched = [item for item in artifacts if
               item.get("name") == PREFIX + str(run_id)
               and item.get("expired") is False
               and isinstance(item.get("size_in_bytes"), int)
               and 40_000_000 < item["size_in_bytes"] < 1_000_000_000]
    if len(matched) != 1:
        raise ArtifactError("EXACT_DERIVED_IMAGE_ARTIFACT_NOT_VERIFIED")
    return {"run_id": run_id, "artifact_id": matched[0]["id"],
            "artifact_name": matched[0]["name"],
            "archive_bytes": matched[0]["size_in_bytes"],
            "main_commit_sha": SOURCE_MAIN_SHA,
            "original_image_is_separate": True,
            "watch_contacted": False, "flash_allowed": False}


def fetch(url: str, token: str) -> dict:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "UgLyOS-Issue47-Offline-Provenance",
        **({"Authorization": "Bearer " + token} if token else {}),
    })
    try:
        with urlopen(request, timeout=30) as response:
            if int(response.headers.get("Content-Length", "0")) > 2_000_000:
                raise ArtifactError("OVERSIZED_API_METADATA")
            body = response.read(2_000_001)
    except (HTTPError, URLError, TimeoutError) as error:
        raise ArtifactError("GITHUB_ACTIONS_READ_FAILED") from error
    if len(body) > 2_000_000:
        raise ArtifactError("OVERSIZED_API_RESPONSE")
    try:
        return json.loads(body)
    except (ValueError, UnicodeError) as error:
        raise ArtifactError("UNPARSEABLE_GITHUB_METADATA") from error


def discover(token: str) -> dict:
    api = "https://api.github.com/repos/" + REPO
    runs = fetch(api + "/actions/workflows/" + WORKFLOW +
                 "/runs?event=push&per_page=30", token)
    rows = runs.get("workflow_runs", [])
    candidates = [r for r in rows if r.get("head_sha") == SOURCE_MAIN_SHA
                  and r.get("conclusion") == "success" and r.get("event") == "push"]
    data = {}
    for item in candidates[:2]:
        rid = item.get("id")
        if isinstance(rid, int) and rid > 0:
            data[rid] = fetch(api + "/actions/runs/" + str(rid) +
                              "/artifacts?per_page=100", token)
    return choose(runs, data)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--github-output", type=Path, help="GitHub Actions $GITHUB_OUTPUT")
    args = p.parse_args()
    try:
        result = discover(os.environ.get("GITHUB_TOKEN", ""))
        if args.output.exists():
            raise ArtifactError("REPORT_ALREADY_EXISTS")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        if args.github_output:
            with args.github_output.open("a") as f:
                f.write("run_id=" + str(result["run_id"]) + "\n")
                f.write("artifact_name=" + result["artifact_name"] + "\n")
    except (OSError, ValueError) as error:
        print("DERIVED_ARTIFACT_NOT_YET_VERIFIED: " + str(error), file=sys.stderr)
        return 2
    print("PASS: exact main-commit converted rootfs artifact exists (off-device)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
