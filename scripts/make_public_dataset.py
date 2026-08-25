#!/usr/bin/env python3
"""Create the de-identified aggregate dataset used by artifact evaluation.

The source directory is intentionally excluded from release archives.  Output
contains no usernames, IP addresses, user-agent strings, timestamps, rendering
hashes, raw images, or passwords.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


MODALITIES = {
    "audio": "audio_stability",
    "canvas": "canvas_stability",
}


def classify_environment(user_agent: str) -> tuple[str, str]:
    """Map a user-agent to the paper's coarse Table 2 categories."""

    if "Windows" in user_agent:
        operating_system = "Windows"
    elif "Android" in user_agent:
        operating_system = "Android"
    elif "iPhone" in user_agent or "iPad" in user_agent:
        operating_system = "iOS"
    elif "Macintosh" in user_agent:
        operating_system = "macOS"
    elif "Linux" in user_agent:
        operating_system = "Linux"
    else:
        operating_system = "Unknown"

    if "MicroMessenger" in user_agent:
        browser = "Messenger1"
    elif "MQQBrowser" in user_agent or "QQ/" in user_agent:
        browser = "Messenger2"
    elif "Edg/" in user_agent or "Edge/" in user_agent:
        browser = "Edge"
    elif "Firefox/" in user_agent or "FxiOS/" in user_agent:
        browser = "Firefox"
    elif "Chrome/" in user_agent:
        browser = "Chrome"
    elif "Safari/" in user_agent:
        browser = "Safari"
    else:
        browser = "Unknown"

    return operating_system, browser


def first_run_summary(record: dict, key: str) -> dict[str, int | bool]:
    """Summarize the first collection session, as used in paper Tables 1/2."""

    history = record.get(key)
    if not isinstance(history, list) or not history:
        return {"available": False, "runs": 0, "unique_results": 0, "stable": False}

    first = history[0] if isinstance(history[0], dict) else {}
    values = first.get("hashes")
    if not isinstance(values, list):
        values = []
        for run in first.get("runs") or []:
            if not isinstance(run, dict):
                continue
            value = run.get("waveformHash") or run.get("hash")
            if value:
                values.append(value)
    values = [str(value) for value in values if value]
    unique_results = len(set(values))
    return {
        "available": True,
        "runs": len(values),
        "unique_results": unique_results,
        "stable": bool(values) and unique_results == 1,
    }


def build_records(source: Path) -> list[dict]:
    files = sorted(source.glob("*.json"), key=lambda path: path.name.casefold())
    if not files:
        raise SystemExit(f"No JSON participant records found in {source}")

    public_records = []
    for index, path in enumerate(files, start=1):
        raw = json.loads(path.read_text(encoding="utf-8"))
        fingerprint = raw.get("fingerprint") or {}
        details = fingerprint.get("details") or {}
        user_agent = details.get("userAgent") or fingerprint.get("user_agent") or ""
        operating_system, browser = classify_environment(str(user_agent))
        public_records.append(
            {
                "participant_id": f"P{index:04d}",
                "environment": {"os": operating_system, "browser": browser},
                "modalities": {
                    name: first_run_summary(raw, key)
                    for name, key in MODALITIES.items()
                },
            }
        )
    return public_records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("users"))
    parser.add_argument(
        "--output", type=Path, default=Path("data/public/records.jsonl")
    )
    args = parser.parse_args()

    records = build_records(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
            handle.write("\n")
    print(f"Wrote {len(records)} de-identified records to {args.output}")


if __name__ == "__main__":
    main()
