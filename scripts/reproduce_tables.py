#!/usr/bin/env python3
"""Reproduce the stability and environment tables reported in the paper."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


EXPECTED_STABILITY = {
    "Audio": (206, 206),
    "Canvas": (196, 198),
}

EXPECTED_ENVIRONMENTS = [
    ("Windows", "Chrome", 42),
    ("Windows", "Messenger1", 40),
    ("Android", "Messenger1", 36),
    ("Windows", "Edge", 28),
    ("iOS", "Messenger1", 16),
    ("Android", "Chrome", 10),
    ("Android", "Messenger2", 8),
    ("macOS", "Chrome", 8),
    ("macOS", "Safari", 7),
    ("iOS", "Safari", 6),
    ("Unknown", "Messenger1", 4),
    ("Windows", "Firefox", 3),
    ("Linux", "Chrome", 2),
    ("Android", "Firefox", 1),
    ("macOS", "Edge", 1),
    ("Linux", "Firefox", 1),
]


def load_records(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_csv(path: Path, header: list[str], rows: list[tuple]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("data/public/records.jsonl"))
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    parser.add_argument("--verify-paper", action="store_true")
    args = parser.parse_args()

    records = load_records(args.input)
    modality_keys = (("Audio", "audio"), ("Canvas", "canvas"))
    stability_rows = []
    actual_stability = {}
    for label, key in modality_keys:
        available = [r["modalities"][key] for r in records if r["modalities"][key]["available"]]
        stable = sum(bool(item["stable"]) for item in available)
        total = len(available)
        rate = 100.0 * stable / total if total else 0.0
        stability_rows.append((label, stable, total, f"{rate:.1f}%"))
        actual_stability[label] = (stable, total)

    environments = Counter(
        (record["environment"]["os"], record["environment"]["browser"])
        for record in records
    )
    preferred_order = [(os_name, browser) for os_name, browser, _ in EXPECTED_ENVIRONMENTS]
    remaining = sorted(key for key in environments if key not in preferred_order)
    environment_rows = [(*key, environments[key]) for key in preferred_order + remaining]

    write_csv(
        args.output_dir / "table2_stability.csv",
        ["Modality", "Stable devices", "Devices tested", "Stability rate"],
        stability_rows,
    )
    write_csv(
        args.output_dir / "table3_environments.csv",
        ["Operating system", "Browser", "Devices"],
        environment_rows,
    )

    print("Table 2 — Stability")
    for row in stability_rows:
        print(f"  {row[0]:6s} {row[1]:3d}/{row[2]:3d} ({row[3]})")
    print(f"Table 3 — Environment total: {sum(environments.values())}")

    if args.verify_paper:
        expected_environments = {(o, b): n for o, b, n in EXPECTED_ENVIRONMENTS}
        if actual_stability != EXPECTED_STABILITY:
            raise SystemExit(
                f"Table 2 mismatch: expected {EXPECTED_STABILITY}, got {actual_stability}"
            )
        if environments != Counter(expected_environments):
            raise SystemExit(
                f"Table 3 mismatch: expected {expected_environments}, got {dict(environments)}"
            )
        if len(records) != 213:
            raise SystemExit(f"Participant count mismatch: expected 213, got {len(records)}")
        print("Verified: the retained Audio/Canvas rows and Table 3 match the paper.")


if __name__ == "__main__":
    main()
