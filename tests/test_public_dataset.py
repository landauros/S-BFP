from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DATA = ROOT / "data" / "public" / "records.jsonl"
FORBIDDEN_KEYS = {
    "username",
    "password",
    "password_hash",
    "ip",
    "client_ip",
    "user_agent",
    "useragent",
    "timestamp",
    "captured_at",
    "hash",
    "hashes",
    "seed",
    "runs_payload",
}


def all_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key.casefold()
            yield from all_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from all_keys(child)


class PublicDatasetTests(unittest.TestCase):
    def test_schema_and_data_minimization(self):
        records = [
            json.loads(line)
            for line in PUBLIC_DATA.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(records), 213)
        self.assertEqual(
            [record["participant_id"] for record in records],
            [f"P{index:04d}" for index in range(1, 214)],
        )
        for record in records:
            self.assertEqual(
                set(record), {"participant_id", "environment", "modalities"}
            )
            self.assertTrue(FORBIDDEN_KEYS.isdisjoint(set(all_keys(record))))
            self.assertEqual(set(record["modalities"]), {"audio", "canvas", "webgl"})


if __name__ == "__main__":
    unittest.main()
