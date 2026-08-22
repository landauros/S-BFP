#!/usr/bin/env python3
"""Audit a release ZIP for completeness and restricted-data exclusions."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path, PurePosixPath


REQUIRED = {
    "README.md",
    "ETHICS_AND_DATA.md",
    "OPEN_SCIENCE.md",
    "artifact/ARTIFACT_APPENDIX.md",
    "artifact/ARTIFACT_APPENDIX.pdf",
    "data/public/README.md",
    "data/public/records.jsonl",
    "requirements.txt",
    "Dockerfile",
    "SHA256SUMS",
}
FORBIDDEN_PREFIXES = ("users/", "User_Manager/data/", "Canvas/upload/")
FORBIDDEN_DATA_KEYS = {
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
}
RETIRED_TERMS = ("web" + "gl", "tri" + "angle")
TEXT_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".jsonl",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def stripped_name(name: str) -> str:
    path = PurePosixPath(name)
    if path.parts and path.parts[0] == "S-BFP":
        path = PurePosixPath(*path.parts[1:])
    return path.as_posix()


def walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key.casefold()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    archive_path = args.archive.resolve()

    with zipfile.ZipFile(archive_path) as archive:
        names = [stripped_name(info.filename) for info in archive.infolist()]
        name_set = set(names)
        missing = sorted(REQUIRED - name_set)
        if missing:
            raise SystemExit(f"Missing required artifact files: {missing}")
        forbidden = sorted(
            name
            for name in names
            if any(name == prefix.rstrip("/") or name.startswith(prefix) for prefix in FORBIDDEN_PREFIXES)
            or any(part in {".git", ".venv", "__pycache__"} for part in PurePosixPath(name).parts)
        )
        if forbidden:
            raise SystemExit(f"Restricted/runtime paths present: {forbidden[:10]}")
        for info, relative in zip(archive.infolist(), names):
            lowered_name = relative.casefold()
            if any(term in lowered_name for term in RETIRED_TERMS):
                raise SystemExit(f"Retired modality path present: {relative}")
            if PurePosixPath(relative).suffix.casefold() in TEXT_SUFFIXES:
                text = archive.read(info.filename).decode("utf-8", errors="ignore").casefold()
                if any(term in text for term in RETIRED_TERMS):
                    raise SystemExit(f"Retired modality text present: {relative}")

        public_name = "S-BFP/data/public/records.jsonl"
        rows = [
            json.loads(line)
            for line in archive.read(public_name).decode("utf-8").splitlines()
            if line.strip()
        ]
        if len(rows) != 213:
            raise SystemExit(f"Expected 213 public records, found {len(rows)}")
        for index, row in enumerate(rows, start=1):
            if row.get("participant_id") != f"P{index:04d}":
                raise SystemExit(f"Unexpected public participant ID at row {index}")
            leaked = FORBIDDEN_DATA_KEYS.intersection(walk_keys(row))
            if leaked:
                raise SystemExit(f"Forbidden public-data keys at row {index}: {leaked}")
            if set(row.get("modalities", {})) != {"audio", "canvas"}:
                raise SystemExit(f"Unexpected modalities at row {index}")

        manifest = archive.read("S-BFP/SHA256SUMS").decode("utf-8").splitlines()
        for line in manifest:
            expected, relative = line.split("  ", 1)
            actual = hashlib.sha256(archive.read(f"S-BFP/{relative}")).hexdigest()
            if actual != expected:
                raise SystemExit(f"Checksum mismatch: {relative}")

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    print(f"Verified sanitized artifact: {archive_path}")
    print(f"Files: {len(names)}; public records: {len(rows)}")
    print(f"SHA-256 {digest}")


if __name__ == "__main__":
    main()
