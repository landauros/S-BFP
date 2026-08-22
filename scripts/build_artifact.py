#!/usr/bin/env python3
"""Build a deterministic USENIX artifact ZIP without restricted data."""

from __future__ import annotations

import argparse
import hashlib
import stat
import zipfile
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ROOT = PurePosixPath("S-BFP")
EXCLUDED_PARTS = {
    ".git",
    ".idea",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "dist",
    "results",
    "tmp",
}
EXCLUDED_PREFIXES = (
    PurePosixPath("users"),
    PurePosixPath("User_Manager/data"),
    PurePosixPath("Canvas/upload"),
)


def is_excluded(relative: PurePosixPath, output: Path) -> bool:
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return True
    if relative.suffix.casefold() in {".pyc", ".pyo"}:
        return True
    if any(relative == prefix or prefix in relative.parents for prefix in EXCLUDED_PREFIXES):
        return True
    try:
        return (ROOT / Path(relative.as_posix())).resolve() == output.resolve()
    except OSError:
        return False


def archive_files(output: Path) -> list[tuple[PurePosixPath, bytes]]:
    files = []
    for path in sorted(ROOT.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if not path.is_file():
            continue
        relative = PurePosixPath(path.relative_to(ROOT).as_posix())
        if not is_excluded(relative, output):
            files.append((relative, path.read_bytes()))
    return files


def zip_info(name: PurePosixPath, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name.as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = 0o755 if executable else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.create_system = 3
    return info


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=ROOT / "dist" / "s-bfp-usenix-artifact.zip"
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    files = archive_files(output)
    required = {PurePosixPath("README.md"), PurePosixPath("data/public/records.jsonl")}
    available = {name for name, _ in files}
    missing = sorted(required - available)
    if missing:
        raise SystemExit(f"Cannot build artifact; missing: {missing}")

    manifest_lines = []
    with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
        for relative, content in files:
            archive_name = ARCHIVE_ROOT / relative
            executable = relative.suffix == ".sh"
            archive.writestr(zip_info(archive_name, executable), content)
            digest = hashlib.sha256(content).hexdigest()
            manifest_lines.append(f"{digest}  {relative.as_posix()}")
        manifest = ("\n".join(manifest_lines) + "\n").encode("utf-8")
        archive.writestr(zip_info(ARCHIVE_ROOT / "SHA256SUMS"), manifest)

    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(f"Built {output} ({len(files)} files)")
    print(f"SHA-256 {digest}")


if __name__ == "__main__":
    main()
