#!/usr/bin/env python3
"""Offline validator for the single-EXE UniversalUpdater release package."""
from __future__ import annotations
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import zipfile

EXE = "TermsrvPatcherUnified.exe"
MAX_EXE = 512 * 1024 * 1024


def validate(path: Path) -> tuple[int, str]:
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) != 1 or entries[0].filename != EXE:
            raise ValueError("Updater ZIP must contain exactly one root EXE")
        entry = entries[0]
        if entry.is_dir() or entry.flag_bits & 1 or entry.file_size < 1024 or entry.file_size > MAX_EXE:
            raise ValueError("Bad EXE length, encryption or archive format")
        kind = (entry.external_attr >> 16) & 0xF000
        if kind not in (0, 0x8000):
            raise ValueError("Symlinks and special files are not accepted")
        with archive.open(entry) as payload:
            header = payload.read(65536)
        if len(header) < 0x100 or header[:2] != b"MZ":
            raise ValueError("Updater EXE does not have MZ headers")
        pe = struct.unpack_from("<I", header, 0x3C)[0]
        if pe < 0x40 or pe + 24 > len(header) or header[pe:pe + 4] != b"PE\x00\x00":
            raise ValueError("Updater EXE has invalid PE headers")
        machine = struct.unpack_from("<H", header, pe + 4)[0]
        flags = struct.unpack_from("<H", header, pe + 22)[0]
        if machine != 0x8664 or (flags & 0x2000):
            raise ValueError("Updater requires an x64 PE executable, not a DLL")
        broken = archive.testzip()
        if broken:
            raise ValueError("Updater ZIP has a corrupted entry")
        hash_value = hashlib.sha256()
        with archive.open(entry) as payload:
            for block in iter(lambda: payload.read(1024 * 1024), b""):
                hash_value.update(block)
        return entry.file_size, hash_value.hexdigest()


def selftest() -> None:
    fake = bytearray(4096)
    fake[:2] = b"MZ"
    struct.pack_into("<I", fake, 0x3C, 0x80)
    fake[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", fake, 0x84, 0x8664)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "update.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(EXE, fake)
        size, digest = validate(path)
        assert size == 4096 and len(digest) == 64
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("NOTICE.md", "unexpected")
        try:
            validate(path)
        except ValueError as err:
            assert "exactly one" in str(err)
        else:
            raise AssertionError("Unexpected ZIP entry was accepted")
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(EXE, bytes(4096))
        try:
            validate(path)
        except ValueError as err:
            assert "MZ" in str(err)
        else:
            raise AssertionError("Non-PE update archive was accepted")
    print("PASS: single x64 EXE ZIP policy and negative tests")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        selftest()
        return 0
    if len(sys.argv) != 2:
        print("Usage: verify_update_package.py --self-test | path.zip", file=sys.stderr)
        return 2
    try:
        size, digest = validate(Path(sys.argv[1]))
    except (ValueError, FileNotFoundError, zipfile.BadZipFile) as err:
        print("FAIL: " + str(err), file=sys.stderr)
        return 1
    print(f"PASS: update ZIP has one x64 EXE ({size} bytes, SHA-256 {digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
