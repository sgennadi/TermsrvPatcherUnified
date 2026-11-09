#!/usr/bin/env python3
"""Validate two-file portable and one-file updater x64 PE ZIPs, without writing Windows."""
from __future__ import annotations
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import zipfile

EXE = "TermsrvPatcherUnified.exe"
EXAMPLE = "Example.txt"
MAX_EXE = 512 * 1024 * 1024


def _exe(archive: zipfile.ZipFile, entry: zipfile.ZipInfo) -> tuple[int, str]:
    if entry.filename != EXE or entry.is_dir() or entry.flag_bits & 1:
        raise ValueError("Expected one unencrypted root EXE")
    if not 1024 <= entry.file_size <= MAX_EXE:
        raise ValueError("Bad EXE length")
    if (entry.external_attr >> 16) & 0xF000 not in (0, 0x8000):
        raise ValueError("Symlinks and special files are forbidden")
    with archive.open(entry) as payload:
        header = payload.read(65536)
    if len(header) < 0x100 or header[:2] != b"MZ":
        raise ValueError("Updater EXE does not have MZ headers")
    pe = struct.unpack_from("<I", header, 0x3C)[0]
    if pe < 0x40 or pe + 24 > len(header) or header[pe:pe+4] != b"PE\x00\x00":
        raise ValueError("Updater EXE has invalid PE headers")
    machine = struct.unpack_from("<H", header, pe + 4)[0]
    flags = struct.unpack_from("<H", header, pe + 22)[0]
    if machine != 0x8664 or (flags & 0x2000):
        raise ValueError("Updater requires an x64 PE executable, not a DLL")
    broken = archive.testzip()
    if broken is not None:
        raise ValueError("ZIP has a corrupted entry: " + broken)
    digest = hashlib.sha256()
    with archive.open(entry) as payload:
        for block in iter(lambda: payload.read(1024*1024), b""):
            digest.update(block)
    return entry.file_size, digest.hexdigest()


def validate(path: Path) -> tuple[int, str]:
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) != 1 or entries[0].filename != EXE:
            raise ValueError("Updater ZIP must contain exactly one root EXE")
        return _exe(archive, entries[0])


def validate_full(path: Path) -> tuple[int, str]:
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) != 2 or {entry.filename for entry in entries} != {EXE, EXAMPLE}:
            raise ValueError("Portable ZIP must contain exactly TermsrvPatcherUnified.exe and Example.txt")
        e = archive.getinfo(EXAMPLE)
        if e.is_dir() or e.flag_bits & 1 or not 30000 <= e.file_size <= 256*1024:
            raise ValueError("Example.txt is missing its complete license appendix")
        if (e.external_attr >> 16) & 0xF000 not in (0, 0x8000):
            raise ValueError("Example.txt must be a regular file")
        try:
            text = archive.read(e).decode("utf-8-sig")
        except UnicodeError as error:
            raise ValueError("Example.txt must be UTF-8") from error
        for required in (
            "Architecture, Find HEX bytes, Replace HEX bytes",
            "x64, 39 81 3C 06 00 00 0F 84",
            "BEGIN PROJECT NOTICES",
            "BEGIN GPLv3 LICENSE",
            "GNU GENERAL PUBLIC LICENSE",
            "BEGIN NSUDO MIT LICENSE",
            "BEGIN FABIANOSRC MIT LICENSE",
            "MIT License",
        ):
            if required not in text:
                raise ValueError("Example.txt missing required content: "+required)
        return _exe(archive, archive.getinfo(EXE))


def selftest() -> None:
    fake = bytearray(4096)
    fake[:2] = b"MZ"
    struct.pack_into("<I", fake, 0x3C, 0x80)
    fake[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", fake, 0x84, 0x8664)
    example = ("Architecture, Find HEX bytes, Replace HEX bytes\n"
               "x64, 39 81 3C 06 00 00 0F 84\n"
               "BEGIN PROJECT NOTICES\nBEGIN GPLv3 LICENSE\n"
               "GNU GENERAL PUBLIC LICENSE\nBEGIN NSUDO MIT LICENSE\n"
               "BEGIN FABIANOSRC MIT LICENSE\nMIT License\n" + "A"*32000)
    with tempfile.TemporaryDirectory() as directory:
        update = Path(directory)/"update.zip"
        full = Path(directory)/"full.zip"
        with zipfile.ZipFile(update, "w") as archive:
            archive.writestr(EXE, fake)
        result = validate(update)
        assert result[0] == 4096 and len(result[1]) == 64
        with zipfile.ZipFile(full, "w") as archive:
            archive.writestr(EXE, fake)
            archive.writestr(EXAMPLE, example)
        assert validate_full(full) == result
        with zipfile.ZipFile(full, "a") as archive:
            archive.writestr("NOTICE.md", "unexpected third file")
        try:
            validate_full(full)
        except ValueError as error:
            assert "exactly" in str(error)
        else:
            raise AssertionError("Extra portable ZIP entry accepted")
        with zipfile.ZipFile(full, "w") as archive:
            archive.writestr(EXE, fake)
            archive.writestr(EXAMPLE, example.replace("GNU GENERAL PUBLIC LICENSE", "MISSING"))
        try:
            validate_full(full)
        except ValueError as error:
            assert "missing required content" in str(error)
        else:
            raise AssertionError("Missing legal text accepted")
        with zipfile.ZipFile(update, "a") as archive:
            archive.writestr("Example.txt", example)
        try:
            validate(update)
        except ValueError as error:
            assert "exactly one" in str(error)
        else:
            raise AssertionError("Updater ZIP with sidecar accepted")
        with zipfile.ZipFile(update, "w") as archive:
            archive.writestr(EXE, bytes(4096))
        try:
            validate(update)
        except ValueError as error:
            assert "MZ" in str(error)
        else:
            raise AssertionError("Non-PE EXE accepted")
    print("PASS: two-file portable ZIP, one-EXE updater ZIP, negative archive tests")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        selftest()
        return 0
    full = len(sys.argv) == 3 and sys.argv[1] == "--full"
    if not ((len(sys.argv) == 2 and sys.argv[1] != "--full") or full):
        print("Usage: verify_update_package.py --self-test | [--full] path.zip", file=sys.stderr)
        return 2
    try:
        size, digest = (validate_full if full else validate)(Path(sys.argv[-1]))
    except (ValueError, FileNotFoundError, zipfile.BadZipFile) as error:
        print("FAIL: "+str(error), file=sys.stderr)
        return 1
    print(f"PASS: {'portable' if full else 'updater'} ZIP x64 EXE {size} bytes, SHA-256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
