#!/usr/bin/env python3
"""Recover ONLY the pinned NSudo 8.2 x64 DLL from a previously verified CI EXE.

Fallback when the archived GitHub release CDN is unavailable. This is NOT a
generic PE extractor: both the prior release ZIP and contained EXE hashes and
the recovered native DLL SHA-256 must match fixed reviewed values.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import struct
import sys
import zipfile

PINNED_PREVIEW_ZIP = "dfc040185587c2897630871111f3d272af671d7364d6cfd990508bac7396a10d"
PINNED_PREVIEW_EXE = "b43650a5d443e182ed56c91af75dcd185e7364fd09e26c0bf1db8f09e8176223"
PINNED_DLL_SHA256 = "d55f34fde79021338446a2c3bc8de36e074c473bb3038d8d8cd33de80bd59168"
PINNED_DLL_MD5 = "5ed8991f370151275e73f53a9a3474e3"
FILE_NAME = "TermsrvPatcherUnified.exe"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recover(executable: bytes) -> bytes:
    matches: list[bytes] = []
    location = 0
    while True:
        start = executable.find(b"MZ", location)
        if start < 0:
            break
        location = start + 2
        if start + 0x40 > len(executable):
            continue
        pe_offset = struct.unpack_from("<I", executable, start + 0x3C)[0]
        if not (0x40 <= pe_offset <= 0x600):
            continue
        pe = start + pe_offset
        if pe + 24 > len(executable) or executable[pe:pe + 4] != b"PE\x00\x00":
            continue
        machine, sections, _, _, _, optional, flags = struct.unpack_from(
            "<HHIIIHH", executable, pe + 4)
        if machine != 0x8664 or not (flags & 0x2000) or not 1 <= sections <= 24:
            continue
        table = pe + 24 + optional
        if table + 40 * sections > len(executable):
            continue
        length = 0
        for index in range(sections):
            header = table + 40 * index
            size, offset = struct.unpack_from("<II", executable, header + 16)
            length = max(length, offset + size)
        if not (8192 <= length <= 512000) or start + length > len(executable):
            continue
        candidate = executable[start:start + length]
        if hashlib.md5(candidate).hexdigest() != PINNED_DLL_MD5:
            continue
        if sha256(candidate) != PINNED_DLL_SHA256:
            raise ValueError("Pinned NSudo DLL SHA-256 mismatch")
        matches.append(candidate)
    if len(matches) != 1:
        raise ValueError("Expected exactly one pinned x64 NSudo 8.2 library")
    return matches[0]


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: recover-nsudo-from-preview.py preview6-dist.zip output-directory",
              file=sys.stderr)
        return 2
    archive = Path(sys.argv[1])
    if sha256(archive.read_bytes()) != PINNED_PREVIEW_ZIP:
        raise ValueError("Preview.6 ZIP checksum does not match the pinned artifact")
    with zipfile.ZipFile(archive) as z:
        if FILE_NAME not in z.namelist():
            raise ValueError("Prior preview package has no expected EXE")
        exe = z.read(FILE_NAME)
    if sha256(exe) != PINNED_PREVIEW_EXE:
        raise ValueError("Prior preview EXE is not the exact verified build")
    dll = recover(exe)
    target = Path(sys.argv[2])
    target.mkdir(parents=True, exist_ok=True)
    (target / "NSudoDM.dll").write_bytes(dll)
    (target / "NSudoDM.sha256").write_text(PINNED_DLL_SHA256, encoding="ascii")
    print(f"PASS: recovered pinned official NSudo 8.2 x64 (SHA256 {PINNED_DLL_SHA256})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
