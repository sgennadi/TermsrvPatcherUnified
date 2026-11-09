#!/usr/bin/env python3
"""Aggregate opt-in offline-file reports into a separate, bounded CSV.

Offline output reports do not imply a successful system installation. No file
paths, users, hostnames or real DLL bytes are transmitted; only a small edited
byte-range description, hashes and file version are public by operator consent.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import re
import sys

MARKER = "termsrv-offline/v1"
FIELDS = ("architecture", "file", "dll", "app", "original_sha256",
          "original_crc32", "patched_sha256", "patched_crc32", "edits")
COLUMNS = ("architecture", "dll_version", "app_version", "original_sha256",
           "original_crc32", "patched_sha256", "patched_crc32", "edits",
           "first_seen_utc", "last_seen_utc", "report_count")
HEX_EDIT = re.compile(r"0x([0-9A-F]{8}):((?:[0-9A-F]{2}){1,64})>((?:[0-9A-F]{2}){1,64})")


def parse(body: str) -> dict[str, str]:
    if not isinstance(body, str) or "\r" in body or len(body) > 6144:
        raise ValueError("Unsafe offline compatibility comment")
    lines = body.split("\n")
    if len(lines) != len(FIELDS) + 1 or lines[0] != MARKER:
        raise ValueError("Invalid offline report fields")
    record: dict[str, str] = {}
    for key, line in zip(FIELDS, lines[1:]):
        if not line.startswith(key + "="):
            raise ValueError("Unexpected compatibility field")
        record[key] = line[len(key) + 1:]
    if record["architecture"] not in ("x86", "x64") or record["file"] != "termsrv.dll":
        raise ValueError("Wrong target or architecture")
    if (record["dll"] != "Unknown" and
            re.fullmatch(r"[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}", record["dll"]) is None):
        raise ValueError("Invalid DLL version")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", record["app"]) is None:
        raise ValueError("Invalid application version")
    for key in ("original_sha256", "patched_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", record[key]) is None:
            raise ValueError("Invalid hash")
    if record["original_sha256"] == record["patched_sha256"]:
        raise ValueError("No changed bytes")
    for key in ("original_crc32", "patched_crc32"):
        if re.fullmatch(r"[0-9A-F]{8}", record[key]) is None:
            raise ValueError("Invalid CRC32")
    changes = record["edits"].split("|")
    if not 1 <= len(changes) <= 16:
        raise ValueError("Invalid number of edits")
    last_end = 0
    for change in changes:
        m = HEX_EDIT.fullmatch(change)
        if m is None:
            raise ValueError("Invalid byte-range edit")
        offset = int(m.group(1), 16)
        before, after = m.group(2), m.group(3)
        if offset < last_end or len(before) != len(after) or before == after:
            raise ValueError("Overlapping or invalid byte ranges")
        last_end = offset + len(before) // 2
    return record


def apply_event(event: dict, current: str) -> tuple[str, bool]:
    if not isinstance(event, dict) or event.get("action") != "created":
        return current, False
    issue = event.get("issue") or {}
    comment = event.get("comment") or {}
    if (issue.get("number") != 1 or "pull_request" in issue or
            comment.get("user", {}).get("type") == "Bot"):
        return current, False
    body = comment.get("body")
    if not isinstance(body, str) or not body.startswith(MARKER + "\n"):
        return current, False
    try:
        report = parse(body)
        when = datetime.fromisoformat(comment["created_at"].replace("Z", "+00:00"))
        if when.tzinfo is None:
            raise ValueError("Timestamp must be timezone-aware")
        stamp = when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (KeyError, AttributeError, ValueError, TypeError):
        return current, False

    rows: list[dict[str, str]]
    if current.strip():
        reader = csv.DictReader(io.StringIO(current))
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise ValueError("Unexpected offline CSV schema")
        rows = list(reader)
        if len(rows) > 20000 or any(None in r for r in rows):
            raise ValueError("CSV row limit or malformed data")
    else:
        rows = []
    values = (report["architecture"], report["dll"], report["app"],
              report["original_sha256"], report["original_crc32"],
              report["patched_sha256"], report["patched_crc32"], report["edits"])
    for row in rows:
        if tuple(row[c] for c in COLUMNS[:8]) == values:
            row["report_count"] = str(min(int(row["report_count"]) + 1, 1000000000))
            row["last_seen_utc"] = stamp
            break
    else:
        rows.append(dict(zip(COLUMNS, (*values, stamp, stamp, "1"))))
    rows.sort(key=lambda x: tuple(x[c] for c in COLUMNS[:8]))
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue(), True


def self_test() -> None:
    record = "\n".join((MARKER, "architecture=x86", "file=termsrv.dll",
        "dll=10.0.19041.1", "app=0.1.0-preview.11",
        "original_sha256=" + "a"*64, "original_crc32=1234ABCD",
        "patched_sha256=" + "b"*64, "patched_crc32=FFFFFFFF",
        "edits=0x00000040:11223344>AABBCCDD"))
    event = {"action": "created", "issue": {"number": 1},
             "comment": {"user": {"type": "User"},
                         "created_at": "2026-11-09T09:00:00Z", "body": record}}
    updated, ok = apply_event(event, ",".join(COLUMNS) + "\n")
    assert ok and "x86,10.0.19041.1" in updated
    updated, ok = apply_event(event, updated)
    assert ok and list(csv.DictReader(io.StringIO(updated)))[0]["report_count"] == "2"
    for invalid in (record + "\nname=PRIVATE", record.replace("architecture=x86", "architecture=arm64"),
        record.replace("original_crc32=1234ABCD", "original_crc32=bad"),
        record.replace("patched_sha256=" + "b"*64, "patched_sha256=" + "a"*64),
        record.replace("11223344>AABBCCDD", "11223344>11223344"),
        record.replace("0x00000040", "0x0000004G")):
        event["comment"]["body"] = invalid
        unchanged, accepted = apply_event(event, updated)
        assert not accepted and unchanged == updated
    event["comment"]["body"] = record
    event["issue"]["number"] = 2
    assert not apply_event(event, updated)[1]
    print("PASS: offline CRC32, SHA-256, architecture and byte-range report parser")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return 0
    if len(sys.argv) != 3 or sys.argv[2] != "data/offline-fixes.csv":
        print("Usage: record_offline_fix.py event.json data/offline-fixes.csv", file=sys.stderr)
        return 2
    event = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    target = Path(sys.argv[2])
    original = target.read_text(encoding="utf-8") if target.exists() else ""
    updated, changed = apply_event(event, original)
    if not changed:
        print("NOOP: not a valid, approved offline report")
        return 0
    tmp = target.with_suffix(".csv.tmp")
    try:
        tmp.write_text(updated, encoding="utf-8")
        tmp.replace(target)
    finally:
        tmp.unlink(missing_ok=True)
    print("PASS: offline-file report added to public CSV")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
