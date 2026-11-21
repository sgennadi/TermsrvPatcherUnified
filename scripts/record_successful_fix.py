#!/usr/bin/env python3
"""Aggregate opt-in, bounded version/hash/changed-byte compatibility comments.

Accept both v1 version-only reports and v2 reports. Do not execute submitted
text and do not mistake an opt-in report for proof of system compatibility.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import sys

BASE = ("windows", "release", "build", "ubr", "file", "dll", "app", "mode")
EXTRA = ("original_sha256", "patched_sha256", "edits")
V1 = "termsrv-success/v1"
V2 = "termsrv-success/v2"
OLD_COLUMNS = (
    "windows", "release", "build", "ubr", "file_name", "dll_version",
    "app_version", "mode", "first_seen_utc", "last_seen_utc", "report_count",
)
COLUMNS = OLD_COLUMNS[:8] + EXTRA + OLD_COLUMNS[8:]
EDIT = re.compile(r"0x([0-9A-F]{8}):((?:[0-9A-F]{2}){1,64})>((?:[0-9A-F]{2}){1,64})")


def parse_comment(body: str) -> dict[str, str]:
    if not isinstance(body, str) or "\r" in body or len(body) > 6144:
        raise ValueError("Compatibility report exceeds safe bounds")
    lines = body.split("\n")
    if not lines:
        raise ValueError("Empty report")
    marker = lines[0]
    fields = BASE + (EXTRA if marker == V2 else ())
    if marker not in (V1, V2) or len(lines) != len(fields) + 1:
        raise ValueError("Unknown report schema")
    if marker == V1 and len(body) > 400:
        raise ValueError("Legacy report too long")
    parsed: dict[str, str] = {}
    for name, line in zip(fields, lines[1:]):
        if not line.startswith(name + "="):
            raise ValueError("Unexpected report field")
        parsed[name] = line[len(name) + 1:]

    if parsed["windows"] not in ("Windows 10", "Windows 11"):
        raise ValueError("Unknown Windows product")
    if re.fullmatch(r"[A-Za-z0-9._-]{1,20}", parsed["release"]) is None:
        raise ValueError("Invalid Windows release")
    for field, low, high in (("build", 19041, 99999), ("ubr", 0, 999999)):
        digits = parsed[field]
        if not digits.isascii() or not digits.isdecimal() or not low <= int(digits) <= high:
            raise ValueError("Invalid Windows build")
    if parsed["file"] != "termsrv.dll":
        raise ValueError("Unknown DLL")
    if re.fullmatch(r"[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}", parsed["dll"]) is None:
        raise ValueError("Invalid DLL version")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", parsed["app"]) is None:
        raise ValueError("Invalid application version")
    if parsed["mode"] not in ("manual", "automatic"):
        raise ValueError("Unknown fix mode")
    if marker == V2:
        original, patched = parsed["original_sha256"], parsed["patched_sha256"]
        if (re.fullmatch(r"[0-9a-f]{64}", original) is None or
                re.fullmatch(r"[0-9a-f]{64}", patched) is None or original == patched):
            raise ValueError("Invalid SHA-256 metadata")
        edits = parsed["edits"].split("|")
        if not 1 <= len(edits) <= 16:
            raise ValueError("Invalid edit count")
        last_end = 0
        for entry in edits:
            m = EDIT.fullmatch(entry)
            if m is None:
                raise ValueError("Invalid change encoding")
            offset = int(m.group(1), 16)
            before, after = m.group(2), m.group(3)
            if offset < last_end or len(before) != len(after) or before == after:
                raise ValueError("Invalid or overlapping edits")
            last_end = offset + len(before) // 2
    else:
        parsed.update({field: "" for field in EXTRA})
    return parsed


def load_rows(existing: str) -> list[dict[str, str]]:
    if not existing.strip():
        return []
    reader = csv.DictReader(io.StringIO(existing))
    header = tuple(reader.fieldnames or ())
    if header not in (OLD_COLUMNS, COLUMNS):
        raise ValueError("Unexpected CSV schema")
    rows = list(reader)
    if len(rows) > 20000:
        raise ValueError("Maximum rows exceeded")
    for row in rows:
        if None in row or any(v is None for v in row.values()):
            raise ValueError("Invalid CSV data")
        if header == OLD_COLUMNS:
            row.update({key: "" for key in EXTRA})
    return rows


def apply_comment(event: dict, existing: str) -> tuple[str, bool]:
    if not isinstance(event, dict) or event.get("action") != "created":
        return existing, False
    issue, comment = event.get("issue") or {}, event.get("comment") or {}
    if issue.get("number") != 1 or "pull_request" in issue:
        return existing, False
    if comment.get("user", {}).get("type") == "Bot":
        return existing, False
    body = comment.get("body", "")
    if not isinstance(body, str) or not body.startswith((V1 + "\n", V2 + "\n")):
        return existing, False
    try:
        record = parse_comment(body)
    except ValueError:
        return existing, False
    timestamp = comment.get("created_at", "")
    if not isinstance(timestamp, str):
        raise ValueError("Missing GitHub timestamp")
    try:
        when = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(
            timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("Invalid GitHub timestamp") from exc
    rows = load_rows(existing)
    key = tuple(record[field] for field in BASE + EXTRA)
    for row in rows:
        if tuple(row[field] for field in COLUMNS[:11]) == key:
            row["report_count"] = str(min(int(row["report_count"]) + 1, 1000000000))
            row["last_seen_utc"] = when
            break
    else:
        rows.append(dict(zip(COLUMNS, (*key, when, when, "1"))))
    rows.sort(key=lambda row: (row["windows"], int(row["build"]), int(row["ubr"]),
                                row["dll_version"], row["app_version"], row["mode"],
                                row["original_sha256"], row["patched_sha256"], row["edits"]))
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue(), True


def self_test() -> None:
    core = ("windows=Windows 11", "release=24H2", "build=26100", "ubr=3415",
            "file=termsrv.dll", "dll=10.0.26100.3415",
            "app=0.1.0-preview.8", "mode=automatic")
    v1 = "\n".join((V1, *core))
    v2 = "\n".join((V2, *core, "original_sha256=" + "a" * 64,
                    "patched_sha256=" + "b" * 64,
                    "edits=0x00000028:11223344>AABBCCDD"))
    event = {"action": "created", "issue": {"number": 1},
             "comment": {"user": {"type": "User"},
                         "created_at": "2026-11-09T05:00:00Z", "body": v1}}
    legacy, ok = apply_comment(event, ",".join(OLD_COLUMNS) + "\n")
    assert ok and legacy.startswith(",".join(COLUMNS))
    event["comment"]["body"] = v2
    migrated, ok = apply_comment(event, legacy)
    assert ok and len(list(csv.DictReader(io.StringIO(migrated)))) == 2
    twice, ok = apply_comment(event, migrated)
    assert ok
    rows = list(csv.DictReader(io.StringIO(twice)))
    assert sorted(int(row["report_count"]) for row in rows) == [1, 2]
    assert any(row["original_sha256"] == "a" * 64 and
               row["edits"] == "0x00000028:11223344>AABBCCDD" for row in rows)
    for bad in (v2 + "\nhostname=SECRET", v2.replace("b" * 64, "a" * 64),
                v2.replace("0x00000028", "0x0000002G"),
                v2.replace("11223344>AABBCCDD", "11223344>11223344"),
                v2.replace("0x00000028:11223344>AABBCCDD",
                           "0x00000028:11223344>AABBCCDD|0x0000002A:1122>3344"),
                v2.replace("edits=0x00000028:11223344>AABBCCDD", "edits=")):
        event["comment"]["body"] = bad
        rejected, accepted = apply_comment(event, twice)
        assert not accepted and rejected == twice
    event["comment"]["body"] = v1
    event["comment"]["user"]["type"] = "Bot"
    rejected, accepted = apply_comment(event, twice)
    assert not accepted and rejected == twice
    print("PASS: bounded v1/v2 compatibility schemas, SHA-256, byte ranges and CSV migration")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return 0
    if len(sys.argv) != 3:
        print("Usage: record_successful_fix.py event.json output.csv", file=sys.stderr)
        return 2
    event = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    target = Path(sys.argv[2])
    if target.as_posix() != "data/successful-fixes.csv":
        raise ValueError("CSV output path is restricted")
    existing = target.read_text(encoding="utf-8") if target.exists() else ""
    updated, changed = apply_comment(event, existing)
    if not changed:
        print("NOOP: unrelated/invalid GitHub Issue comment")
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(".csv.tmp")
    try:
        temp.write_text(updated, encoding="utf-8")
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)
    print("PASS: updated opt-in compatibility CSV")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
