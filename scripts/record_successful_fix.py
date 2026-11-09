#!/usr/bin/env python3
"""Aggregate opt-in, version-only GitHub Issue comments into a CSV file.

Never executes shell commands from GitHub comments. This is not validation of
RDP functionality or of the legal entitlement to modify Windows system files.
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
import tempfile

COLUMNS = (
    "windows", "release", "build", "ubr", "file_name", "dll_version", "app_version",
    "mode", "first_seen_utc", "last_seen_utc", "report_count",
)
REQUIRED = ("windows", "release", "build", "ubr", "file", "dll", "app", "mode")
MARKER = "termsrv-success/v1"


def parse_comment(body: str) -> dict[str, str]:
    if not isinstance(body, str) or len(body) > 400 or "\r" in body:
        raise ValueError("Comment format or length is invalid")
    lines = body.split("\n")
    if len(lines) != 9 or lines[0] != MARKER:
        raise ValueError("Compatibility marker or fields do not match")
    parsed: dict[str, str] = {}
    for key, line in zip(REQUIRED, lines[1:]):
        prefix = key + "="
        if not line.startswith(prefix):
            raise ValueError("Unexpected compatibility field")
        parsed[key] = line[len(prefix):]
    if parsed["windows"] not in ("Windows 10", "Windows 11"):
        raise ValueError("Unknown Windows edition family")
    if re.fullmatch(r"[A-Za-z0-9._-]{1,20}", parsed["release"]) is None:
        raise ValueError("Invalid Windows release")
    for name, minimum, maximum in (("build", 19041, 99999), ("ubr", 0, 999999)):
        value = parsed[name]
        if not value.isascii() or not value.isdecimal() or not minimum <= int(value) <= maximum:
            raise ValueError("Invalid Windows build metadata")
    if parsed["file"] != "termsrv.dll":
        raise ValueError("Unsupported target file")
    if re.fullmatch(r"[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}", parsed["dll"]) is None:
        raise ValueError("Invalid DLL version")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", parsed["app"]) is None:
        raise ValueError("Invalid application version")
    if parsed["mode"] not in ("manual", "automatic"):
        raise ValueError("Unknown application mode")
    return parsed


def apply_comment(event: dict, existing: str) -> tuple[str, bool]:
    if not isinstance(event, dict) or event.get("action") != "created":
        return existing, False
    issue = event.get("issue") or {}
    comment = event.get("comment") or {}
    if issue.get("number") != 1 or "pull_request" in issue:
        return existing, False
    # Any logged-in GitHub user can submit. Only this exact version schema
    # is aggregated, and no comment text is executed as code.
    if comment.get("user", {}).get("type") == "Bot":
        return existing, False
    body = comment.get("body", "")
    if not isinstance(body, str) or not body.startswith(MARKER + "\n"):
        return existing, False
    try:
        record = parse_comment(body)
    except ValueError:
        return existing, False
    timestamp = comment.get("created_at", "")
    if not isinstance(timestamp, str):
        raise ValueError("Missing GitHub creation time")
    try:
        created = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone(
            timezone.utc)
    except ValueError as exc:
        raise ValueError("Invalid GitHub time") from exc
    when = created.strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = list(csv.DictReader(io.StringIO(existing))) if existing.strip() else []
    if rows and tuple(rows[0]) != COLUMNS:
        raise ValueError("Unexpected compatibility CSV schema")
    if len(rows) > 20_000:
        raise ValueError("Compatibility CSV row limit reached")
    key = (
        record["windows"], record["release"], record["build"], record["ubr"],
        record["file"], record["dll"], record["app"], record["mode"],
    )
    changed = False
    for row in rows:
        current = tuple(row[name] for name in COLUMNS[:8])
        if current == key:
            try:
                count = int(row["report_count"])
            except (TypeError, ValueError) as exc:
                raise ValueError("Compatibility CSV count is invalid") from exc
            row["report_count"] = str(min(count + 1, 1_000_000_000))
            row["last_seen_utc"] = when
            changed = True
            break
    if not changed:
        rows.append(dict(zip(COLUMNS, (
            *key, when, when, "1",
        ))))
    rows.sort(key=lambda x: (
        x["windows"], int(x["build"]), int(x["ubr"]),
        x["dll_version"], x["app_version"], x["mode"]))
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue(), True


def self_test() -> None:
    body = "\n".join((MARKER, "windows=Windows 11", "release=24H2",
        "build=26100", "ubr=3415", "file=termsrv.dll", "dll=10.0.26100.3415",
        "app=0.1.0-preview.7", "mode=automatic"))
    event = {"action": "created", "issue": {"number": 1},
        "comment": {"user": {"type": "User"},
                    "created_at": "2026-11-09T05:00:00Z", "body": body}}
    result, changed = apply_comment(event, "")
    assert changed and "Windows 11,24H2,26100,3415,termsrv.dll" in result
    result2, changed = apply_comment(event, result)
    assert changed and ",2\n" in result2
    event["comment"]["body"] += "\nhostname=SECRET"
    ignored, changed = apply_comment(event, result2)
    assert ignored == result2 and not changed, "Unexpected private field was accepted"
    event["comment"]["body"] = "Unrelated issue discussion"
    ignored, changed = apply_comment(event, result2)
    assert ignored == result2 and not changed
    event["comment"]["body"] = body
    event["comment"]["user"] = {"type": "Bot"}
    ignored, changed = apply_comment(event, result2)
    assert ignored == result2 and not changed
    print("PASS: safe, bounded version-only compatibility aggregation and negative tests")

def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return 0
    if len(sys.argv) != 3:
        print("Usage: record_successful_fix.py event.json output.csv", file=sys.stderr)
        return 2
    event = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    destination = Path(sys.argv[2])
    if destination.as_posix() != "data/successful-fixes.csv":
        raise ValueError("Output path is fixed by repository policy")
    existing = destination.read_text(encoding="utf-8") if destination.exists() else ""
    updated, changed = apply_comment(event, existing)
    if not changed:
        print("NOOP: unrelated or unauthorized comment")
        return 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    # GitHub runner checkout is the only intended output. Fixed filename, no
    # user-controlled path or shell interpolation.
    temporary = destination.with_suffix(".csv.tmp")
    try:
        temporary.write_text(updated, encoding="utf-8")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    print("PASS: updated opt-in compatibility CSV")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
