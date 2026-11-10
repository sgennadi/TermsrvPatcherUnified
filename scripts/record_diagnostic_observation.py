#!/usr/bin/env python3
"""Untrusted, opt-in Termsrv diagnostic observations -> public, inert CSV.

This script NEVER changes Patterns/ or treats an anonymous report as proof of
a successful Apply. Source GitHub Issue body is untrusted, even if a relay
normally creates it. The contents must match the strict server-rendered form.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import uuid

PROJECT = "sgennadi/TermsrvPatcherUnified"
MARKER = "<!-- udx-report-id:"
HEADER = "## Anonymous UniversalDiagnostics"
FOOTER = "Only reviewed typed metadata. No descriptions, logs, secrets, hostnames or account identifiers."
NAMES = ("Schema", "Project", "Component", "Version", "Severity", "Error class",
         "Error code", "Observed UTC", "OS", "Architecture", "Fingerprint",
         "Windows release", "Windows build", "Windows UBR", "DLL version", "DLL SHA-256")
COLUMNS = ("issue_number", "observed_utc", "received_utc", "windows_release",
           "windows_build", "windows_ubr", "dll_version", "dll_sha256",
           "app_version", "component", "error_type", "error_code",
           "severity", "architecture", "verification")
SAFE = re.compile(r"\A[A-Za-z][A-Za-z0-9 _-]{0,55}\Z")
ERROR = re.compile(r"\A[A-Za-z][A-Za-z0-9_]{0,63}\Z")
CODE = re.compile(r"\A(?:0x[A-Fa-f0-9]{1,8}|[A-Za-z0-9_-]{1,32})\Z")
APP = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?\Z")
RELEASE = re.compile(r"\A[A-Za-z0-9._-]{1,20}\Z")
DLL = re.compile(r"\A[0-9]{1,5}(?:\.[0-9]{1,8}){1,4}\Z")
HASH = re.compile(r"\A[a-f0-9]{64}\Z")
EVENT_TITLE = re.compile(r"\A\[Diagnostics\] TermsrvPatcherUnified ([0-9a-f]{8})\Z")


def parse(event: dict) -> dict[str, str] | None:
    if not isinstance(event, dict) or event.get("action") != "opened":
        return None
    issue = event.get("issue")
    if not isinstance(issue, dict) or "pull_request" in issue:
        return None
    number = issue.get("number")
    title, body = issue.get("title"), issue.get("body")
    if not isinstance(number, int) or isinstance(number, bool) or not 1 <= number <= 999999999:
        return None
    if not isinstance(title, str) or not EVENT_TITLE.fullmatch(title):
        return None
    if not isinstance(body, str) or len(body) > 4096 or "\r" in body:
        return None
    if issue.get("html_url") != f"https://github.com/{PROJECT}/issues/{number}":
        return None
    repository = event.get("repository")
    if isinstance(repository, dict) and repository.get("full_name") != PROJECT:
        return None
    lines = body.rstrip("\n").split("\n")
    if (len(lines) != len(NAMES) + 5 or
            lines[1:3] != [HEADER, ""] or
            lines[-2:] != ["", FOOTER] or
            not lines[0].startswith(MARKER) or
            not lines[0].endswith(" -->")):
        return None
    event_id = lines[0][len(MARKER):-4]
    try:
        parsed_id = uuid.UUID(event_id)
    except (ValueError, AttributeError):
        return None
    if parsed_id.version != 4 or str(parsed_id) != event_id or event_id[:8] != EVENT_TITLE.fullmatch(title).group(1):
        return None
    values: dict[str, str] = {}
    for name, line in zip(NAMES, lines[3:-2]):
        prefix = f"- {name}: "
        if not line.startswith(prefix):
            return None
        values[name] = line[len(prefix):]
    if values["Schema"] != "universal-diagnostics/v1" or values["Project"] != PROJECT:
        return None
    if not SAFE.fullmatch(values["Component"]) or not ERROR.fullmatch(values["Error class"]):
        return None
    if not CODE.fullmatch(values["Error code"]) or not APP.fullmatch(values["Version"]):
        return None
    if values["Severity"] not in ("error", "warning", "info"):
        return None
    if values["OS"] != "Windows" or values["Architecture"] != "AMD64":
        return None
    if not RELEASE.fullmatch(values["Windows release"]) or not DLL.fullmatch(values["DLL version"]):
        return None
    if not HASH.fullmatch(values["DLL SHA-256"]) or not HASH.fullmatch(values["Fingerprint"]):
        return None
    if any(not v.isascii() or not v.isdecimal() for v in (values["Windows build"], values["Windows UBR"])):
        return None
    if not (19041 <= int(values["Windows build"]) <= 99999 and
            0 <= int(values["Windows UBR"]) <= 999999):
        return None
    expected = hashlib.sha256("|".join((values["Project"], values["Component"],
        values["Error class"], values["Error code"])).lower().encode("utf-8")).hexdigest()
    if values["Fingerprint"] != expected:
        return None
    try:
        seen = datetime.strptime(values["Observed UTC"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        received = datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00"))
        if received.tzinfo is None or seen < received - timedelta(days=90) or seen > received + timedelta(minutes=5):
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return dict(zip(COLUMNS, (
        str(number), seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
        received.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        values["Windows release"], values["Windows build"], values["Windows UBR"],
        values["DLL version"], values["DLL SHA-256"], values["Version"],
        values["Component"], values["Error class"], values["Error code"],
        values["Severity"], values["Architecture"], "unverified"
    )))


def apply_event(event: dict, existing: str) -> tuple[str, bool]:
    record = parse(event)
    if record is None:
        return existing, False
    if existing.strip():
        reader = csv.DictReader(io.StringIO(existing))
        if tuple(reader.fieldnames or ()) != COLUMNS:
            raise ValueError("Unexpected diagnostic observations header.")
        records = list(reader)
        if len(records) > 20000 or any(None in row or set(row) != set(COLUMNS) for row in records):
            raise ValueError("Diagnostic observations CSV is malformed or oversized.")
    else:
        records = []
    if any(row["issue_number"] == record["issue_number"] for row in records):
        return existing, False
    records.append(record)
    records.sort(key=lambda r: int(r["issue_number"]))
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(records)
    return output.getvalue(), True


def self_test() -> None:
    uid = "c7d5e980-21ba-4bbb-86bc-7995c182d81b"
    values = ("universal-diagnostics/v1", PROJECT, "RdpSettings",
        "0.1.0-preview.23", "error", "InvalidOperationException", "0x80131509",
        "2026-11-10T06:40:00Z", "Windows", "AMD64")
    fp = hashlib.sha256("|".join((PROJECT,"RdpSettings","InvalidOperationException","0x80131509")).lower().encode()).hexdigest()
    full = (*values, fp, "25H2", "26200", "1234", "10.0.26200.1234", "a"*64)
    body = (f"{MARKER}{uid} -->\n{HEADER}\n\n" +
        "\n".join(f"- {k}: {v}" for k,v in zip(NAMES, full)) +
        f"\n\n{FOOTER}\n")
    event = {"action":"opened","issue":{"number":42,
        "title":"[Diagnostics] TermsrvPatcherUnified "+uid[:8],
        "body":body, "created_at":"2026-11-10T06:45:00Z",
        "html_url":f"https://github.com/{PROJECT}/issues/42"},
        "repository":{"full_name":PROJECT}}
    original = ",".join(COLUMNS)+"\n"
    updated, changed = apply_event(event, original)
    assert changed and len(list(csv.DictReader(io.StringIO(updated)))) == 1
    assert "a"*64 in updated and updated.endswith(",unverified\n")
    assert not apply_event(event, updated)[1]  # Duplicate event safe.
    for malicious in (
        body + "\nHOSTNAME=PRIVATE", body.replace("a"*64, "G"*64),
        body.replace("- DLL SHA-256:", "- Password:"),
        body.replace("26200", "invalid"),
        body.replace(fp, "0"*64),
        body.replace("- DLL SHA-256: "+"a"*64, "- DLL SHA-256: "+"a"*64+"\n- IP: 1.2.3.4")
    ):
        event["issue"]["body"] = malicious
        assert not apply_event(event, original)[1]
    event["issue"]["body"] = body
    event["issue"]["title"] = "Untrusted fake issue"
    assert not apply_event(event, original)[1]
    print("PASS: strict anonymous DLL evidence format, SHA256, dedup, fail-closed unverified CSV")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return 0
    if len(sys.argv) != 3 or sys.argv[2] != "data/diagnostic-observations.csv":
        print("Usage: record_diagnostic_observation.py GitHubEvent.json data/diagnostic-observations.csv", file=sys.stderr)
        return 2
    event = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    dst = Path(sys.argv[2])
    current = dst.read_text(encoding="utf-8") if dst.exists() else ""
    modified, changed = apply_event(event, current)
    if not changed:
        print("NOOP: unrelated, legacy or malformed diagnostic issue.")
        return 0
    tmp = dst.with_suffix(".csv.tmp")
    try:
        tmp.write_text(modified, encoding="utf-8")
        tmp.replace(dst)
    finally:
        tmp.unlink(missing_ok=True)
    print("PASS: appended an explicitly unverified diagnostic observation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
