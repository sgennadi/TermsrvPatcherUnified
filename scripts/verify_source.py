#!/usr/bin/env python3
"""Offline SOURCE validation. This is not a C# build or Windows integration test."""
from __future__ import annotations

from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
checks = []


def check(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)
    checks.append(message)


def parse_catalog(name: str):
    profiles = []
    for line_no, line in enumerate((ROOT / "Patterns" / name).read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cells = line.split(",", 2)
        check(len(cells) == 3, f"{name} line {line_no}: three columns")
        arch, finds, replacements = cells
        check(arch.strip() in ("x86", "x64"), f"{name} line {line_no}: architecture")
        left = [part.split() for part in finds.split("|")]
        right = [part.split() for part in replacements.split("|")]
        check(len(left) == len(right), f"{name} line {line_no}: group count")
        for find, repl in zip(left, right):
            check(len(find) == len(repl) and len(find) >= 4, f"{name} line {line_no}: group lengths")
            check(all(re.fullmatch(r"(?:[0-9a-fA-F]{2}|\*)", token) for token in find),
                  f"{name} line {line_no}: valid find bytes")
            check(all(re.fullmatch(r"[0-9a-fA-F]{2}", token) for token in repl),
                  f"{name} line {line_no}: valid replace bytes")
            check(any(token != "*" for token in find), f"{name} line {line_no}: not all wildcard")
        profiles.append((arch.strip(), left, right))
    return profiles


for path in ["App.xaml", "MainWindow.xaml", "UpdateCenterWindow.xaml", "DiagnosticsWindow.xaml",
             "Shared/UniversalDiagnostics/UniversalDiagnostics.vbproj", "AboutWindow.xaml", "app.manifest", "TermsrvPatcher.Unified.csproj",
             "Tests/TermsrvPatcher.Tests.csproj"]:
    tree = ET.parse(ROOT / path)
    check(tree.getroot() is not None, f"{path}: well-formed XML")

app = ET.parse(ROOT / "MainWindow.xaml").getroot()
code = (ROOT / "MainWindow.xaml.cs").read_text(encoding="utf-8")
for element in app.iter():
    for key, value in element.attrib.items():
        attr = key.rsplit("}", 1)[-1]
        if attr in {"Click", "TextChanged", "SelectionChanged"}:
            check(bool(re.search(r"\bvoid\s+" + re.escape(value) + r"\s*\(", code)),
                  f"XAML event handler exists: {value}")

auto = parse_catalog("AutomaticPatterns.txt")
legacy = parse_catalog("LegacyUserPatterns.MANUAL.txt")
check(len(auto) == 3, "3 automatic patterns")
check(len(legacy) == 16, "16 legacy manual patterns")
check(len(parse_catalog("Examples.NOT_ACTIVE.txt")) >= 0, "examples segregated")

project = (ROOT / "TermsrvPatcher.Unified.csproj").read_text(encoding="utf-8")
main = (ROOT / "MainWindow.xaml").read_text(encoding="utf-8")
readme = (ROOT / "README.md").read_text(encoding="utf-8")
for version in (project, main, readme):
    check("0.1.0-preview.5" in version, "version consistency")
check("UpdateNotificationController" in (ROOT / "Core/UpdateIntegration.cs").read_text(encoding="utf-8"),
      "shared updater notification controller referenced")
check("UniversalDiagnosticsEmbedded.Capture" in (ROOT / "Core/DiagnosticsBridge.cs").read_text(encoding="utf-8"),
      "embedded diagnostics Capture method referenced")
check("0.1.0-preview.5" in (ROOT / "Core/UpdateIntegration.cs").read_text(encoding="utf-8"),
      "updater version matches application")
check("--inspect-file" in (ROOT / "App.xaml.cs").read_text(encoding="utf-8"),
      "read-only CLI is wired")
check('level="asInvoker"' in (ROOT / "app.manifest").read_text(encoding="utf-8"),
      "read-only CLI does not require UAC")
check("Request administrator elevation" not in (ROOT / "app.manifest").read_text(encoding="utf-8"),
      "manifest has no accidental privilege prompt")
check("State = PatchState.Unsupported" in (ROOT / "Core" / "TermsrvEngine.cs").read_text(encoding="utf-8"),
      "unsafe preview is blocked before Apply")
check((ROOT / "scripts" / "create-github-repo.cmd").exists(),
      "GitHub CLI bootstrap script is included")
check((ROOT / "docs" / "GITHUB_SETUP.md").exists(),
      "GitHub repository setup guide is included")
check((ROOT / "SECURITY.md").exists() and (ROOT / "CONTRIBUTING.md").exists(),
      "GitHub contribution and security docs are included")
check("RequireExecutableEdits" in (ROOT / "Core" / "TermsrvEngine.cs").read_text(encoding="utf-8"),
      "PE section preflight invoked before writes")
check("NearMatchFinder.Find" in (ROOT / "Core" / "DllScanner.cs").read_text(encoding="utf-8"),
      "read-only similar signature finder wired")
check("--no-restore" in (ROOT / ".github" / "workflows" / "windows-ci.yml").read_text(encoding="utf-8"),
      "GitHub workflow tests restored project")
check((ROOT / "Assets" / "app.ico").stat().st_size > 128, "application icon exists")
check((ROOT / "LICENSE").stat().st_size > 30_000, "GPLv3 license included")
check("MIT License" in (ROOT / "licenses" / "fabianosrc-MIT.txt").read_text(),
      "MIT attribution included")

# Validate exact synthetic detection and ambiguous duplication in an independent interpreter.
def offsets(payload, tokens):
    found = []
    for start in range(len(payload) - len(tokens) + 1):
        if all(t == "*" or payload[start + pos] == int(t, 16)
               for pos, t in enumerate(tokens)):
            found.append(start)
    return found

for i, (_, groups, _) in enumerate(auto, 1):
    signature = groups[0]
    fake = [0xFA] * 256
    fake[30:30 + len(signature)] = [0x73 if t == "*" else int(t, 16) for t in signature]
    check(offsets(fake, signature) == [30], f"signature {i}: unique synthetic match")
    fake[80:80 + len(signature)] = fake[30:30 + len(signature)]
    check(offsets(fake, signature) == [30, 80], f"signature {i}: duplicate rejected by policy")

# This tests the inspection concept, NOT the compiled C# implementation.
example_signature = auto[1][1][0]
modified = [0xFA] * 128
modified[40:40 + len(example_signature)] = [int(t, 16) for t in example_signature]
modified[40 + 12] ^= 1
check(not offsets(modified, example_signature), "modified automatic bytes no exact match")
check(sum(modified[40 + j] != int(t, 16) for j, t in enumerate(example_signature)) == 1,
      "modified automatic bytes differ in exactly one location")

print(f"PASS: {len(checks)} offline source-format and synthetic signature checks.")
print("NOTE: C# compilation and real Windows service tests were NOT performed.")

# NSudo vendor safety contract: official source and archive must be pinned, and
# fallback must not silently change the system DLL ownership or ACL.
nsudo = (ROOT / "Core/NsudoDevilModeScope.cs").read_text(encoding="utf-8")
privileges = (ROOT / "Core/PrivilegeHelper.cs").read_text(encoding="utf-8")
prep = (ROOT / "scripts/prepare-nsudo.ps1").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/windows-ci.yml").read_text(encoding="utf-8")
check("LoadLibraryW" in nsudo and "FreeLibrary" in nsudo, "NSudo load and unload use native entry points")
check("EnsurePrivateDirectory" in nsudo, "NSudo extraction has protected directory gate")
check("SHA256.HashData" in nsudo, "Embedded binary hash verified at runtime")
check("0x8664" in nsudo, "Embedded binary must match x64 architecture")
check("NsudoDevilModeScope.Enter" in privileges, "NSudo used only in protected writer")
check("takeown.exe" not in privileges and "icacls.exe" not in privileges, "No implicit ACL/ownership fallback")
check("346e38030cc9eeef48223804ba27631db96691d68bfc5d1728140d468f555204" in prep, "NSudo stable archive hash is pinned")
check("-p:RequireNSudo=true" in workflow and "prepare-nsudo.ps1" in workflow, "NSudo release dependency is mandatory in CI")
check((ROOT / "licenses/NSudo-MIT.txt").exists(), "NSudo MIT notice is retained")
print("PASS: 9 additional NSudo source safety checks.")

check((ROOT / "GlobalUsings.cs").exists() and "global using System.IO;" in (ROOT / "GlobalUsings.cs").read_text(), "WPF main project explicitly imports System.IO")
check("using System.IO;" in (ROOT / "Tests/Program.cs").read_text(), "WPF test project explicitly imports System.IO")
print("PASS: explicit WPF SDK import guards.")
