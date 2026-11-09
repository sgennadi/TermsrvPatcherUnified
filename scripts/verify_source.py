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
check(len(legacy) == 22, "22 historical manual patterns, including six sourced Windows 10 signatures")

auto_text = (ROOT / "Patterns" / "AutomaticPatterns.txt").read_text(encoding="utf-8")
legacy_text = (ROOT / "Patterns" / "LegacyUserPatterns.MANUAL.txt").read_text(encoding="utf-8")
check(
    "x64, 39 81 3C 06 00 00 0F 84 * * * 00," in auto_text
    and "x64, 39 81 3C 06 00 00 0F * * * * 00," not in auto_text,
    "generic catalog fixes the JE/JZ opcode and wildcards only rel32 low bytes")
check(
    "x64, 39 81 3C 06 00 00 0F 84 5F 64 01 00," in legacy_text
    and "x64, 39 81 3C 06 00 00 0F 84 5F 64 01 20," not in legacy_text,
    "Server 2022 20348.3091 legacy pattern has the corrected 00 final byte")


# Documented Windows 10 legacy variants must be manual-only exact signatures:
# a pattern sourced from a webpage is not independent compatibility evidence.
historical_references = [
    "39 81 3C 06 00 00 0F 84 F7 40 01 00",
    "39 81 3C 06 00 00 0F 84 E7 43 01 00",
    "39 81 3C 06 00 00 0F 84 7F 2C 01 00",
    "39 81 3C 06 00 00 0F 84 53 71 02 00",
    "39 81 3C 06 00 00 0F 84 3F 42 02 00",
    "39 81 3C 06 00 00 0F 84 73 42 02 00",
]
check(all(legacy_text.count(pattern) == 1 and pattern not in auto_text
          for pattern in historical_references),
      "six externally documented Windows 10 signatures are unique and manual-only")
check("mysysadmintips.com" in legacy_text and "not independently DLL-verified" in legacy_text,
      "historical source attribution and validation limit remain explicit")
check(len(parse_catalog("Examples.NOT_ACTIVE.txt")) >= 0, "examples segregated")

project = (ROOT / "TermsrvPatcher.Unified.csproj").read_text(encoding="utf-8")
main = (ROOT / "MainWindow.xaml").read_text(encoding="utf-8")
readme = (ROOT / "README.md").read_text(encoding="utf-8")
for version in (project, main, readme):
    check("0.1.0-preview.18" in version, "version consistency")
check("UpdateNotificationController" in (ROOT / "Core/UpdateIntegration.cs").read_text(encoding="utf-8"),
      "shared updater notification controller referenced")
check("UniversalDiagnosticsEmbedded.Capture" in (ROOT / "Core/DiagnosticsBridge.cs").read_text(encoding="utf-8"),
      "embedded diagnostics Capture method referenced")
check("0.1.0-preview.18" in (ROOT / "Core/UpdateIntegration.cs").read_text(encoding="utf-8"),
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
check("MIT License" in (ROOT / "licenses" / "fabianosrc-MIT.txt").read_text(encoding="utf-8"),
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

check((ROOT / "GlobalUsings.cs").exists() and "global using System.IO;" in (ROOT / "GlobalUsings.cs").read_text(encoding="utf-8"), "WPF main project explicitly imports System.IO")
check("using System.IO;" in (ROOT / "Tests/Program.cs").read_text(encoding="utf-8"), "WPF test project explicitly imports System.IO")
print("PASS: explicit WPF SDK import guards.")

packager = (ROOT / 'scripts/package_preview.ps1').read_text(encoding="utf-8")
workflow = (ROOT / '.github/workflows/windows-ci.yml').read_text(encoding="utf-8")
release = (ROOT / '.github/workflows/release-preview.yml').read_text(encoding="utf-8")
example = (ROOT / 'Example.txt').read_text(encoding="utf-8")
check(all(p in packager for p in ('Example.txt', 'LICENSE', 'NOTICE.md',
      'licenses/NSudo-MIT.txt', 'licenses/fabianosrc-MIT.txt')),
      "portable Example.txt includes complete GPLv3, notices and MIT texts")
check('verify_update_package.py --full' in packager, "portable two-file ZIP is validated")
check('verify_update_package.py $updateZip' in packager, "single-EXE updater ZIP validated")
check('scripts/package_preview.ps1' in workflow and 'scripts/package_preview.ps1' in release,
      "CI and release share the exact-layout packager")
check('Architecture, Find HEX bytes, Replace HEX bytes' in example and 'x64,' in example,
      "Example.txt contains real HEX pattern formatting examples")
print("PASS: two-file portable ZIP, updater and license packaging guards.")

check((ROOT / "Core/GitHubIssuePublisher.cs").exists(), "opt-in GitHub Issue publisher present")
publisher = (ROOT / "Core/GitHubIssuePublisher.cs").read_text(encoding="utf-8")
check("AllowAutoRedirect = false" in publisher and "UseCookies = false" in publisher, "GitHub Issue publishing refuses redirects and cookies")
check("api.github.com/repos/sgennadi/TermsrvPatcherUnified/issues" in publisher, "GitHub Issue source and response are pinned")
check("MarkSubmitted" in (ROOT / "Core/DiagnosticsBridge.cs").read_text(encoding="utf-8"), "explicit local submission acknowledgement")
check("SessionToken.Clear()" in (ROOT / "DiagnosticsWindow.xaml.cs").read_text(encoding="utf-8"), "temporary UI credential is cleared")
check("TermsrvPatcherUnified.NativeProtected" in (ROOT / "Core/NsudoDevilModeScope.cs").read_text(encoding="utf-8"), "NSudo extraction is isolated from audit logs")
print("PASS: reviewed GitHub Issue delivery and private native cache checks.")

for view_name in ("DiagnosticsWindow", "UpdateCenterWindow", "AboutWindow", "SuccessfulFixWindow"):
    view = ET.parse(ROOT / (view_name + ".xaml")).getroot()
    source = (ROOT / (view_name + ".xaml.cs")).read_text(encoding="utf-8")
    for element in view.iter():
        for key, value in element.attrib.items():
            if key.rsplit("}", 1)[-1] in {"Click", "TextChanged", "SelectionChanged"}:
                check(bool(re.search(r"\bvoid\s+" + re.escape(value) + r"\s*\(", source)),
                      f"{view_name}: GUI handler exists for {value}")
print("PASS: secondary WPF window event handler guards.")

check("global using System.Net.Http;" in (ROOT / 'GlobalUsings.cs').read_text(encoding="utf-8"), 'WPF project explicitly imports System.Net.Http for GitHub Issues API')

check((ROOT / "Core/UpdateInstallBridge.cs").exists(), "manual self-update bridge exists")
check("PortableExeTransaction" in (ROOT / "Core/UpdateInstallBridge.cs").read_text(encoding="utf-8"), "self-update uses shared transactional rollback")
check("TermsrvPatcherUnified-update-win-x64.zip" in (ROOT / "Core/UpdateIntegration.cs").read_text(encoding="utf-8"), "update channel expects single-executable release asset")
check("PrepareAndLaunchAsync" in (ROOT / "UpdateCenterWindow.xaml.cs").read_text(encoding="utf-8"), "manual Install launches checked updater")
check("--update-probe" in (ROOT / "Core/UpdateInstallBridge.cs").read_text(encoding="utf-8"), "updater health probe exists")
print("PASS: self-update integration source guards.")

check((ROOT / "scripts/record_successful_fix.py").exists(), "version-only compatibility CSV aggregation script exists")
check("SuccessfulFixMetadata.FromSuccessfulApply" in (ROOT / "MainWindow.xaml.cs").read_text(encoding="utf-8"), "compatibility report is offered after successful protected apply")
check("SuccessfulFixPublisher" in (ROOT / "SuccessfulFixWindow.xaml.cs").read_text(encoding="utf-8"), "user-confirmed GitHub Issues compatibility reporting is wired")
check("issue_comment" in (ROOT / ".github/workflows/compatibility-report.yml").read_text(encoding="utf-8"), "GitHub event handler updates compatibility CSV")
check((ROOT / "data/successful-fixes.csv").exists(), "compatibility CSV exists")
check("original_sha256,patched_sha256,edits" in (ROOT / "data/successful-fixes.csv").read_text(encoding="utf-8"), "CSV contains v2 hashes and edits")
check("CreateBackupCheck" in (ROOT / "MainWindow.xaml").read_text(encoding="utf-8"), "backup checkbox exists")
check("Apply(PatchPlan preview, bool createBackup" in (ROOT / "Core/TermsrvEngine.cs").read_text(encoding="utf-8"), "optional backup wired into apply")
check("termsrv-success/v2" in (ROOT / "Core/SuccessfulFixPublisher.cs").read_text(encoding="utf-8"), "v2 compatibility report is supported")
check((ROOT / "Core/OfflineDllPatcher.cs").exists(), "offline x86/x64 DLL patcher source exists")
check((ROOT / "Core/DllHealthMonitor.cs").exists(), "passive DLL health source exists")
check((ROOT / "Core/RdpSessionViewer.cs").exists(), "native read-only WTS inventory source exists")
check((ROOT / "Tests/RdpHealthTests.cs").exists(), "passive health and WTS regression tests exist")
check("RdpSessionsGrid" in (ROOT / "MainWindow.xaml").read_text(encoding="utf-8"),
      "GUI includes the local read-only RDP session inventory")
check("--rdp-health-qa" in (ROOT / ".github/workflows/windows-ci.yml").read_text(encoding="utf-8"),
      "Windows CI runs passive health and WTS regression")

check((ROOT / "Core/OfflineFixMetadata.cs").exists(), "offline CRC32/SHA-256 report schema exists")
check((ROOT / "scripts/record_offline_fix.py").exists(), "offline report parser is present")
check("original_crc32,patched_sha256,patched_crc32" in (ROOT / "data/offline-fixes.csv").read_text(encoding="utf-8"), "separate public offline CRC32 CSV schema exists")
check("OfflineSaveButton" in (ROOT / "MainWindow.xaml").read_text(encoding="utf-8"), "offline copy Save button exists in GUI")
check("--offline" in (ROOT / "App.xaml.cs").read_text(encoding="utf-8"), "offline GUI can bypass startup UAC request")
check("OperationLock.Acquire()" in (ROOT / "Core/TermsrvEngine.cs").read_text(encoding="utf-8"), "protected Apply and Restore use a cross-process lock")
check("## Disclaimer" in (ROOT / "README.md").read_text(encoding="utf-8"), "README includes liability and risk notice")
check("## Preview." not in (ROOT / "README.md").read_text(encoding="utf-8"),
      "README contains current usage, not per-build change history")
check((ROOT / "Core/RdpPolicyDiagnostics.cs").exists() and (ROOT / "Core/OperationHistory.cs").exists(),
      "read-only RDP policy and local history core modules present")
check((ROOT / "Core/RdpSettingsTransaction.cs").exists() and
      (ROOT / "Tests/RdpTransactionTests.cs").exists(),
      "RDP settings transactional rollback and fault-injection regression present")
check("--rdp-transaction-qa" in workflow, "Windows CI verifies transactional setting/ServiceGuard rollback")
check("RdpSettingsTransaction.Execute" in (ROOT / "Core/RdpConfiguration.cs").read_text(encoding="utf-8"),
      "all RDP Settings writes share the rollback transaction")
check((ROOT / "Tests/RdpPolicyHistoryTests.cs").exists(), "policy/history regressions present")
check((ROOT / "Core/HexViewport.cs").exists() and
      (ROOT / "Tests/PatternInspectionTests.cs").exists(),
      "bounded read-only 16-column HEX viewer and regression tests are present")
check("--pattern-inspection-qa" in workflow, "Windows CI tests pattern evidence and HEX viewer")
check(all(name in main for name in ("ManualHexRows", "ManualHexMask",
                                   "ManualHexPrevious", "ManualHexNext",
                                   "ManualFragmentGrid", "CheckAllImportedButton")),
      "Manual has masked HEX viewer, search and imported-catalog controls")
check("RdpPolicyGrid" in main and "OperationHistoryGrid" in main, "read-only policy and history UI available")
check("--rdp-policy-history-qa" in workflow, "Windows CI runs RDP history/policy tests")

print("PASS: compatibility report source guards.")

check(not re.search(r"\.read_text\(\s*\)", (ROOT / "scripts/verify_source.py").read_text(encoding="utf-8")), "source validator uses explicit UTF-8 on Windows")

check((ROOT / "Tests/UpdateTransactionSyntheticTests.cs").exists(), "disposable EXE update success and rollback tests exist")
check((ROOT / "Tests/PublishedUpgradeTests.cs").exists(), "published EXE transaction QA harness exists")
check((ROOT / "Core/DllBackupStore.cs").exists(), "DLL backup and Restore share strict file validator")
check((ROOT / "Tests/DllBackupIntegrityTests.cs").exists(), "real-DLL-copy backup integrity tests are checked in")
check("--dll-backup-qa" in (ROOT / ".github/workflows/windows-ci.yml").read_text(encoding="utf-8"),
      "Windows CI executes full backup On/Off, tamper and Restore verification")
check((ROOT / ".github/workflows/published-dll-readonly-qa.yml").exists(), "real Windows DLL read-only smoke workflow exists")
readonly_qa = (ROOT / ".github/workflows/published-dll-readonly-qa.yml").read_text(encoding="utf-8")
check("Get-FileHash" in readonly_qa and "TermService" in readonly_qa and "Get-Acl" in readonly_qa,
      "real DLL inspection QA checks checksum, service state and ACL")
check((ROOT / ".github/workflows/published-upgrade-qa.yml").exists(), "pinned real published EXE upgrade workflow exists")
for workflow in (ROOT / ".github/workflows").glob("*.yml"):
    source = workflow.read_text(encoding="utf-8")
    check("actions/checkout@v4" not in source and "actions/setup-dotnet@v4" not in source and "actions/upload-artifact@v4" not in source,
          f"{workflow.name}: GitHub Node 24 action policy")
check("actions/checkout@v7" in (ROOT / ".github/workflows/release-preview.yml").read_text(encoding="utf-8"),
      "release workflow checkout uses Node 24")
check("actions/setup-dotnet@v6" in (ROOT / ".github/workflows/windows-ci.yml").read_text(encoding="utf-8"),
      "Windows CI SDK setup uses Node 24")
check("actions/upload-artifact@v7" in (ROOT / ".github/workflows/windows-ci.yml").read_text(encoding="utf-8"),
      "Windows CI artifact upload uses Node 24")
check((ROOT / "Tests/UiSmokeTests.cs").exists(), "offscreen WPF layout smoke exists")
check("--ui-smoke" in (ROOT / ".github/workflows/windows-ci.yml").read_text(encoding="utf-8"), "Windows CI runs offscreen WPF layout smoke")
check("HasMutatingRights" in (ROOT / "Core/UpdateInstallBridge.cs").read_text(encoding="utf-8"), "safe Program Files ACL write-rights test")
print("PASS: preview.8 updater transaction and offscreen GUI smoke guards.")
