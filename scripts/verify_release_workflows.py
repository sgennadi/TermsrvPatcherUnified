#!/usr/bin/env python3
"""Read-only release workflow structure and fail-closed policy checks.

Release workflows are intentionally DISABLED. Parse with PyYAML BaseLoader to
avoid YAML 1.1's implicit conversion of the GitHub Actions 'on' key to boolean.
This script must never access signing secrets or publish a release.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = {
    "STABLE": ".github/workflows/release-stable.yml",
    "PREVIEW": ".github/workflows/release-preview.yml",
}

for channel, filename in WORKFLOWS.items():
    source = (ROOT / filename).read_text(encoding="utf-8")
    workflow = yaml.load(source, Loader=yaml.BaseLoader)
    assert isinstance(workflow, dict), f"{filename}: root mapping required"
    assert workflow.get("on") == {"push": {"branches": ["main"]}}, (
        f"{filename}: main push must be the only trigger"
    )
    assert workflow.get("permissions", {}).get("contents") == "read", (
        f"{filename}: top-level permissions must remain read-only"
    )
    jobs = workflow.get("jobs")
    jobname = "publish-" + channel.lower()
    assert isinstance(jobs, dict) and list(jobs) == [jobname], (
        f"{filename}: exactly one release job is supported"
    )
    job = jobs[jobname]
    assert job.get("if") == "false", f"{filename}: automatic release publishing must stay disabled"
    assert job.get("environment") == "release-signing", (
        f"{filename}: protected signing environment is mandatory"
    )
    assert job.get("permissions", {}).get("contents") == "write", (
        f"{filename}: GitHub release writing must be scoped to the disabled job"
    )
    steps = job["steps"]
    assert isinstance(steps, list) and steps
    names = [step.get("name") for step in steps if "name" in step]
    assert len(names) == len(set(names)), f"{filename}: duplicate named workflow steps"
    assert all(set(step).issubset({"uses", "with", "name", "if", "shell", "run", "env"}) for step in steps), (
        f"{filename}: unknown step properties"
    )
    def step_index(needle: str) -> int:
        matches = [i for i, step in enumerate(steps) if needle in step.get("name", "")]
        assert len(matches) == 1, f"{filename}: expected one '{needle}' step"
        return matches[0]

    version = step_index("Validate explicit")
    signed = step_index("Sign release EXE")
    packed = step_index("Package exact two-file")
    archived = step_index("Verify exact signed EXE")
    published = step_index("Publish " + ("Stable" if channel == "STABLE" else "signed Preview") + " release")
    checked = step_index("Verify published updater release assets")
    assert version < signed < packed < archived < published < checked, (
        f"{filename}: signing / packaging / verification / publishing sequence changed"
    )
    assert steps[signed].get("run", "").strip() == "./scripts/sign_release_exe.ps1"
    assert steps[archived].get("run", "").strip() == "./scripts/verify_signed_release_archives.ps1"
    for step in (steps[signed], steps[archived], steps[published]):
        assert step.get("if") == f"env.PUBLISH_{channel} == 'true'", (
            f"{filename}: mandatory release gate missing"
        )
    sign_env = steps[signed]["env"]
    assert sign_env.get("TPU_PFX_BASE64") == "${{ secrets.TPU_SIGNING_PFX_BASE64 }}"
    assert sign_env.get("TPU_PFX_PASSWORD") == "${{ secrets.TPU_SIGNING_PFX_PASSWORD }}"
    assert sign_env.get("TPU_PIN") == "${{ vars.TPU_SIGNER_SPKI_SHA256 }}"
    assert steps[archived]["env"].get("TPU_SIGNER_SPKI_SHA256") == (
        "${{ vars.TPU_SIGNER_SPKI_SHA256 }}"
    )
    assert "gh release create " in steps[published].get("run", "")
    assert source.count("gh release create ") == 1, f"{filename}: multiple publish commands"
    if channel == "PREVIEW":
        # Preserve the existing notes-only edit. Do not replace archives or
        # retroactively represent unsigned artifacts as signed.
        assert source.count("gh release edit ") == 1, (
            f"{filename}: expected one notes-only Preview edit"
        )
        assert "gh release edit $tag --repo $env:GITHUB_REPOSITORY --notes-file release-notes.txt" in source, (
            f"{filename}: Preview edit must update notes only"
        )
        assert "published assets retained unchanged" in source
        assert "published binaries and signature status remain unchanged" in source
        assert "New release: the published EXE and both ZIPs passed pinned Authenticode verification." in source
    else:
        assert "gh release edit " not in source, (
            f"{filename}: Stable release must not modify an existing publication"
        )
    assert "unsigned Windows x64" not in source, f"{filename}: stale unsigned release notes"
    assert "Version = GetAssemblyVersion()" in source and (
        "typeof(UpdateIntegration).Assembly.GetName().Version" in source
    ), f"{filename}: assembly-derived updater version verification missing"
    assert "RELEASE_ASSEMBLY_VERSION" in source
    probe_steps = [step for step in steps if "Read-only EXE and offline update probe smoke tests" in step.get("name", "")]
    assert len(probe_steps) == 1, f"{filename}: exactly one real EXE startup health probe"
    expected_arg = "RELEASE_VERSION" if channel == "PREVIEW" else "RELEASE_ASSEMBLY_VERSION"
    assert "'--update-probe', $env:" + expected_arg in probe_steps[0].get("run", ""), (
        f"{filename}: startup probe must use actual {channel} EXE release identity"
    )
    assert source.count("scripts/sign_release_exe.ps1") == 1
    assert source.count("scripts/verify_signed_release_archives.ps1") == 1
    print(f"PASS: {channel} publisher parses; remains disabled with pinned signing and ordered gates")

for script in ("scripts/sign_release_exe.ps1", "scripts/verify_signed_release_archives.ps1"):
    assert (ROOT / script).is_file(), f"Missing security gate script: {script}"
print("PASS: both release verification scripts are present; no release was published")
