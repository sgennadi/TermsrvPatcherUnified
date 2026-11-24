#!/usr/bin/env python3
"""Promote only the frozen, independently verified 1.0.8 signed QA package.

No build, signing key access, system DLL changes or automatic acceptance.
The owner must record genuine VM acceptance before a protected manual run.
A failed draft verification never publishes the draft.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from verify_update_package import validate, validate_full

ROOT = Path(__file__).resolve().parents[1]
REPO = "sgennadi/TermsrvPatcherUnified"
OWNER = "sgennadi"
TAG = "v1.0.8"
CANDIDATE = "f6b19322599db57d80fa68e3903fdb498e33c59f"
ARTIFACT_ID = 14893070061
ARTIFACT_RUN = 45332770728
ARTIFACT_SIZE = 122728972
ARTIFACT_SHA = "310b026f147b06c771381eb94df59fe278b16fb20910cac35c669e40756c6d00"
EXE = "TermsrvPatcherUnified.exe"
EXE_SHA = "acbcebe071e8ccb2b995127bdf72fb15378480a60552115a862443ac61ae4793"
PIN = "a185f90644de1c2c5ea2ae2e923eb08f93ebde4b06cc8273679a168dfa5535b9"
FULL = "TermsrvPatcherUnified-win-x64.zip"
UPDATE = "TermsrvPatcherUnified-update-win-x64.zip"
MANIFEST = "SHA256SUMS.txt"
# Independently hashed exact bytes of the retained artifact, not mutable URLs.
ASSETS = {
    FULL: (61371572, "f564215caf6cc8600fdf0c485b8539cbf3018eea18b45802a8d8f8439dd8ae70"),
    UPDATE: (61356719, "19ecd327125e7dae0fff51860780d6d14e421d6bb0292df8cff0bf8663ea0680"),
    MANIFEST: (209, "a6ce5909d05c776d1dc760899cf31caaa43533f106233fbf7f55d6ed2d611b2b"),
}
RUNS = {
    45332709646: ("Windows build and safety tests", "push"),
    45332709652: ("CodeQL security analysis", "push"),
    45332710387: ("Self-signed Authenticode verifier regression (no secrets)", "push"),
    45332709643: ("Signing configuration readiness (no key access)", "push"),
    ARTIFACT_RUN: ("Protected signing smoke test (no release)", "workflow_dispatch"),
}
ACCEPTANCE = [
    "Stable 1.0.8 VM acceptance: PASS",
    "Commit: " + CANDIDATE,
    "Artifact: " + str(ARTIFACT_ID),
    "Recovery verification: PASS",
]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def gh(*args):
    result = subprocess.run(["gh", *args], text=True, encoding="utf-8",
                            capture_output=True, check=False)
    require(result.returncode == 0, "GitHub command failed: " + " ".join(args[:3]))
    return result.stdout

def api(endpoint):
    return json.loads(gh("api", endpoint))

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def check_acceptance(comment):
    user = comment.get("user") or {}
    require(comment.get("issue_url") ==
            "https://api.github.com/repos/" + REPO + "/issues/82",
            "Acceptance must be recorded on issue #82.")
    require(user.get("login") == OWNER and user.get("type") == "User"
            and comment.get("author_association") == "OWNER"
            and comment.get("performed_via_github_app") is None,
            "Acceptance must be attested by the repository owner, not a bot.")
    lines = (comment.get("body") or "").strip().splitlines()
    require(lines[:4] == ACCEPTANCE and len(lines) >= 5
            and lines[4].startswith("Evidence: ")
            and len("\n".join(lines[4:]).strip()) >= 35,
            "Missing exact candidate-bound acceptance and recovery evidence.")
    require(str(comment.get("created_at", "")) >= "2026-11-24T05:24:01Z",
            "Acceptance predates the retained candidate.")

def check_run(run, run_id, name, event):
    require(run.get("id") == run_id and run.get("name") == name
            and run.get("event") == event and run.get("head_branch") == "main"
            and run.get("head_sha") == CANDIDATE
            and run.get("status") == "completed" and run.get("conclusion") == "success",
            "Required candidate workflow has not passed: " + name)

def check_artifact(artifact):
    run = artifact.get("workflow_run") or {}
    require(artifact.get("id") == ARTIFACT_ID
            and artifact.get("name") == "signed-qa-" + CANDIDATE
            and artifact.get("expired") is False
            and artifact.get("size_in_bytes") == ARTIFACT_SIZE
            and artifact.get("digest") == "sha256:" + ARTIFACT_SHA
            and run.get("id") == ARTIFACT_RUN
            and run.get("head_sha") == CANDIDATE and run.get("head_branch") == "main",
            "The exact signed QA artifact is unavailable or changed.")

def matching_releases():
    pages = json.loads(gh("api", "repos/" + REPO + "/releases?per_page=100",
                          "--paginate", "--slurp"))
    return [r for page in pages for r in page if r.get("tag_name") == TAG]

def tag_refs():
    refs = api("repos/" + REPO + "/git/matching-refs/tags/" + TAG)
    return [r for r in refs if r.get("ref") == "refs/tags/" + TAG]

def check_tag(required):
    refs = tag_refs()
    require(len(refs) <= 1, "Ambiguous target tag.")
    if required or refs:
        require(len(refs) == 1 and refs[0].get("object") == {
            "type": "commit", "sha": CANDIDATE,
            "url": "https://api.github.com/repos/" + REPO + "/git/commits/" + CANDIDATE
        }, "Tag does not point to the exact verified candidate.")

def check_gates():
    require(os.environ.get("GITHUB_REPOSITORY") == REPO
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_ACTOR") == OWNER
            and os.environ.get("GITHUB_TRIGGERING_ACTOR") == OWNER,
            "Protected promotion requires an owner-triggered main workflow.")
    comment_id = os.environ.get("TPU_ACCEPTANCE_COMMENT_ID", "")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", comment_id) is not None,
            "A real acceptance comment ID is required.")
    check_acceptance(api("repos/" + REPO + "/issues/comments/" + comment_id))
    for run_id, (name, event) in RUNS.items():
        check_run(api("repos/" + REPO + "/actions/runs/" + str(run_id)),
                  run_id, name, event)
    check_artifact(api("repos/" + REPO + "/actions/artifacts/" + str(ARTIFACT_ID)))
    latest = api("repos/" + REPO + "/releases/latest")
    require(latest.get("tag_name") == "v1.0.7"
            and not latest.get("draft") and not latest.get("prerelease"),
            "Latest Stable changed; do not overwrite or downgrade.")
    require(not matching_releases() and not tag_refs(),
            "A 1.0.8 release/draft or tag already exists; inspect it manually.")

def download_artifact(path):
    request = urllib.request.Request(
        "https://api.github.com/repos/" + REPO + "/actions/artifacts/"
        + str(ARTIFACT_ID) + "/zip",
        headers={"Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "TPU-verified-stable-promotion"})
    # The bearer token belongs only to the API request, never the redirected
    # object-storage request. urllib does not copy unredirected headers.
    request.add_unredirected_header("Authorization", "Bearer " + os.environ["GH_TOKEN"])
    with urllib.request.urlopen(request, timeout=120) as response, path.open("xb") as output:
        require(response.geturl().startswith("https://"), "Insecure artifact redirect.")
        total = 0
        while block := response.read(1024 * 1024):
            total += len(block)
            require(total <= ARTIFACT_SIZE, "Unexpected artifact size.")
            output.write(block)
    require(path.stat().st_size == ARTIFACT_SIZE and digest(path) == ARTIFACT_SHA,
            "Outer artifact checksum mismatch.")

def check_files(directory):
    for name, (size, sha) in ASSETS.items():
        path = directory / name
        require(path.is_file() and not path.is_symlink()
                and path.stat().st_size == size and digest(path) == sha,
                "Exact candidate asset mismatch: " + name)
    entries = (directory / MANIFEST).read_text(encoding="ascii").splitlines()
    require(len(entries) == 2 and set(entries) == {
        ASSETS[name][1] + "  " + name for name in (FULL, UPDATE)
    }, "Checksum manifest mismatch.")
    full = validate_full(directory / FULL)
    update = validate(directory / UPDATE)
    require(full == update and full[1] == EXE_SHA,
            "Archive executable bytes do not match the verified candidate.")

def prepare():
    check_gates()
    require(all(not (ROOT / name).exists() for name in ASSETS)
            and not (ROOT / "publish").exists(), "Expected a clean checkout.")
    with tempfile.TemporaryDirectory(prefix="tpu-verified-108-") as temporary:
        archive_path = Path(temporary) / "artifact.zip"
        download_artifact(archive_path)
        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            require(len(entries) == 3 and {entry.filename for entry in entries} == set(ASSETS),
                    "Artifact must contain exactly three approved assets.")
            for entry in entries:
                require(not entry.is_dir() and not entry.flag_bits & 1
                        and (entry.external_attr >> 16) & 0xF000 in (0, 0x8000)
                        and entry.file_size == ASSETS[entry.filename][0],
                        "Unexpected artifact entry.")
                with archive.open(entry) as source, (ROOT / entry.filename).open("xb") as target:
                    shutil.copyfileobj(source, target)
    check_files(ROOT)
    # The existing Windows archive verifier compares both ZIPs to this exact
    # EXE and verifies the pinned signer. Never execute the candidate here.
    (ROOT / "publish").mkdir()
    with zipfile.ZipFile(ROOT / UPDATE) as archive:
        with archive.open(EXE) as source, (ROOT / "publish" / EXE).open("xb") as target:
            shutil.copyfileobj(source, target)
    print("PASS: exact signed candidate extracted; approval and prior CI verified.")

def check_release(release, draft):
    require(release.get("tag_name") == TAG
            and release.get("target_commitish") == CANDIDATE
            and release.get("draft") is draft and release.get("prerelease") is False,
            "Release metadata does not match the exact candidate.")
    assets = release.get("assets") or []
    require(len(assets) == 3 and {a.get("name") for a in assets} == set(ASSETS),
            "Server-side release asset set mismatch.")
    for asset in assets:
        size, sha = ASSETS[asset["name"]]
        require(asset.get("state") == "uploaded" and asset.get("size") == size
                and asset.get("digest") == "sha256:" + sha,
                "Server-side asset digest mismatch: " + asset["name"])

def publish():
    # Recheck the exact bytes and acceptance immediately before any write.
    # This does not fabricate VM test evidence or authorize unsigned builds.
    check_gates()
    check_files(ROOT)
    require(digest(ROOT / "publish" / EXE) == EXE_SHA
            and os.environ.get("TPU_SIGNER_SPKI_SHA256", "").lower() == PIN,
            "Verified executable or independently configured signing pin changed.")
    notes = (
        "1. Pinned Authenticode verification of installed and replacement EXEs.\n"
        "2. Full SemVer identity in updates, GUI and diagnostic reports.\n"
        "3. Preview-to-Stable ordering and downgrade/replay rejection.\n"
        "4. Explicit administrator approval, protected staging, backup and rollback.\n"
        "5. Verified signed ZIP contents and SHA-256 manifest.\n\n"
        "Windows x64, .NET 10, self-contained. Legacy unsigned installations require "
        "a manually verified transition to a signed build. A self-signed certificate "
        "may display Unknown Publisher. No unattended EXE installation is supported.\n\n"
        "Automated checks and owner-recorded acceptance: "
        "https://github.com/sgennadi/TermsrvPatcherUnified/issues/82\n"
        "Signing is not Microsoft endorsement or proof of licensing compatibility.\n"
    )
    with tempfile.TemporaryDirectory(prefix="tpu-release-notes-") as temporary:
        note_path = Path(temporary) / "notes.txt"
        note_path.write_text(notes, encoding="utf-8")
        gh("release", "create", TAG, *(str(ROOT / name) for name in ASSETS),
           "--repo", REPO, "--draft", "--target", CANDIDATE,
           "--title", "TermsrvPatcherUnified 1.0.8 (Stable)",
           "--notes-file", str(note_path))
    drafts = matching_releases()
    require(len(drafts) == 1, "Missing or ambiguous draft release.")
    check_release(drafts[0], draft=True)
    check_tag(required=False)
    # The draft remains unpublished unless all three uploaded assets match.
    gh("release", "edit", TAG, "--repo", REPO, "--draft=false", "--latest")
    releases = matching_releases()
    require(len(releases) == 1, "Missing or ambiguous published release.")
    check_release(releases[0], draft=False)
    check_tag(required=True)
    latest = api("repos/" + REPO + "/releases/latest")
    require(latest.get("id") == releases[0].get("id"), "Release is not Latest Stable.")
    print("PASS: signed 1.0.8 published; exact server-side asset digests and tag verified.")

def selftest():
    comment = {
        "issue_url": "https://api.github.com/repos/" + REPO + "/issues/82",
        "user": {"login": OWNER, "type": "User"}, "author_association": "OWNER",
        "performed_via_github_app": None, "created_at": "2026-11-24T06:00:00Z",
        "body": "\n".join(ACCEPTANCE + ["Evidence: synthetic unit-test fixture, not real acceptance."]),
    }
    check_acceptance(comment)
    def rejects(call):
        try:
            call()
        except ValueError:
            return
        raise AssertionError("Invalid promotion evidence accepted.")
    for key, value in (
        ("issue_url", "https://api.github.com/repos/other/repo/issues/82"),
        ("user", {"login": "other", "type": "User"}),
        ("performed_via_github_app", {"id": 123}),
        ("author_association", "CONTRIBUTOR"),
        ("body", "PASS"), ("created_at", "2026-11-23T00:00:00Z"),
    ):
        bad = copy.deepcopy(comment)
        bad[key] = value
        rejects(lambda: check_acceptance(bad))
    bad = copy.deepcopy(comment)
    bad["body"] = bad["body"].replace(CANDIDATE, "0" * 40)
    rejects(lambda: check_acceptance(bad))
    artifact = {"id": ARTIFACT_ID, "name": "signed-qa-" + CANDIDATE,
                "expired": False, "size_in_bytes": ARTIFACT_SIZE,
                "digest": "sha256:" + ARTIFACT_SHA,
                "workflow_run": {"id": ARTIFACT_RUN, "head_sha": CANDIDATE,
                                 "head_branch": "main"}}
    check_artifact(artifact)
    for key, value in (("expired", True), ("digest", "sha256:" + "0" * 64),
                       ("id", 1), ("size_in_bytes", 1)):
        bad = copy.deepcopy(artifact)
        bad[key] = value
        rejects(lambda: check_artifact(bad))
    run_id, (name, event) = next(iter(RUNS.items()))
    run = {"id": run_id, "name": name, "event": event, "head_branch": "main",
           "head_sha": CANDIDATE, "status": "completed", "conclusion": "success"}
    check_run(run, run_id, name, event)
    for key, value in (("head_sha", "0" * 40), ("conclusion", "failure"),
                       ("head_branch", "other"), ("event", "pull_request")):
        bad = copy.deepcopy(run)
        bad[key] = value
        rejects(lambda: check_run(bad, run_id, name, event))
    release = {
        "tag_name": TAG, "target_commitish": CANDIDATE, "draft": True,
        "prerelease": False,
        "assets": [{"name": n, "size": s, "digest": "sha256:" + h, "state": "uploaded"}
                   for n, (s, h) in ASSETS.items()],
    }
    check_release(release, draft=True)
    for key, value in (("draft", False), ("prerelease", True),
                       ("target_commitish", "0" * 40), ("assets", release["assets"][:2])):
        bad = copy.deepcopy(release)
        bad[key] = value
        rejects(lambda: check_release(bad, draft=True))
    bad = copy.deepcopy(release)
    bad["assets"][0]["digest"] = "sha256:" + "0" * 64
    rejects(lambda: check_release(bad, draft=True))
    print("PASS: offline promotion gates reject wrong owner, acceptance, run, artifact, draft or digest.")

if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["--self-test"]:
            selftest()
        elif sys.argv[1:] == ["--prepare"]:
            prepare()
        elif sys.argv[1:] == ["--publish"]:
            publish()
        else:
            raise ValueError("Use --self-test, --prepare, or --publish.")
    except Exception as error:
        # No secret, redirected storage URL, or raw API response in the log.
        print("Promotion failed closed: " + (str(error) if isinstance(error, ValueError)
                                              else type(error).__name__), file=sys.stderr)
        raise SystemExit(1)
