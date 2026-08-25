from __future__ import annotations

import re
from pathlib import Path

import pytest
from dcc_mcp_core import yaml_loads

RELEASE_PLEASE_ACTION = "googleapis/release-please-action@45996ed1f6d02564a971a2fa1b5860e934307cf7"
CHECKOUT_ACTION = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
SETUP_PYTHON_ACTION = "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"
UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD_ARTIFACT_ACTION = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
PYPI_PUBLISH_ACTION = "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"


def _release_workflow_contents() -> str:
    workflow_path = Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"
    return workflow_path.read_text(encoding="utf-8")


def _parsed_workflow(contents: str) -> dict:
    workflow = yaml_loads(contents)
    assert isinstance(workflow, dict)
    return workflow


def _unique_named_step(job: dict, name: str) -> dict:
    matches = [step for step in job["steps"] if step.get("name") == name]
    assert len(matches) == 1
    return matches[0]


def _parsed_action_refs(job: dict) -> list[str]:
    return [step["uses"] for step in job["steps"] if "uses" in step]


def _strip_shell_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if quote:
            if character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _normalized_shell_lines(run: str) -> tuple[str, ...]:
    executable_lines = []
    for line in run.splitlines():
        executable = _strip_shell_comment(line).strip()
        if executable:
            executable_lines.append(re.sub(r"\s+", " ", executable))
    return tuple(executable_lines)


def _assert_actions_and_permissions_contract(contents: str) -> None:
    workflow = _parsed_workflow(contents)
    jobs = workflow["jobs"]

    assert set(jobs) == {
        "release-please",
        "build-release-artifacts",
        "publish",
        "attach-release-artifacts",
    }
    assert workflow["permissions"] == {}
    assert jobs["release-please"]["permissions"] == {
        "contents": "write",
        "pull-requests": "write",
    }
    assert jobs["build-release-artifacts"]["permissions"] == {"contents": "read"}
    assert jobs["publish"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert jobs["attach-release-artifacts"]["permissions"] == {"contents": "write"}
    assert all(
        not (
            job.get("permissions", {}).get("contents") == "write"
            and job.get("permissions", {}).get("id-token") == "write"
        )
        for job in jobs.values()
    )

    assert jobs["release-please"]["outputs"] == {
        "release_created": "${{ steps.release.outputs.release_created }}",
        "tag_name": "${{ steps.release.outputs.tag_name }}",
    }
    assert jobs["build-release-artifacts"]["needs"] == "release-please"
    assert jobs["publish"]["needs"] == ["release-please", "build-release-artifacts"]
    assert jobs["attach-release-artifacts"]["needs"] == [
        "release-please",
        "build-release-artifacts",
    ]
    release_condition = "${{ needs.release-please.outputs.release_created == 'true' }}"
    assert all(
        jobs[job_name]["if"] == release_condition
        for job_name in ("build-release-artifacts", "publish", "attach-release-artifacts")
    )

    assert _parsed_action_refs(jobs["release-please"]) == [RELEASE_PLEASE_ACTION]
    assert _parsed_action_refs(jobs["build-release-artifacts"]) == [
        CHECKOUT_ACTION,
        SETUP_PYTHON_ACTION,
        UPLOAD_ARTIFACT_ACTION,
    ]
    assert _parsed_action_refs(jobs["publish"]) == [
        DOWNLOAD_ARTIFACT_ACTION,
        PYPI_PUBLISH_ACTION,
    ]
    assert _parsed_action_refs(jobs["attach-release-artifacts"]) == [DOWNLOAD_ARTIFACT_ACTION]
    action_refs = [action for job in jobs.values() for action in _parsed_action_refs(job)]
    assert action_refs
    assert all(re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", action) for action in action_refs)


def _assert_artifact_handoff_contract(contents: str) -> None:
    workflow = _parsed_workflow(contents)
    jobs = workflow["jobs"]

    build = jobs["build-release-artifacts"]
    publish = jobs["publish"]
    attach = jobs["attach-release-artifacts"]

    build_step = _unique_named_step(build, "Build release distributions")
    upload = _unique_named_step(build, "Upload release distributions")
    publish_download = _unique_named_step(publish, "Download release distributions")
    pypi_publish = _unique_named_step(publish, "Publish release distributions to PyPI")
    attach_download = _unique_named_step(attach, "Download release distributions")
    attach_step = _unique_named_step(attach, "Attach distributions to exact GitHub Release")

    assert _normalized_shell_lines(build_step["run"]) == (
        "python -m pip install build && python -m build",
    )
    all_runs = [step.get("run", "") for job in jobs.values() for step in job.get("steps", [])]
    assert sum("python -m build" in " ".join(_normalized_shell_lines(run)) for run in all_runs) == 1
    assert upload["uses"] == UPLOAD_ARTIFACT_ACTION
    assert upload["with"] == {
        "name": "release-distributions",
        "path": "dist/",
        "if-no-files-found": "error",
    }
    assert publish_download["uses"] == DOWNLOAD_ARTIFACT_ACTION
    assert publish_download["with"] == {
        "name": "release-distributions",
        "path": "dist/",
    }
    assert pypi_publish["uses"] == PYPI_PUBLISH_ACTION
    assert attach_download["uses"] == DOWNLOAD_ARTIFACT_ACTION
    assert attach_download["with"] == publish_download["with"]

    assert build["steps"].index(build_step) < build["steps"].index(upload)
    assert publish["steps"].index(publish_download) < publish["steps"].index(pypi_publish)
    assert attach["steps"].index(attach_download) < attach["steps"].index(attach_step)

    assert attach_step["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "GH_REPO": "${{ github.repository }}",
        "RELEASE_TAG": "${{ needs.release-please.outputs.tag_name }}",
        "EXPECTED_SHA": "${{ github.sha }}",
    }
    assert _normalized_shell_lines(attach_step["run"]) == (
        "set -euo pipefail",
        'test -n "${RELEASE_TAG:-}"',
        '''tag_target="$(gh api "repos/$GH_REPO/git/ref/tags/$RELEASE_TAG" --jq '.object.type + ":" + .object.sha')"''',
        'test "$tag_target" = "commit:$EXPECTED_SHA"',
        '''release_target="$(gh release view "$RELEASE_TAG" --repo "$GH_REPO" --json tagName,targetCommitish --jq '.tagName + ":" + .targetCommitish')"''',
        'test "$release_target" = "$RELEASE_TAG:$EXPECTED_SHA"',
        r"mapfile -t release_files < <(find dist -maxdepth 1 -type f \( -name '*.whl' -o -name '*.tar.gz' \) -print | LC_ALL=C sort)",
        'test "${#release_files[@]}" -eq 2',
        r"""test "$(printf '%s\n' "${release_files[@]}" | grep -Ec '\.whl$')" -eq 1""",
        r"""test "$(printf '%s\n' "${release_files[@]}" | grep -Ec '\.tar\.gz$')" -eq 1""",
        """mapfile -t existing_assets < <(gh release view "$RELEASE_TAG" --repo "$GH_REPO" --json assets --jq '.assets[].name')""",
        'test "${#existing_assets[@]}" -eq 0',
        'gh release upload "$RELEASE_TAG" --repo "$GH_REPO" --clobber=false "${release_files[@]}"',
    )
    assert "v0.7.0" not in contents


def _assert_release_workflow_contract(contents: str) -> None:
    _assert_actions_and_permissions_contract(contents)
    _assert_artifact_handoff_contract(contents)


def _replace_once(contents: str, original: str, replacement: str) -> str:
    assert contents.count(original) == 1
    return contents.replace(original, replacement, 1)


def test_release_actions_are_commit_pinned_and_jobs_have_minimal_permissions():
    _assert_actions_and_permissions_contract(_release_workflow_contents())


def test_release_builds_once_and_hands_the_same_artifact_to_both_destinations():
    _assert_artifact_handoff_contract(_release_workflow_contents())


def test_release_contract_rejects_commented_exact_tag_guard():
    contents = _replace_once(
        _release_workflow_contents(),
        '          test "$tag_target" = "commit:$EXPECTED_SHA"',
        '          # test "$tag_target" = "commit:$EXPECTED_SHA"',
    )

    with pytest.raises(AssertionError):
        _assert_release_workflow_contract(contents)


def test_release_contract_rejects_harmless_pypi_publisher_replacement():
    publisher = (
        "      - name: Publish release distributions to PyPI\n"
        "        uses: pypa/gh-action-pypi-publish@"
        "dc37677b2e1c63e2034f94d8a5b11f265b73ba33 # release/v1"
    )
    contents = _replace_once(
        _release_workflow_contents(),
        publisher,
        "      - name: Publish release distributions to PyPI\n"
        '        run: echo "publisher disabled"',
    )

    with pytest.raises(AssertionError):
        _assert_release_workflow_contract(contents)


def test_release_contract_rejects_commented_zero_existing_assets_guard():
    contents = _replace_once(
        _release_workflow_contents(),
        '          test "${#existing_assets[@]}" -eq 0',
        '          # test "${#existing_assets[@]}" -eq 0',
    )

    with pytest.raises(AssertionError):
        _assert_release_workflow_contract(contents)


def test_release_contract_rejects_duplicate_named_step_decoy():
    attach_name = "      - name: Attach distributions to exact GitHub Release"
    contents = _replace_once(
        _release_workflow_contents(),
        attach_name,
        '      - name: Download release distributions\n        run: echo "decoy"\n' + attach_name,
    )

    with pytest.raises(AssertionError):
        _assert_release_workflow_contract(contents)
