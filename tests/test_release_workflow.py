from __future__ import annotations

import re
from pathlib import Path

from dcc_mcp_core import yaml_loads


def _release_workflow() -> tuple[str, dict]:
    workflow_path = Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"
    contents = workflow_path.read_text(encoding="utf-8")
    return contents, yaml_loads(contents)


def test_release_actions_are_commit_pinned_and_jobs_have_minimal_permissions():
    contents, workflow = _release_workflow()

    action_refs = re.findall(r"\buses:\s*([^\s#]+)", contents)
    assert action_refs
    assert all(re.search(r"@[0-9a-f]{40}$", action) for action in action_refs)
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["release-please"]["permissions"] == {
        "contents": "write",
        "pull-requests": "write",
    }
    assert workflow["jobs"]["build-release-artifacts"]["permissions"] == {"contents": "read"}
    assert workflow["jobs"]["publish"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert workflow["jobs"]["attach-release-artifacts"]["permissions"] == {"contents": "write"}
    assert all(
        not (
            job.get("permissions", {}).get("contents") == "write"
            and job.get("permissions", {}).get("id-token") == "write"
        )
        for job in workflow["jobs"].values()
    )


def test_release_builds_once_and_hands_the_same_artifact_to_both_destinations():
    contents, workflow = _release_workflow()
    jobs = workflow["jobs"]

    assert jobs["release-please"]["outputs"]["tag_name"] == "${{ steps.release.outputs.tag_name }}"

    build = jobs["build-release-artifacts"]
    publish = jobs["publish"]
    attach = jobs["attach-release-artifacts"]
    assert build["needs"] == "release-please"
    assert publish["needs"] == ["release-please", "build-release-artifacts"]
    assert attach["needs"] == ["release-please", "build-release-artifacts"]

    build_runs = [step.get("run", "") for step in build["steps"]]
    all_runs = [step.get("run", "") for job in jobs.values() for step in job.get("steps", [])]
    assert sum("python -m build" in run for run in build_runs) == 1
    assert sum("python -m build" in run for run in all_runs) == 1

    upload = next(
        step for step in build["steps"] if step.get("name") == "Upload release distributions"
    )
    build_step = next(
        step for step in build["steps"] if step.get("name") == "Build release distributions"
    )
    publish_download = next(
        step for step in publish["steps"] if step.get("name") == "Download release distributions"
    )
    attach_download = next(
        step for step in attach["steps"] if step.get("name") == "Download release distributions"
    )
    assert upload["with"] == {
        "name": "release-distributions",
        "path": "dist/",
        "if-no-files-found": "error",
    }
    assert publish_download["with"] == {
        "name": "release-distributions",
        "path": "dist/",
    }
    assert attach_download["with"] == publish_download["with"]

    assert build["steps"].index(build_step) < build["steps"].index(upload)
    assert not any("checkout" in step.get("uses", "") for step in publish["steps"])
    assert not any("checkout" in step.get("uses", "") for step in attach["steps"])
    assert publish["steps"].index(publish_download) < len(publish["steps"]) - 1
    assert attach["steps"].index(attach_download) < len(attach["steps"]) - 1

    attach_step = attach["steps"][-1]
    assert attach_step["name"] == "Attach distributions to exact GitHub Release"
    assert attach_step["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "GH_REPO": "${{ github.repository }}",
        "RELEASE_TAG": "${{ needs.release-please.outputs.tag_name }}",
        "EXPECTED_SHA": "${{ github.sha }}",
    }
    attach_run = attach_step["run"]
    assert "git/ref/tags/$RELEASE_TAG" in attach_run
    assert "commit:$EXPECTED_SHA" in attach_run
    assert 'gh release view "$RELEASE_TAG"' in attach_run
    assert 'gh release upload "$RELEASE_TAG"' in attach_run
    assert "--clobber=false" in attach_run
    assert "${{ github.sha }}" not in attach_run
    assert "v0.7.0" not in contents
