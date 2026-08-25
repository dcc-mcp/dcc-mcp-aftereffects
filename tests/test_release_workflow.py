from __future__ import annotations

import re
from pathlib import Path

from dcc_mcp_core import yaml_loads


def test_release_actions_are_commit_pinned_and_jobs_have_minimal_permissions():
    workflow_path = Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"
    contents = workflow_path.read_text(encoding="utf-8")
    workflow = yaml_loads(contents)

    action_refs = re.findall(r"\buses:\s*([^\s#]+)", contents)
    assert action_refs
    assert all(re.search(r"@[0-9a-f]{40}$", action) for action in action_refs)
    assert workflow["permissions"] == {}
    assert workflow["jobs"]["release-please"]["permissions"] == {
        "contents": "write",
        "pull-requests": "write",
    }
    assert workflow["jobs"]["publish"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
