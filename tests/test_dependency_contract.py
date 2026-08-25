from pathlib import Path

from dcc_mcp_core import yaml_loads


def test_ci_exercises_floor_and_latest_compatible_dependencies():
    workflow_path = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
    workflow = yaml_loads(workflow_path.read_text(encoding="utf-8"))
    job = workflow["jobs"]["dependency-compatibility"]

    assert job["strategy"]["matrix"]["lane"] == ["floor", "latest"]
    steps = {step.get("name"): step for step in job["steps"]}
    assert steps["Install floor dependencies"]["run"] == (
        'python -m pip install -e ".[dev]" "dcc-mcp-core==0.20.14"'
    )
    assert steps["Install latest compatible dependencies"]["run"] == (
        'python -m pip install --upgrade --upgrade-strategy eager -e ".[dev]"'
    )
    assert steps["Validate dependency lane"]["run"] == (
        "python -m pip check\npytest tests/test_package.py tests/test_install_hardening.py -q\n"
    )
