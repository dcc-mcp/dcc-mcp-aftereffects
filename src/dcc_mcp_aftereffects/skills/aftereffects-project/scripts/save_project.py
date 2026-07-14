from pathlib import Path

from adobe.after_effects import AfterEffects
from adobe.core.errors import HostScriptError
from adobe.dcc_mcp import action_result
from dcc_mcp_core.skill import skill_entry


def save_project(path: str):
    output = Path(path)
    if not output.is_absolute() or output.suffix.lower() != ".aep":
        raise HostScriptError("path must be absolute and end with .aep")
    project = AfterEffects().project
    if project is None:
        raise HostScriptError("After Effects has no active project")
    project.save(str(output))
    return {"path": str(output), "saved": True}


@skill_entry
def main(path: str, **_kwargs):
    return action_result("After Effects project saved.", lambda: save_project(path))


if __name__ == "__main__":
    from dcc_mcp_core.skill import run_main

    run_main(main)
