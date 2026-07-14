from adobe.after_effects import AfterEffects
from adobe.core.errors import HostScriptError
from adobe.dcc_mcp import action_result
from dcc_mcp_core.skill import skill_entry


def inspect_project():
    app = AfterEffects()
    project = app.project
    if project is None:
        raise HostScriptError("After Effects has no active project")
    active = app.active_item
    return {
        "project_name": project.name,
        "item_count": project.item_count,
        "active_item": active.name if active else None,
    }


@skill_entry
def main(**_kwargs):
    return action_result("After Effects project inspected.", inspect_project)


if __name__ == "__main__":
    from dcc_mcp_core.skill import run_main

    run_main(main)
