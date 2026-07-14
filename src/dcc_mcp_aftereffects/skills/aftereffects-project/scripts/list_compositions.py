from adobe.after_effects import AfterEffects
from adobe.core.errors import HostScriptError
from adobe.dcc_mcp import action_result
from dcc_mcp_core.skill import skill_entry


def list_compositions():
    project = AfterEffects().project
    if project is None:
        raise HostScriptError("After Effects has no active project")
    compositions = [
        {
            "name": comp.name,
            "width": comp.width,
            "height": comp.height,
            "duration": comp.duration,
        }
        for comp in project.compositions
    ]
    return {"compositions": compositions, "composition_count": len(compositions)}


@skill_entry
def main(**_kwargs):
    return action_result("After Effects compositions listed.", list_compositions)


if __name__ == "__main__":
    from dcc_mcp_core.skill import run_main

    run_main(main)
