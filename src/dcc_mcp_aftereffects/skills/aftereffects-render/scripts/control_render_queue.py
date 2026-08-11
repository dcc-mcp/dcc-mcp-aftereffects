from adobe.dcc_mcp import action_result
from dcc_mcp_core.skill import skill_entry

from dcc_mcp_aftereffects.operations import control_render_queue


@skill_entry
def main(**kwargs):
    return action_result("After Effects render queue controlled.", control_render_queue, **kwargs)


if __name__ == "__main__":
    from dcc_mcp_core.skill import run_main

    run_main(main)
